/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	_ "embed"
	"io"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	spec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/sidecar/sidecarclient"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
)

const (
	ordererImage       = "icr.io/cbdc/mock-ordering-service:0.0.2"
	testNodeImage      = "icr.io/cbdc/committer-test-node:0.0.2"
	ordererPort        = "7050"
	sidecarPort        = "4001"
	queryServicePort   = "7001"
	loadGenMetricsPort = "2110"
	channelName        = "testchannel"
)

// TestStartTestNode spawns a mock orderer and an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNode(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer connection.CloseConnectionsLog(dockerClient)

	stopAndRemoveContainersByName(ctx, t, dockerClient, "orderer", "committer", "load-gen")

	workload.NewTxSignerVerifier(&workload.PolicyProfile{})
	block, err := workload.CreateConfigBlock(&workload.PolicyProfile{
		NamespacePolicies: map[string]*workload.Policy{
			types.MetaNamespaceID: {
				// This is the policy that is defined in samples/loadgen.yaml
				Scheme: signature.Ecdsa,
				Seed:   11,
			},
		},
		OrdererEndpoints: []*connection.OrdererEndpoint{
			{MspID: "org", Endpoint: *connection.CreateEndpoint(serviceEndpoint(ordererPort))},
		},
	})
	require.NoError(t, err)
	configBlockPath := config.WriteConfigBlock(t, block)
	require.FileExists(t, configBlockPath)

	startOrderer(ctx, t, dockerClient, "orderer", configBlockPath)
	startCommitter(ctx, t, dockerClient, "committer", configBlockPath)
	startCommitter(ctx, t, dockerClient, "load-gen", configBlockPath, "/root/run-loadgen.sh")

	t.Log("Try to fetch the first block")
	sidecarEndpoint, err := connection.NewEndpoint("localhost:" + sidecarPort)
	require.NoError(t, err)
	committedBlock := sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Config{
		ChannelID: channelName,
		Endpoint:  sidecarEndpoint,
	}, 0)
	b, ok := channel.NewReader(ctx, committedBlock).Read()
	require.True(t, ok)
	t.Logf("Received block #%d with %d TXs", b.Header.Number, len(b.Data.Data))

	metricsURL, err := monitoring.MakeMetricsURL("localhost:" + loadGenMetricsPort)
	require.NoError(t, err)
	t.Logf("Check the load generator metrics from: %s", metricsURL)
	require.Eventually(t, func() bool {
		count := promutil.GetMetricValueFromURL(t, metricsURL, "loadgen_transaction_committed_total")
		t.Logf("loadgen_transaction_committed_total: %d", count)
		return count > 1_000
	}, 5*time.Minute, 1*time.Second)
}

//nolint:revive
func startOrderer(ctx context.Context, t *testing.T, dockerClient *client.Client, name, configBlockPath string) {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	configPath := path.Clean(path.Join(wd, "../../cmd/config/samples/mock-orderer.yaml"))
	require.FileExists(t, configPath)

	containerCfg := &container.Config{
		Image: ordererImage,
		ExposedPorts: nat.PortSet{
			nat.Port(ordererPort + "/tcp"): struct{}{},
		},
		Cmd: []string{"/app", "start", "--config", "/config.yaml"},
		Tty: true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: network.NetworkHost,
		Mounts: []mount.Mount{
			{ // config block.
				Type:     mount.TypeBind,
				Source:   configBlockPath,
				Target:   "/root/config/sc-genesis-block.proto.bin",
				ReadOnly: true,
			},
			{ // config.
				Type:     mount.TypeBind,
				Source:   configPath,
				Target:   "/config.yaml",
				ReadOnly: true,
			},
		},
		PortBindings: nat.PortMap{
			nat.Port(ordererPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "0.0.0.0",
				HostPort: ordererPort,
			}},
		},
	}

	startContainer(ctx, t, dockerClient, name, containerCfg, hostCfg, nil, nil)
}

//nolint:revive
func startCommitter(
	ctx context.Context, t *testing.T, dockerClient *client.Client, name, configBlockPath string, cmd ...string,
) {
	t.Helper()
	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   cmd,
		ExposedPorts: nat.PortSet{
			nat.Port(sidecarPort + "/tcp"):        struct{}{},
			nat.Port(queryServicePort + "/tcp"):   struct{}{},
			nat.Port(loadGenMetricsPort + "/tcp"): struct{}{},
		},
		Env: []string{
			"SC_SIDECAR_ORDERER_CHANNEL_ID=" + channelName,
			"SC_SIDECAR_ORDERER_CONNECTION_ENDPOINTS=" + serviceEndpoint(ordererPort),
			"SC_LOADGEN_ORDERER_CLIENT_ORDERER_CHANNEL_ID=" + channelName,
			"SC_LOADGEN_ORDERER_CLIENT_ORDERER_CONNECTION_ENDPOINTS=" + serviceEndpoint(ordererPort),
			"SC_LOADGEN_ORDERER_CLIENT_SIDECAR_ENDPOINT=" + serviceEndpoint(sidecarPort),
			"SC_QUERY_SERVER_ENDPOINT=:" + queryServicePort,
		},
		Tty: true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: network.NetworkHost,
		Mounts: []mount.Mount{
			{ // config block
				Type:     mount.TypeBind,
				Source:   configBlockPath,
				Target:   "/root/config/sc-genesis-block.proto.bin",
				ReadOnly: true,
			},
		},
		PortBindings: nat.PortMap{
			// sidecar port binding
			nat.Port(sidecarPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "0.0.0.0",
				HostPort: sidecarPort,
			}},
			// query service port bindings
			nat.Port(queryServicePort + "/tcp"): []nat.PortBinding{{
				HostIP:   "0.0.0.0",
				HostPort: queryServicePort,
			}},
			// loadgen service port bindings
			nat.Port(loadGenMetricsPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "0.0.0.0",
				HostPort: loadGenMetricsPort,
			}},
		},
	}

	startContainer(ctx, t, dockerClient, name, containerCfg, hostCfg, nil, nil)
}

//nolint:revive
func startContainer(
	ctx context.Context,
	t *testing.T,
	dockerClient *client.Client,
	containerName string,
	containerCfg *container.Config,
	hostCfg *container.HostConfig,
	networkCfg *network.NetworkingConfig,
	platformCfg *spec.Platform,
) {
	t.Helper()
	resp, err := dockerClient.ContainerCreate(ctx, containerCfg, hostCfg, networkCfg, platformCfg, containerName)
	require.NoError(t, err)

	//nolint:contextcheck // We want to ensure cleanup when the test is done.
	t.Cleanup(func() {
		stopAndRemoveID(context.Background(), t, dockerClient, resp.ID)
	})

	require.NoError(t, dockerClient.ContainerStart(ctx, resp.ID, container.StartOptions{}))

	logs, err := dockerClient.ContainerLogs(ctx, resp.ID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	require.NoError(t, err)
	go func() {
		_, err = io.Copy(os.Stdout, logs)
		if err != nil {
			t.Logf("[%s] logs ended with: %v", containerName, err)
		}
	}()
}

func stopAndRemoveContainersByName(ctx context.Context, t *testing.T, dockerClient *client.Client, names ...string) {
	t.Helper()
	list, err := dockerClient.ContainerList(ctx, container.ListOptions{
		All: true,
	})
	require.NoError(t, err)

	nameToID := make(map[string]string)
	for _, c := range list {
		for _, name := range c.Names {
			nameToID[name[1:]] = c.ID
		}
	}
	for _, containerName := range names {
		id, ok := nameToID[containerName]
		if !ok {
			t.Logf("container '%s' not found", containerName)
			continue
		}
		t.Logf("stopping container '%s' (%s)", containerName, id)
		stopAndRemoveID(ctx, t, dockerClient, id)
	}
}

func stopAndRemoveID(ctx context.Context, t *testing.T, dockerClient *client.Client, id string) {
	t.Helper()
	err := dockerClient.ContainerStop(ctx, id, container.StopOptions{})
	if err != nil {
		t.Logf("unable to stop container %s: %s", id, err)
	}
	err = dockerClient.ContainerRemove(ctx, id, container.RemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})
	if err != nil {
		t.Logf("unable to remove container: %s", err)
	}
}

func serviceEndpoint(port string) string {
	switch runtime.GOOS {
	case "linux":
		return "localhost:" + port
	default:
		return "host.docker.internal:" + port
	}
}
