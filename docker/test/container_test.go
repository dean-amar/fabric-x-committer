/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	_ "embed"
	docker "github.com/fsouza/go-dockerclient"
	"io"
	"os"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/service/sidecar/sidecarclient"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

const (
	testNodeImage      = "icr.io/cbdc/committer-test-node:0.0.2"
	sidecarPort        = "4001"
	loadGenMetricsPort = "2118"
	channelName        = "mychannel"
	monitoredMetric    = "loadgen_transaction_committed_total"
)

// TestStartTestNode spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNode(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer connection.CloseConnectionsLog(dockerClient)

	stopAndRemoveContainersByName(ctx, t, dockerClient, "orderer", "db", "vc-service", "verifier", "query", "coordinator", "sidecar", "loadgen")
	startCommitterWithNodes(ctx, t, dockerClient, "db")
	startCommitterWithNodes(ctx, t, dockerClient, "verifier")
	startCommitterWithNodes(ctx, t, dockerClient, "vc-service")
	startCommitterWithNodes(ctx, t, dockerClient, "query")
	startCommitterWithNodes(ctx, t, dockerClient, "coordinator")
	startCommitterWithNodes(ctx, t, dockerClient, "sidecar")

	startCommitterWithNodes(ctx, t, dockerClient, "orderer")
	startCommitterWithNodes(ctx, t, dockerClient, "loadgen")

	t.Log("Try to fetch the first block")

	sidecarContainerEndpoint := GetContainerIP(t, "sidecar", "test-net")
	t.Logf("sidecar-container-endpoint: %s", sidecarContainerEndpoint)
	sidecarEndpoint, err := connection.NewEndpoint("localhost:" + sidecarPort)
	require.NoError(t, err)
	committedBlock := sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Config{
		ChannelID: channelName,
		Client: test.MakeTLSClientConfig(&connection.TLSConfig{
			Mode:        "mtls",
			KeyPath:     "/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/client/private-key",
			CertPath:    "/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/client/public-key",
			CACertPaths: []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/client/ca-certificate"},
		}, sidecarEndpoint),
	}, 0)
	b, ok := channel.NewReader(ctx, committedBlock).Read()
	require.True(t, ok)
	t.Logf("Received block #%d with %d TXs", b.Header.Number, len(b.Data.Data))
	t.Logf("After-sidecar-connection.")
	metricsURL, err := monitoring.MakeMetricsURL("localhost:" + loadGenMetricsPort)
	require.NoError(t, err)

	t.Logf("Check the load generator metrics from: %s", metricsURL)
	// We check often since the load generator's metrics might be closed if the limit is reached.
	// We log only if there are changes to avoid spamming the log.
	prevCount := -1
	require.Eventually(t, func() bool {
		count := test.GetMetricValueFromURL(t, metricsURL, monitoredMetric)
		if prevCount != count {
			t.Logf("%s: %d", monitoredMetric, count)
		}
		prevCount = count
		return count > 1_000
	}, 15*time.Minute, 100*time.Millisecond)
}

//nolint:revive
func startCommitterWithNodes(ctx context.Context, t *testing.T, dockerClient *client.Client, nodeName string) {
	t.Helper()
	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   []string{"run", nodeName},
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode("test-net"),
	}

	// Bind mounts based on nodeName
	switch nodeName {
	case "query":
		hostCfg.Binds = []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/query:/certs"}
	case "vc-service":
		hostCfg.Binds = []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/vc-service:/certs"}
	case "verifier":
		hostCfg.Binds = []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/verifier:/certs"}
	case "sidecar":
		hostCfg.Binds = []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/sidecar:/certs",
			"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/client:/client_certs"}
	case "coordinator":
		hostCfg.Binds = []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/coordinator:/certs",
			"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/client:/client_certs"}
	case "loadgen":
		hostCfg.Binds = []string{"/Users/deanamar/Work/fabric-x-committer/cmd/tls-certificates/client:/client_certs"}
	}

	if nodeName == "sidecar" {
		containerCfg.ExposedPorts = nat.PortSet{
			sidecarPort + "/tcp": struct{}{},
		}
		hostCfg.PortBindings = nat.PortMap{
			// sidecar port binding
			sidecarPort + "/tcp": []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: sidecarPort,
			}},
		}
	}

	if nodeName == "loadgen" {
		containerCfg.ExposedPorts = nat.PortSet{
			loadGenMetricsPort + "/tcp": struct{}{},
		}
		hostCfg.PortBindings = nat.PortMap{
			// loadgen service port bindings
			loadGenMetricsPort + "/tcp": []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: loadGenMetricsPort,
			}},
		}
	}

	resp, err := dockerClient.ContainerCreate(ctx, containerCfg, hostCfg, nil, nil, nodeName)
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
			t.Logf("[%s] logs ended with: %v", nodeName, err)
		}
	}()
}

// GetContainerIP returns the IP address of a container on the given network.
func GetContainerIP(t *testing.T, containerName, networkName string) string {
	t.Helper()

	cli, err := docker.NewClientFromEnv()
	require.NoError(t, err)

	c, err := cli.InspectContainer(containerName)
	require.NoError(t, err)

	net := c.NetworkSettings.Networks[networkName]
	require.NotNil(t, net, "container %q has no network %q", containerName, networkName)
	require.NotEmpty(t, net.IPAddress, "container %q has no IP on network %q", containerName, networkName)

	return net.IPAddress + ":"
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
