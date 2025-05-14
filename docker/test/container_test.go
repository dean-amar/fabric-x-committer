package test

import (
	"context"
	_ "embed"
	"io"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	spec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/cmd/config"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/sidecar/sidecarclient"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature/sigtest"
)

const (
	ordererImage     = "icr.io/cbdc/mock-ordering-service:0.0.2"
	testNodeImage    = "icr.io/cbdc/committer-test-node:0.0.2"
	ordererPort      = "7050"
	sidecarPort      = "4001"
	queryServicePort = "7001"
	channelName      = "testchannel"
)

// TestStartTestNode spawns a mock orderer and an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNode(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer connection.CloseConnectionsLog(dockerClient)

	stopAndRemoveContainersByName(ctx, t, dockerClient, "orderer", "committer")

	_, pubKey := sigtest.NewSignatureFactory(signature.Ecdsa).NewKeys()
	configBlockPath := config.CreateConfigBlock(t, &config.ConfigBlock{
		ChannelID: channelName,
		OrdererEndpoints: []*connection.OrdererEndpoint{
			{MspID: "org", Endpoint: *connection.CreateEndpoint(ordererEndpoint())},
		},
		MetaNamespaceVerificationKey: pubKey,
	})
	require.FileExists(t, configBlockPath)

	startOrderer(ctx, t, dockerClient, "orderer", configBlockPath)
	startCommitter(ctx, t, dockerClient, "committer", configBlockPath)

	t.Log("Try to fetch the first block.")
	sidecarEndpoint, err := connection.NewEndpoint("localhost:" + sidecarPort)
	require.NoError(t, err)
	committedBlock := sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Config{
		ChannelID: channelName,
		SidecarClient: &connection.ServerConfig{
			Endpoint: *sidecarEndpoint,
		},
	}, 0)
	b, ok := channel.NewReader(ctx, committedBlock).Read()
	require.True(t, ok)
	t.Logf("Received block #%d with %d TXs", b.Header.Number, len(b.Data.Data))

	// TODO: do some more checks
}

//nolint:revive
func startOrderer(ctx context.Context, t *testing.T, dockerClient *client.Client, name, configBlockPath string) {
	t.Helper()
	// TODO: we want to replace this with `config/templates` in the future
	wd, err := os.Getwd()
	require.NoError(t, err)
	configPath := path.Join(path.Join(wd, "testdata"), "orderer.yaml")
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
func startCommitter(ctx context.Context, t *testing.T, dockerClient *client.Client, name, configBlockPath string) {
	t.Helper()
	containerCfg := &container.Config{
		Image: testNodeImage,
		ExposedPorts: nat.PortSet{
			nat.Port(sidecarPort + "/tcp"):      struct{}{},
			nat.Port(queryServicePort + "/tcp"): struct{}{},
		},
		Env: []string{
			"SC_SIDECAR_ORDERER_CHANNEL_ID=" + channelName,
			"SC_SIDECAR_ORDERER_CONNECTION_ENDPOINTS=" + ordererEndpoint(),
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

func ordererEndpoint() string {
	switch runtime.GOOS {
	case "linux":
		return "localhost:" + ordererPort
	default:
		return "host.docker.internal:" + ordererPort
	}
}
