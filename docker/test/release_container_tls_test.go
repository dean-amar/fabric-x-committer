package test

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	testUtils "github.com/hyperledger/fabric-x-committer/utils/test"
)

type startNodeParameters struct {
	secureConnManager *testUtils.CredentialsFactory
	nodeName          string
	clientCredsDir    string
	network           string
}

const (
	committerReleaseImage = "icr.io/cbdc/committer:0.0.2"
	loadgenReleaseImage   = "icr.io/cbdc/loadgen:0.0.2"
	sidecarPort2          = "4002" //comment
	loadGenMetricsPort2   = "2119"
	networkPrefix         = "sc_network"

	// containerConfigPath is the path to the config in the docker container.
	containerConfigPath = "/root/config"
	localConfigPath     = "../../cmd/config/samples_with_tls"
)

// @TODO: change the sidecar and loadgen ports.
// @TODO: add env to set the original test to work with tls paths.
// @TODO: fix code to suit production levels.
// @TODO: change comments.

func getConfigPath(t *testing.T) (configPath string) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, localConfigPath)
}

// TestCommitterNodesWithTLS spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestCommitterNodesWithTLS(t *testing.T) {
	ctx := t.Context()
	dockerClient := createDockerClient(t)

	serviceNames := []string{"db", "verifier", "vc", "query", "coordinator", "sidecar", "orderer", "loadgen"}
	stopAndRemoveContainersByName(ctx, t, dockerClient, serviceNames...)

	// create docker network for committer's components to run in.
	netName := fmt.Sprintf("%s_%s", networkPrefix, uuid.NewString())
	testUtils.CreateDockerNetwork(t, netName)
	t.Cleanup(func() {
		testUtils.RemoveDockerNetwork(t, netName)
	})

	// creating tls manager and creates client creds.
	tlsManager := testUtils.NewCredentialsFactory(t)
	clientTLSConfig, clientCredsDir := tlsManager.CreateClientCredentials(t, connection.MutualTLSMode)

	t.Logf("client-tls-config: %v", clientTLSConfig)

	for _, node := range serviceNames {
		nodeParams := startNodeParameters{
			secureConnManager: tlsManager,
			nodeName:          node,
			clientCredsDir:    clientCredsDir,
			network:           netName,
		}
		switch node {
		case "db", "orderer":
			startNodeWithTestImage(ctx, t, dockerClient, nodeParams)
		case "loadgen":
			startLoadgenNodeWithReleaseImage(ctx, t, dockerClient, nodeParams)
		default:
			startCommitterNodeWithReleaseImage(ctx, t, dockerClient, nodeParams)
		}
	}
	monitorMetrics(t, loadGenMetricsPort)
}

func startCommitterNodeWithReleaseImage(ctx context.Context, t *testing.T, dockerClient *client.Client, params startNodeParameters) {
	t.Helper()

	tManager, name, clientCertsDir, netName :=
		params.secureConnManager, params.nodeName, params.clientCredsDir, params.network

	containerCfg := &container.Config{
		Image: committerReleaseImage,
		Cmd:   []string{"committer", fmt.Sprintf("start-%s", name), "--config", fmt.Sprintf("%s/%s.yaml", containerConfigPath, name)},
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
	}

	var serverCredsPath string
	switch name {
	case "sidecar":
		_, serverCredsPath = tManager.CreateServerCredentials(t, connection.MutualTLSMode, name, "localhost")
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
	default:
		_, serverCredsPath = tManager.CreateServerCredentials(t, connection.MutualTLSMode, name)
	}

	// bind the credential paths.
	require.NotEmpty(t, serverCredsPath)
	hostCfg.Binds = []string{
		fmt.Sprintf("%s:/certs", serverCredsPath),
		fmt.Sprintf("%s:/client_certs", clientCertsDir),
		fmt.Sprintf("%s/%s.yaml:/%s/%s.yaml", getConfigPath(t), name, containerConfigPath, name),
	}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}

func startLoadgenNodeWithReleaseImage(ctx context.Context, t *testing.T, dockerClient *client.Client, params startNodeParameters) {
	t.Helper()

	tManager, name, clientCertsDir, netName :=
		params.secureConnManager, params.nodeName, params.clientCredsDir, params.network

	containerCfg := &container.Config{
		Image: loadgenReleaseImage,
		Cmd:   []string{name, "start", "--config", fmt.Sprintf("%s/%s.yaml", containerConfigPath, name)},
		ExposedPorts: nat.PortSet{
			nat.Port(loadGenMetricsPort + "/tcp"): struct{}{},
		},
		Tty: true,
	}

	_, serverCredsPath := tManager.CreateServerCredentials(t, name)
	require.NotEmpty(t, serverCredsPath)

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
		PortBindings: nat.PortMap{
			nat.Port(loadGenMetricsPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: loadGenMetricsPort,
			}},
		},
		Binds: []string{
			fmt.Sprintf("%s:/certs", serverCredsPath),
			fmt.Sprintf("%s:/client_certs", clientCertsDir),
			fmt.Sprintf("%s/%s.yaml:/%s/%s.yaml", getConfigPath(t), name, containerConfigPath, name),
		},
	}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}

func startNodeWithTestImage(ctx context.Context, t *testing.T, dockerClient *client.Client, params startNodeParameters) {
	t.Helper()
	tManager, name, clientCertsDir, netName :=
		params.secureConnManager, params.nodeName, params.clientCredsDir, params.network

	_, serverCredsPath := tManager.CreateServerCredentials(t, name)
	require.NotEmpty(t, serverCredsPath)

	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   []string{"run", name},
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
		Binds: []string{
			fmt.Sprintf("%s:/certs", serverCredsPath),
			fmt.Sprintf("%s:/client_certs", clientCertsDir),
		},
	}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}
