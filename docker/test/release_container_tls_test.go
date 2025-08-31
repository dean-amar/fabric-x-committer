package test

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/stretchr/testify/require"
	"testing"
)

type startNodeParameters struct {
	secureConnManager *test.SecureCommunicationManager
	nodeName          string
	clientCredsDir    string
	network           string
}

const (
	committerReleaseImage = "icr.io/cbdc/committer:0.0.2"
	loadgenReleaseImage   = "icr.io/cbdc/loadgen:0.0.2"
	networkPrefix         = "sc_network"
)

// TestCommitterNodesWithTLS spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestCommitterNodesWithTLS(t *testing.T) {
	ctx := t.Context()
	dockerClient := createDockerClient(t)

	serviceNames := []string{"db", "verifier", "vc", "query", "coordinator", "sidecar", "orderer", "loadgen"}
	stopAndRemoveContainersByName(ctx, t, dockerClient, serviceNames...)

	// create docker network for committer's components to run in.
	netName := fmt.Sprintf("%s_%s", networkPrefix, uuid.NewString())
	test.CreateDockerNetwork(t, netName)
	t.Cleanup(func() {
		test.RemoveDockerNetwork(t, netName)
	})

	// creating tls manager and creates client creds.
	tlsManager := test.NewSecureCommunicationManager(t)
	clientCredsPath, clientCredsDir := tlsManager.CreateClientCertificate(t)
	clientTLSConfig := test.CreateTLSConfigFromPaths(connection.MutualTLSMode, clientCredsPath)
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
			startWithTestNode(ctx, t, dockerClient, nodeParams)
		case "loadgen":
			startReleaseLoadgenNode(ctx, t, dockerClient, nodeParams)
		default:
			startReleaseCommitterNode(ctx, t, dockerClient, nodeParams)
		}
	}
	monitorMetrics(t, loadGenMetricsPort)
}

func startReleaseCommitterNode(ctx context.Context, t *testing.T, dockerClient *client.Client, params startNodeParameters) {
	t.Helper()

	tManager, name, clientCertsDir, netName :=
		params.secureConnManager, params.nodeName, params.clientCredsDir, params.network

	containerCfg := &container.Config{
		Image: committerReleaseImage,
		Cmd:   []string{"committer", fmt.Sprintf("start-%s", name), "--config", fmt.Sprintf("root/config/%s.yaml", name)},
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
	}

	var serverCredsPath string
	switch name {
	case "sidecar":
		_, serverCredsPath = tManager.CreateServerCertificate(t, name, "localhost")
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
		_, serverCredsPath = tManager.CreateServerCertificate(t, name)
	}

	// bind the credential paths.
	require.NotEmpty(t, serverCredsPath)
	hostCfg.Binds = []string{
		fmt.Sprintf("%s:/certs", serverCredsPath),
		fmt.Sprintf("%s:/client_certs", clientCertsDir),
	}

	switch name {
	case "verifier":
		hostCfg.Binds = append(
			hostCfg.Binds,
			fmt.Sprintf("/Users/deanamar/Work/fabric-x-committer/cmd/config/samples_with_tls/sigservice.yaml:/root/config/%s.yaml", name),
		)
	case "vc":
		hostCfg.Binds = append(
			hostCfg.Binds,
			fmt.Sprintf("/Users/deanamar/Work/fabric-x-committer/cmd/config/samples_with_tls/vcservice.yaml:/root/config/%s.yaml", name),
		)
	case "coordinator":
		hostCfg.Binds = append(
			hostCfg.Binds,
			fmt.Sprintf("/Users/deanamar/Work/fabric-x-committer/cmd/config/samples_with_tls/coordinator.yaml:/root/config/%s.yaml", name),
		)
	case "query":
		hostCfg.Binds = append(
			hostCfg.Binds,
			fmt.Sprintf("/Users/deanamar/Work/fabric-x-committer/cmd/config/samples_with_tls/queryservice.yaml:/root/config/%s.yaml", name),
		)
	case "sidecar":
		hostCfg.Binds = append(
			hostCfg.Binds,
			fmt.Sprintf("/Users/deanamar/Work/fabric-x-committer/cmd/config/samples_with_tls/sidecar.yaml:/root/config/%s.yaml", name),
		)
	default:
		//donothing
	}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}

func startReleaseLoadgenNode(ctx context.Context, t *testing.T, dockerClient *client.Client, params startNodeParameters) {
	t.Helper()

	tManager, name, clientCertsDir, netName :=
		params.secureConnManager, params.nodeName, params.clientCredsDir, params.network

	containerCfg := &container.Config{
		Image: loadgenReleaseImage,
		Cmd:   []string{name, "start", "--config", "root/config/loadgen.yaml"},
		ExposedPorts: nat.PortSet{
			nat.Port(loadGenMetricsPort + "/tcp"): struct{}{},
		},
		Tty: true,
	}

	_, serverCredsPath := tManager.CreateServerCertificate(t, name)
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
			"/Users/deanamar/Work/fabric-x-committer/cmd/config/samples_with_tls/loadgen.yaml:/root/config/loadgen.yaml",
			fmt.Sprintf("%s:/certs", serverCredsPath), fmt.Sprintf("%s:/client_certs", clientCertsDir),
		},
	}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}

func startWithTestNode(ctx context.Context, t *testing.T, dockerClient *client.Client, params startNodeParameters) {
	t.Helper()
	tManager, name, clientCertsDir, netName :=
		params.secureConnManager, params.nodeName, params.clientCredsDir, params.network

	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   []string{"run", name},
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(netName),
	}
	_, serverCredsPath := tManager.CreateServerCertificate(t, name)

	require.NotEmpty(t, serverCredsPath)
	hostCfg.Binds = []string{fmt.Sprintf("%s:/certs", serverCredsPath), fmt.Sprintf("%s:/client_certs", clientCertsDir)}

	createContainerAndItsLogs(ctx, t, dockerClient, containerCfg, hostCfg, name)
}
