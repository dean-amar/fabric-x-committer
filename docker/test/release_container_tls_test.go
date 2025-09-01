/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
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
	testutils "github.com/hyperledger/fabric-x-committer/utils/test"
)

type startNodeParameters struct {
	credsFactory    *testutils.CredentialsFactory
	nodeName        string
	clientCredsPath string
	networkName     string
}

const (
	committerReleaseImage = "icr.io/cbdc/committer:0.0.2"
	loadgenReleaseImage   = "icr.io/cbdc/loadgen:0.0.2"

	// To support parallel run of the two container images, we need to use different port for the Loadgen
	// These ports are used in the test-image test.
	loadGenMetricsReleaseImagePort = "2119"

	networkPrefix = "sc_network"

	// containerConfigPath is the path to the config directory inside the container.
	containerConfigPath = "/root/config"
	// localConfigPath is the path for the sample YAML configurations per service.
	localConfigPath = "../../cmd/config/samples"
)

// TestCommitterNodesWithTLS runs each committer component in Docker and verifies
// it starts with TLS enabled and connects successfully.
func TestCommitterNodesWithTLS(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	dockerClient := createDockerClient(t)

	serviceNames := []string{"db", "verifier", "vc", "query", "coordinator", "sidecar", "orderer", "loadgen"}
	stopAndRemoveContainersByName(ctx, t, dockerClient, serviceNames...)

	// Create an isolated network for the test run.
	networkName := fmt.Sprintf("%s_%s", networkPrefix, uuid.NewString())
	testutils.CreateDockerNetwork(t, networkName)
	t.Cleanup(func() {
		testutils.RemoveDockerNetwork(t, networkName)
	})

	// one factory per test and client credentials for mutual TLS.
	credsFactory := testutils.NewCredentialsFactory(t)
	_, clientCredsPath := credsFactory.CreateClientCredentials(t, connection.MutualTLSMode)

	for _, name := range serviceNames {
		params := startNodeParameters{
			credsFactory:    credsFactory,
			nodeName:        name,
			clientCredsPath: clientCredsPath,
			networkName:     networkName,
		}

		switch name {
		case "db", "orderer":
			startNodeWithTestImage(ctx, t, dockerClient, params)
		case "loadgen":
			startLoadgenNodeWithReleaseImage(ctx, t, dockerClient, params)
		default:
			startCommitterNodeWithReleaseImage(ctx, t, dockerClient, params)
		}
	}

	monitorMetrics(t, loadGenMetricsReleaseImagePort)
}

// startCommitterNodeWithReleaseImage starts a committer node using the release image.
func startCommitterNodeWithReleaseImage(
	ctx context.Context,
	t *testing.T,
	dockerClient *client.Client,
	params startNodeParameters,
) {
	t.Helper()

	cfgPath := filepath.Join(mustGetWD(t), localConfigPath)
	serverName := params.nodeName

	containerCfg := &container.Config{
		Image: committerReleaseImage,
		Cmd: []string{
			"committer",
			fmt.Sprintf("start-%s", serverName),
			"--config",
			fmt.Sprintf("%s/%s.yaml", containerConfigPath, serverName),
		},
		Tty: true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(params.networkName),
	}

	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, connection.MutualTLSMode, serverName)
	require.NotEmpty(t, serverCredsPath)

	hostCfg.Binds = assembleBinds(t,
		serverCredsPath,
		params.clientCredsPath,
		fmt.Sprintf("%s/%s.yaml:/%s/%s.yaml", cfgPath, serverName, containerConfigPath, serverName),
	)

	createContainerAndItsLogs(ctx, t, createContainerParameters{
		dockerClient:    dockerClient,
		containerConfig: containerCfg,
		hostConfig:      hostCfg,
		name:            serverName,
	})
}

// startLoadgenNodeWithReleaseImage starts a load generator instance using the release image.
func startLoadgenNodeWithReleaseImage(
	ctx context.Context,
	t *testing.T,
	dockerClient *client.Client,
	params startNodeParameters,
) {
	t.Helper()

	cfgPath := filepath.Join(mustGetWD(t), localConfigPath)
	serverName := params.nodeName

	containerCfg := &container.Config{
		Image: loadgenReleaseImage,
		Cmd: []string{
			serverName,
			"start",
			"--config",
			fmt.Sprintf("%s/%s.yaml", containerConfigPath, serverName),
		},
		ExposedPorts: nat.PortSet{
			nat.Port(loadGenMetricsReleaseImagePort + "/tcp"): {},
		},
		Tty: true,
		// Set the monitoring server endpoint to match the exposed port.
		Env: []string{
			fmt.Sprintf("SC_LOADGEN_MONITORING_SERVER_ENDPOINT=:%s", loadGenMetricsReleaseImagePort),
		},
	}

	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, serverName)
	require.NotEmpty(t, serverCredsPath)

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(params.networkName),
		PortBindings: nat.PortMap{
			nat.Port(loadGenMetricsReleaseImagePort + "/tcp"): []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: loadGenMetricsReleaseImagePort,
			}},
		},
		Binds: assembleBinds(t,
			serverCredsPath,
			params.clientCredsPath,
			fmt.Sprintf("%s/%s.yaml:/%s/%s.yaml", cfgPath, serverName, containerConfigPath, serverName),
		),
	}

	createContainerAndItsLogs(ctx, t, createContainerParameters{
		dockerClient:    dockerClient,
		containerConfig: containerCfg,
		hostConfig:      hostCfg,
		name:            serverName,
	})
}

// startNodeWithTestImage starts a basic test node (e.g., DB, orderer) using the test image.
func startNodeWithTestImage(
	ctx context.Context,
	t *testing.T,
	dockerClient *client.Client,
	params startNodeParameters,
) {
	t.Helper()

	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.nodeName)
	require.NotEmpty(t, serverCredsPath)

	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   []string{"run", params.nodeName},
		Tty:   true,
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(params.networkName),
		Binds:       assembleBinds(t, serverCredsPath, params.clientCredsPath),
	}

	createContainerAndItsLogs(ctx, t, createContainerParameters{
		dockerClient:    dockerClient,
		containerConfig: containerCfg,
		hostConfig:      hostCfg,
		name:            params.nodeName,
	})
}

func assembleBinds(t *testing.T, serverCredsPath, clientCredsPath string, additionalBinds ...string) []string {
	t.Helper()
	return append([]string{
		fmt.Sprintf("%s:/certs", serverCredsPath),
		fmt.Sprintf("%s:/client_certs", clientCredsPath),
	}, additionalBinds...)
}

// mustGetWD returns the current working directory.
func mustGetWD(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return wd
}
