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

	testutils "github.com/hyperledger/fabric-x-committer/utils/test"
)

type startNodeParameters struct {
	credsFactory    *testutils.CredentialsFactory
	nodeName        string
	clientCredsPath string
	networkName     string
	tlsMode         string
}

const (
	committerReleaseImage = "icr.io/cbdc/committer:0.0.2"
	loadgenReleaseImage   = "icr.io/cbdc/loadgen:0.0.2"

	networkPrefix = "sc_network"
	genBlock      = "sc-genesis-block"
	// containerConfigPath is the path to the config directory inside the container.
	containerConfigPath = "/root/config"
	// localConfigPath is the path for the sample YAML configurations per service.
	localConfigPath = "../../cmd/config/samples"
	// binPath is the path to the binary files.
	binPath = "../../bin"
)

// TestCommitterNodesWithTLS runs each committer component in Docker container and verifies
// it starts with TLS enabled and connects successfully.
// This test uses the release images for all the components but 'db' and 'orderer'.
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

	//nolint:paralleltest // This test is hard to parallelize for several reasons.
	// We start the sidecar using a genesis block that is precompiled ahead of time.
	// To run this test in parallel, we would need multiple instances of the same
	// services with unique names, which would require regenerating the genesis block
	// for each instance.
	// We would also need to adjust the YAML configuration to support distinct
	// hostnames, which would add unnecessary complexity.
	for _, mode := range testutils.ServerModes {
		mode := mode
		t.Run(fmt.Sprintf("tls-mode:%s", mode), func(t *testing.T) {
			// one factory per test and client credentials for mutual TLS.
			credsFactory := testutils.NewCredentialsFactory(t)
			_, clientCredsPath := credsFactory.CreateClientCredentials(t, mode)
			for _, name := range serviceNames {
				params := startNodeParameters{
					credsFactory:    credsFactory,
					nodeName:        name,
					clientCredsPath: clientCredsPath,
					networkName:     networkName,
					tlsMode:         mode,
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
			monitorMetrics(t, retrieveLocalMappedPortDockerContainer(ctx, t, "loadgen", loadGenMetricsPort))
		})
	}
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
		Env: []string{
			"SC_COORDINATOR_SERVER_TLS_MODE=" + params.tlsMode,
			"SC_COORDINATOR_VERIFIER_TLS_MODE=" + params.tlsMode,
			"SC_COORDINATOR_VALIDATOR_COMMITTER_TLS_MODE=" + params.tlsMode,
			"SC_QUERY_SERVER_TLS_MODE=" + params.tlsMode,
			"SC_SIDECAR_SERVER_TLS_MODE=" + params.tlsMode,
			"SC_SIDECAR_COMMITTER_TLS_MODE=" + params.tlsMode,
			"SC_VC_SERVER_TLS_MODE=" + params.tlsMode,
			"SC_VERIFIER_SERVER_TLS_MODE=" + params.tlsMode,
		},
		Tty: true,
	}

	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.tlsMode, serverName)
	require.NotEmpty(t, serverCredsPath)

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(params.networkName),
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
			nat.Port(loadGenMetricsPort + "/tcp"): {},
		},
		Tty: true,
		Env: []string{
			"SC_LOADGEN_SERVER_TLS_MODE=" + params.tlsMode,
			"SC_LOADGEN_ORDERER_CLIENT_SIDECAR_CLIENT_TLS_MODE=" + params.tlsMode,
		},
	}

	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.tlsMode, serverName)
	require.NotEmpty(t, serverCredsPath)

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(params.networkName),
		PortBindings: nat.PortMap{
			nat.Port(loadGenMetricsPort + "/tcp"): []nat.PortBinding{{
				HostIP:   "localhost",
				HostPort: "0", // auto port catch
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

	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.tlsMode, params.nodeName)
	require.NotEmpty(t, serverCredsPath)

	containerCfg := &container.Config{
		Image: testNodeImage,
		Cmd:   []string{"run", params.nodeName},
		Tty:   true,
		Env: []string{
			"SC_LOADGEN_ORDERER_CLIENT_SIDECAR_CLIENT_TLS_MODE=" + params.tlsMode,
		},
	}

	hostCfg := &container.HostConfig{
		NetworkMode: container.NetworkMode(params.networkName),
		Binds: assembleBinds(t,
			serverCredsPath,
			params.clientCredsPath,
			fmt.Sprintf("%s/%s-release.proto.bin:/%s/%s.proto.bin",
				filepath.Join(mustGetWD(t), binPath), genBlock, containerConfigPath, genBlock,
			),
		),
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
