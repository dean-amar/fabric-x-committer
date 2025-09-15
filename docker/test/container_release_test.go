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
	"github.com/hyperledger/fabric-x-common/internaltools/configtxgen"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/cmd/config"
	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	testutils "github.com/hyperledger/fabric-x-committer/utils/test"
)

type startNodeParameters struct {
	credsFactory        *testutils.CredentialsFactory
	client              *client.Client
	node                string
	clientTLSConfigPath string
	networkName         string
	tlsMode             string
	containerName       string
	configBlockPath     string
}

const (
	committerReleaseImage = "icr.io/cbdc/committer:0.0.2"
	loadgenReleaseImage   = "icr.io/cbdc/loadgen:0.0.2"

	networkPrefixName = "sc_network"
	genBlockFile      = "sc-genesis-block.proto.bin"
	// containerConfigPath is the path to the config directory inside the container.
	containerConfigPath = "/root/config"
	// localConfigPath is the path for the sample YAML configurations per service.
	localConfigPath     = "../../cmd/config/samples"
	containerPrefixName = "sc_test"
)

// TestCommitterNodesWithTLS runs each committer component in Docker container and verifies
// it starts with different TLS modes and connect successfully.
// This test uses the release images for all the components but 'db' and 'orderer'.
func TestCommitterNodesWithTLS(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	dockerClient := createDockerClient(t)

	t.Log("creating config-block")
	tmpConfigBlockPath := filepath.Join(t.TempDir(), genBlockFile)
	v := config.NewViperWithLoadGenDefaults()
	c, err := config.ReadLoadGenYamlAndSetupLogging(v, fmt.Sprintf("%s/loadgen.yaml", localConfigPath))
	require.NoError(t, err)
	configBlock, err := workload.CreateConfigBlock(c.LoadProfile.Transaction.Policy)
	require.NoError(t, err)
	require.NoError(t, configtxgen.WriteOutputBlock(configBlock, tmpConfigBlockPath))

	credsFactory := testutils.NewCredentialsFactory(t)
	for _, mode := range testutils.ServerModes {
		mode := mode
		t.Run(fmt.Sprintf("tls-mode:%s", mode), func(t *testing.T) {
			t.Parallel()
			// Create an isolated network for each test with different tls mode.
			networkName := fmt.Sprintf("%s_%s", networkPrefixName, uuid.NewString())
			testutils.CreateDockerNetwork(t, networkName)
			t.Cleanup(func() {
				testutils.RemoveDockerNetwork(t, networkName)
			})

			_, clientCredsPath := credsFactory.CreateClientCredentials(t, mode)
			for _, node := range []string{
				"db", "verifier", "vc", "query", "coordinator", "sidecar", "orderer", "loadgen",
			} {
				params := startNodeParameters{
					credsFactory:        credsFactory,
					client:              dockerClient,
					node:                node,
					clientTLSConfigPath: clientCredsPath,
					networkName:         networkName,
					tlsMode:             mode,
					containerName:       fmt.Sprintf("%s_%s_%s", containerPrefixName, node, mode),
					configBlockPath:     tmpConfigBlockPath,
				}

				switch node {
				case "db", "orderer":
					startNodeWithTestImage(ctx, t, params)
				case "loadgen":
					startLoadgenNodeWithReleaseImage(ctx, t, params)
				default:
					startCommitterNodeWithReleaseImage(ctx, t, params)
				}
			}
			monitorMetric(t, containerMappedHostPort(ctx, t,
				fmt.Sprintf("%s_%s_%s", containerPrefixName, "loadgen", mode), loadGenMetricsPort))
		})
	}
}

// startCommitterNodeWithReleaseImage starts a committer node using the release image.
func startCommitterNodeWithReleaseImage(
	ctx context.Context,
	t *testing.T,
	params startNodeParameters,
) {
	t.Helper()
	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.tlsMode, params.node)
	require.NotEmpty(t, serverCredsPath)

	createContainerAndItsLogs(ctx, t, createContainerParameters{
		dockerClient: params.client,
		containerConfig: &container.Config{
			Image: committerReleaseImage,
			Cmd: []string{
				"committer",
				fmt.Sprintf("start-%s", params.node),
				"--config",
				fmt.Sprintf("%s.yaml", filepath.Join(containerConfigPath, params.node)),
			},
			Hostname: params.node,
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
		},
		hostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(params.networkName),
			Binds: assembleBinds(t,
				serverCredsPath,
				params.clientTLSConfigPath,
				fmt.Sprintf("%s/%s.yaml:/%s/%s.yaml",
					filepath.Join(mustGetWD(t), localConfigPath), params.node,
					containerConfigPath, params.node,
				),
			),
		},
		name: params.containerName,
	})
}

// startLoadgenNodeWithReleaseImage starts a load generator container using the release image.
func startLoadgenNodeWithReleaseImage(
	ctx context.Context,
	t *testing.T,
	params startNodeParameters,
) {
	t.Helper()
	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.tlsMode, params.node)
	require.NotEmpty(t, serverCredsPath)

	createContainerAndItsLogs(ctx, t, createContainerParameters{
		dockerClient: params.client,
		containerConfig: &container.Config{
			Image: loadgenReleaseImage,
			Cmd: []string{
				params.node,
				"start",
				"--config",
				fmt.Sprintf("%s.yaml", filepath.Join(containerConfigPath, params.node)),
			},
			Hostname: params.node,
			ExposedPorts: nat.PortSet{
				loadGenMetricsPort + "/tcp": {},
			},
			Tty: true,
			Env: []string{
				"SC_LOADGEN_SERVER_TLS_MODE=" + params.tlsMode,
				"SC_LOADGEN_ORDERER_CLIENT_SIDECAR_CLIENT_TLS_MODE=" + params.tlsMode,
			},
		},
		hostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(params.networkName),
			PortBindings: nat.PortMap{
				loadGenMetricsPort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
			},
			Binds: assembleBinds(t,
				serverCredsPath,
				params.clientTLSConfigPath,
				fmt.Sprintf("%s/%s.yaml:/%s/%s.yaml",
					filepath.Join(mustGetWD(t), localConfigPath), params.node,
					containerConfigPath, params.node,
				),
			),
		},
		name: params.containerName,
	})
}

// startNodeWithTestImage starts a committer node using the test image (used for: DB, orderer).
func startNodeWithTestImage(
	ctx context.Context,
	t *testing.T,
	params startNodeParameters,
) {
	t.Helper()
	_, serverCredsPath := params.credsFactory.CreateServerCredentials(t, params.tlsMode, params.node)
	require.NotEmpty(t, serverCredsPath)

	createContainerAndItsLogs(ctx, t, createContainerParameters{
		dockerClient: params.client,
		containerConfig: &container.Config{
			Image:    testNodeImage,
			Cmd:      []string{"run", params.node},
			Tty:      true,
			Hostname: params.node,
			Env: []string{
				"SC_LOADGEN_ORDERER_CLIENT_SIDECAR_CLIENT_TLS_MODE=" + params.tlsMode,
			},
		},
		hostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(params.networkName),
			Binds: assembleBinds(t,
				serverCredsPath,
				params.clientTLSConfigPath,
				fmt.Sprintf("%s:/%s",
					params.configBlockPath,
					filepath.Join(containerConfigPath, genBlockFile),
				),
			),
		},
		name: params.containerName,
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
