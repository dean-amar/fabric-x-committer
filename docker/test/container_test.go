/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	"github.com/hyperledger/fabric-x-committer/api/protoblocktx"
	"github.com/hyperledger/fabric-x-committer/api/protonotify"
	"github.com/hyperledger/fabric-x-committer/api/protoqueryservice"
	"github.com/hyperledger/fabric-x-committer/cmd/config"
	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/service/sidecar/sidecarclient"
	"github.com/hyperledger/fabric-x-committer/service/vc/dbtest"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
	testutils "github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/stretchr/testify/require"
	"math/rand"
	"net"
	"path/filepath"
	"testing"
	"time"
)

const (
	sidecarPort        = "4001"
	loadGenMetricsPort = "2118"
	mockOrdererPort    = "7050"
	queryServicePort   = "7001"
)

// ExpectedStatusInBlock holds pairs of expected txID and the corresponding status in a block. The order of statuses
// is expected to be the same as in the committed block.
type ExpectedStatusInBlock struct {
	TxIDs    []string
	Statuses []protoblocktx.Status
}

var defaultRetryProfile connection.RetryProfile

// TestStartTestNodeWithoutLoadgen spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNodeWithoutLoadgen(t *testing.T) {
	t.Parallel()

	// reading the transaction policy from the config block
	v := config.NewViperWithLoadGenDefaults()
	c, err := config.ReadLoadGenYamlAndSetupLogging(v, filepath.Join(localConfigPath, "loadgen.yaml"))
	require.NoError(t, err)

	//t.Log(runtime)

	for _, mode := range []string{connection.NoneTLSMode, connection.OneSideTLSMode, connection.MutualTLSMode} {
		t.Run(fmt.Sprintf("tls-mode:%s", mode), func(t *testing.T) {
			t.Parallel()
			containerName := assembleContainerName("committer", mode, dbtest.PostgresDBType)

			runtime := runner.CommitterRuntime{
				CredFactory:      testutils.NewCredentialsFactory(t),
				SeedForCryptoGen: rand.New(rand.NewSource(10)),
				Config: &runner.Config{
					CrashTest: false,
				},
			}

			ctx := t.Context()
			stopAndRemoveContainersByName(ctx, t, createDockerClient(t), containerName)
			startCommitter(ctx, t, startNodeParameters{
				node:         containerName,
				credsFactory: runtime.CredFactory,
				tlsMode:      mode,
			})

			runtime.SystemConfig.Policy = c.LoadProfile.Transaction.Policy
			runtime.AddOrUpdateNamespaces(t, "1")

			clientTLSConfig, _ := runtime.CredFactory.CreateClientCredentials(t, mode)

			// creating notification service client
			sidecarEndpoint, err := connection.NewEndpoint(
				net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, sidecarPort)),
			)

			runtime.CommittedBlock = sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Parameters{
				ChannelID: channelName,
				Client:    testutils.NewTLSClientConfig(clientTLSConfig, sidecarEndpoint),
			}, 0)

			ordererEndpoint, err := connection.NewEndpoint(
				net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, mockOrdererPort)),
			)

			runtime.OrdererStream, err = testutils.NewBroadcastStream(t.Context(), &ordererconn.Config{
				Connection: ordererconn.ConnectionConfig{
					Endpoints: []*ordererconn.Endpoint{
						{
							ID:       0,
							MspID:    "org",
							Endpoint: *ordererEndpoint,
						},
					},
					TLS: clientTLSConfig,
				},
				ChannelID:     c.LoadProfile.Transaction.Policy.ChannelID,
				Identity:      c.LoadProfile.Transaction.Policy.Identity,
				ConsensusType: ordererconn.Bft,
			})

			// creating query service client
			queryEndpoint, err := connection.NewEndpoint(
				net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, queryServicePort)),
			)
			require.NoError(t, err)
			runtime.QueryServiceClient = protoqueryservice.NewQueryServiceClient(
				testutils.NewSecuredConnection(t, queryEndpoint, clientTLSConfig),
			)

			require.NoError(t, err)
			runtime.NotifyClient = protonotify.NewNotifierClient(
				testutils.NewSecuredConnection(t, sidecarEndpoint, clientTLSConfig),
			)
			// creating notification service stream
			runtime.NotifyStream, err = runtime.NotifyClient.OpenNotificationStream(ctx)
			require.NoError(t, err)

			runtime.CreateNamespacesAndCommit(t, "1")

			//// create namespaces and commit
			//CreateNamespacesAndCommit(t, &notifyStream, ordererStream, runtime.TxBuilder, c.LoadProfile.Transaction.Policy, "1")

			t.Log("Insert TXs")

			txIDs := runtime.MakeAndSendTransactionsToOrderer(t, [][]*protoblocktx.TxNamespace{
				{{
					NsId:      "1",
					NsVersion: 0,
					BlindWrites: []*protoblocktx.Write{
						{
							Key:   []byte("k1"),
							Value: []byte("v1"),
						},
						{
							Key:   []byte("k2"),
							Value: []byte("v2"),
						},
					},
				}},
			}, nil)
			//txIDs := MakeAndSendTransactionsToOrderer(t, &notifyStream, ordererStream, runtime.TxBuilder, [][]*protoblocktx.TxNamespace{
			//	{{
			//		NsId:      "1",
			//		NsVersion: 0,
			//		BlindWrites: []*protoblocktx.Write{
			//			{
			//				Key:   []byte("k1"),
			//				Value: []byte("v1"),
			//			},
			//			{
			//				Key:   []byte("k2"),
			//				Value: []byte("v2"),
			//			},
			//		},
			//	}},
			//}, []protoblocktx.Status{protoblocktx.Status_COMMITTED, protoblocktx.Status_COMMITTED})
			require.Len(t, txIDs, 1)

			t.Log("Query Rows")
			timeoutContext, cancel := context.WithTimeout(ctx, time.Minute)
			t.Cleanup(cancel)
			require.NoError(t, defaultRetryProfile.Execute(timeoutContext, func() error {
				ret, err := runtime.QueryServiceClient.GetRows(
					timeoutContext,
					&protoqueryservice.Query{
						Namespaces: []*protoqueryservice.QueryNamespace{
							{
								NsId: "1",
								Keys: [][]byte{
									[]byte("k1"),
									[]byte("k2"),
								},
							},
						},
					},
				)
				if err == nil {
					t.Logf("read rows from namespace: %v", ret)
				}
				return err
			}))

			t.Log("Try to fetch the first block")
			//runtime.CommittedBlock = sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Parameters{
			//	ChannelID: channelName,
			//	Client:    testutils.NewTLSClientConfig(clientTLSConfig, sidecarEndpoint),
			//}, 0)
			b, ok := channel.NewReader(ctx, runtime.CommittedBlock).Read()
			require.True(t, ok)

			t.Logf("the block: %v", b.String())
			t.Logf("Received block #%d with %d TXs", b.Header.Number, len(b.Data.Data))
		})
	}
}

func startCommitter(ctx context.Context, t *testing.T, params startNodeParameters) {
	t.Helper()
	createAndStartContainerAndItsLogs(ctx, t, createAndStartContainerParameters{
		config: &container.Config{
			Image: testNodeImage,
			Cmd:   []string{"run", "db", "committer", "orderer"},
			ExposedPorts: nat.PortSet{
				sidecarPort + "/tcp":        struct{}{},
				loadGenMetricsPort + "/tcp": struct{}{},
				mockOrdererPort + "/tcp":    struct{}{},
				queryServicePort + "/tcp":   struct{}{},
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
				"SC_SIDECAR_ORDERER_CONNECTION_TLS_MODE=" + params.tlsMode,
				"SC_LOADGEN_SERVER_TLS_MODE=" + params.tlsMode,
				"SC_LOADGEN_ORDERER_CLIENT_SIDECAR_CLIENT_TLS_MODE=" + params.tlsMode,
				"SC_LOADGEN_ORDERER_CLIENT_ORDERER_CONNECTION_TLS_MODE=" + params.tlsMode,
				"SC_ORDERER_SERVER_TLS_MODE=" + params.tlsMode,
			},
			Tty: true,
		},
		hostConfig: &container.HostConfig{
			NetworkMode: network.NetworkDefault,
			PortBindings: nat.PortMap{
				// sidecar port binding
				sidecarPort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
				// loadgen service port bindings
				loadGenMetricsPort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
				mockOrdererPort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
				queryServicePort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
			},
			Binds: assembleBinds(t, params.asNode("localhost")), //fmt.Sprintf("%s:/%s", params.configBlockPath, filepath.Join(containerConfigPath, genBlockFile)),

		},
		name: params.node,
	})
}
