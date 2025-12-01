/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	_ "embed"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/hyperledger/fabric-x-committer/api/protoblocktx"
	"github.com/hyperledger/fabric-x-committer/api/protoqueryservice"
	"github.com/hyperledger/fabric-x-committer/cmd/config"
	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/service/sidecar/sidecarclient"
	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/service/vc/dbtest"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
	testutils "github.com/hyperledger/fabric-x-committer/utils/test"
)

const (
	sidecarPort            = "4001"
	loadGenMetricsPort     = "2118"
	mockOrdererPort        = "7050"
	queryServicePort       = "7001"
	coordinatorServicePort = "9001"
	databasePort           = "5433"
)

// TestStartTestNodeWithoutLoadgen spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNodeWithoutLoadgen(t *testing.T) {
	t.Parallel()

	// reading the transaction policy from the config block
	v := config.NewViperWithLoadGenDefaults()
	conf, err := config.ReadLoadGenYamlAndSetupLogging(v, filepath.Join(localConfigPath, "loadgen.yaml"))
	require.NoError(t, err)
	// creating credential factory
	credsFactory := testutils.NewCredentialsFactory(t)

	for _, mode := range testutils.ServerModes {
		t.Run(fmt.Sprintf("tls-mode:%s", mode), func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			containerName := assembleContainerName("committer", mode, dbtest.PostgresDBType)
			stopAndRemoveContainersByName(ctx, t, createDockerClient(t), containerName)
			startCommitter(ctx, t, startNodeParameters{
				node:         containerName,
				credsFactory: credsFactory,
				tlsMode:      mode,
			})
			// we create dbEnv so we can connect to the database and verify the txs.
			// we need to use the same credentials as defined in the yaml files.
			dbEnv := vc.NewDatabaseTestEnvFromConnection(
				t,
				dbtest.NewConnection(mustGetEndpoint(ctx, t, containerName, databasePort)),
				false,
			)

			c := conf
			c.LoadProfile.Transaction.Policy.OrdererEndpoints = []*ordererconn.Endpoint{
				{
					ID:       0,
					MspID:    "org",
					Endpoint: *mustGetEndpoint(ctx, t, containerName, mockOrdererPort),
				},
			}
			runtime := runner.CommitterRuntime{
				CredFactory:      credsFactory,
				SeedForCryptoGen: rand.New(rand.NewSource(10)),
				Config: &runner.Config{
					CrashTest: false,
				},
				SystemConfig: config.SystemConfig{
					Endpoints: config.SystemEndpoints{
						Sidecar: config.ServiceEndpoints{
							Server: mustGetEndpoint(ctx, t, containerName, sidecarPort),
						},
						Query: config.ServiceEndpoints{
							Server: mustGetEndpoint(ctx, t, containerName, queryServicePort),
						},
						Coordinator: config.ServiceEndpoints{
							Server: mustGetEndpoint(ctx, t, containerName, coordinatorServicePort),
						},
					},
					Policy: c.LoadProfile.Transaction.Policy,
				},
				DBEnv: dbEnv,
			}
			runtime.SystemConfig.ClientTLS, _ = runtime.CredFactory.CreateClientCredentials(t, mode)

			runtime.CreateRuntimeClients(ctx, t)
			runtime.OpenNotificationStream(ctx, t)

			runtime.AddOrUpdateNamespaces(t, "1")

			runtime.CommittedBlock = sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Parameters{
				ChannelID: channelName,
				Client: testutils.NewTLSClientConfig(
					runtime.SystemConfig.ClientTLS, runtime.SystemConfig.Endpoints.Sidecar.Server,
				),
			}, 0)

			t.Log("Try to fetch the first block")
			b, ok := channel.NewReader(ctx, runtime.CommittedBlock).Read()
			require.True(t, ok)
			t.Logf("Received block #%d with %d TXs", b.Header.Number, len(b.Data.Data))

			runtime.CreateNamespacesAndCommit(t, "1")

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
			}, []protoblocktx.Status{protoblocktx.Status_COMMITTED})
			require.Len(t, txIDs, 1)

			t.Log("Query Rows")
			timeoutContext, cancel := context.WithTimeout(ctx, time.Minute)
			t.Cleanup(cancel)

			ret, err := runtime.QueryServiceClient.GetRows(
				timeoutContext,
				&protoqueryservice.Query{
					Namespaces: []*protoqueryservice.QueryNamespace{
						{
							NsId: "1",
							Keys: [][]byte{
								[]byte("k1"), []byte("k2"),
							},
						},
					},
				},
			)
			require.NoError(t, err)
			t.Logf("read rows from namespace: %v", ret)

			requiredItems := []*protoqueryservice.RowsNamespace{
				{
					NsId: "1",
					Rows: []*protoqueryservice.Row{
						{
							Key:     []byte("k1"),
							Value:   []byte("v1"),
							Version: 0,
						},
						{
							Key:     []byte("k2"),
							Value:   []byte("v2"),
							Version: 0,
						},
					},
				},
			}
			requireQueryResults(t, requiredItems, ret.Namespaces)
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
				sidecarPort + "/tcp":            struct{}{},
				mockOrdererPort + "/tcp":        struct{}{},
				queryServicePort + "/tcp":       struct{}{},
				coordinatorServicePort + "/tcp": struct{}{},
				databasePort + "/tcp":           struct{}{},
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
				mockOrdererPort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
				queryServicePort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
				coordinatorServicePort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
				databasePort + "/tcp": []nat.PortBinding{{
					HostIP:   "localhost",
					HostPort: "0", // auto port assign
				}},
			},
			Binds: assembleBinds(t, params.asNode("localhost")),
		},
		name: params.node,
	})
}

func mustGetEndpoint(ctx context.Context, t *testing.T, containerName, servicePort string) *connection.Endpoint {
	t.Helper()
	ep, err := connection.NewEndpoint(
		net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, servicePort)),
	)
	require.NoError(t, err)
	return ep
}

// requireQueryResults requires that the items retrieved by the Query service
// equals to the test items that added to the DB.
// We can’t use ElementsMatch to compare protobuf messages.
// In the in-process tests, the QueryService returns Row objects created directly
// in Go, so their internal protobuf fields stay zeroed.
// But in the Docker tests, the response comes through real gRPC
// (Marshal → send bytes → Unmarshal), which fills internal protobuf fields.
// These hidden fields differ even when Key/Value/Version are identical,
// so DeepEqual sees them as “not equal”. Use a protobuf-aware comparison instead.
func requireQueryResults(
	t *testing.T,
	requiredItems []*protoqueryservice.RowsNamespace,
	retNamespaces []*protoqueryservice.RowsNamespace,
) {
	t.Helper()
	require.Len(t, retNamespaces, len(requiredItems))
	for idx := range retNamespaces {
		require.True(t,
			cmp.Equal(requiredItems[idx].Rows, retNamespaces[idx].Rows, protocmp.Transform()),
			cmp.Diff(requiredItems[idx].Rows, retNamespaces[idx].Rows, protocmp.Transform()),
		)
	}
}
