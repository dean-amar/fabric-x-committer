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
	"github.com/hyperledger/fabric-x-committer/api/protoloadgen"
	"github.com/hyperledger/fabric-x-committer/api/protonotify"
	"github.com/hyperledger/fabric-x-committer/api/protoqueryservice"
	"github.com/hyperledger/fabric-x-committer/cmd/config"
	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/service/sidecar/sidecarclient"
	"github.com/hyperledger/fabric-x-committer/service/vc/dbtest"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/ordererconn"
	"github.com/hyperledger/fabric-x-committer/utils/signature"
	testutils "github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-common/internaltools/configtxgen"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
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

// TestStartTestNodeWithoutLoadgen spawns an all-in-one instance of the committer using docker
// to verify that the committer container starts as expected.
func TestStartTestNodeWithoutLoadgen(t *testing.T) {
	t.Parallel()
	credsFactory := testutils.NewCredentialsFactory(t)

	//Policy := workload.PolicyProfile{
	//	ChannelID:         channelName,
	//	NamespacePolicies: make(map[string]*workload.Policy),
	//}
	//
	//ordererEndpoint, err := connection.NewEndpoint(
	//	net.JoinHostPort("localhost", mockOrdererPort),
	//)
	//
	//Policy.OrdererEndpoints = make([]*ordererconn.Endpoint, 1)
	//Policy.OrdererEndpoints[0] = &ordererconn.Endpoint{ID: 0, MspID: "org", Endpoint: *ordererEndpoint}
	//
	//t.Log("creating config-block")
	//configBlockPath := filepath.Join(t.TempDir(), genBlockFile)
	//configBlock, err := workload.CreateConfigBlock(&Policy)
	//require.NoError(t, err)
	//err = configtxgen.WriteOutputBlock(configBlock, configBlockPath)
	//require.NoError(t, err)

	configBlockPath := filepath.Join(t.TempDir(), genBlockFile)
	v := config.NewViperWithLoadGenDefaults()
	c, err := config.ReadLoadGenYamlAndSetupLogging(v, filepath.Join(localConfigPath, "loadgen.yaml"))
	require.NoError(t, err)
	configBlock, err := workload.CreateConfigBlock(c.LoadProfile.Transaction.Policy)
	require.NoError(t, err)
	require.NoError(t, configtxgen.WriteOutputBlock(configBlock, configBlockPath))

	txBuilder := AddOrUpdateNamespaces(t, c.LoadProfile.Transaction.Policy, "1", "2")

	for _, mode := range []string{connection.NoneTLSMode} {
		t.Run(fmt.Sprintf("tls-mode:%s", mode), func(t *testing.T) {
			t.Parallel()
			containerName := assembleContainerName("committer", mode, dbtest.PostgresDBType)
			clientTLSConfig, _ := credsFactory.CreateClientCredentials(t, mode)

			ctx := t.Context()
			stopAndRemoveContainersByName(ctx, t, createDockerClient(t), containerName)
			startCommitter(ctx, t, startNodeParameters{
				node:         containerName,
				credsFactory: credsFactory,
				tlsMode:      mode,
				//configBlockPath: configBlockPath,
			})

			ordererEndpoint, err := connection.NewEndpoint(
				net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, mockOrdererPort)),
			)
			//ordererEndpoint, err := connection.NewEndpoint(
			//	net.JoinHostPort("172.17.0.2", mockOrdererPort),
			//)
			//Policy.OrdererEndpoints[0] =
			//	require.NoError(t, err)
			t.Logf("orederer-endpoint: %v", ordererEndpoint)
			ep := &ordererconn.Endpoint{ID: 0, MspID: "org", Endpoint: *ordererEndpoint}
			ordererStream, err := testutils.NewBroadcastStream(t.Context(), &ordererconn.Config{
				Connection: ordererconn.ConnectionConfig{
					Endpoints: []*ordererconn.Endpoint{
						ep,
					},
				},
				ChannelID:     c.LoadProfile.Transaction.Policy.ChannelID,
				Identity:      c.LoadProfile.Transaction.Policy.Identity,
				ConsensusType: ordererconn.Bft,
			})
			t.Log(ordererStream)
			queryEndpoint, err := connection.NewEndpoint(
				net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, queryServicePort)),
			)
			require.NoError(t, err)
			QueryServiceClient := protoqueryservice.NewQueryServiceClient(
				testutils.NewSecuredConnection(t, queryEndpoint, clientTLSConfig),
			)
			t.Log(QueryServiceClient)
			sidecarEndpoint, err := connection.NewEndpoint(
				net.JoinHostPort("localhost", getContainerMappedHostPort(ctx, t, containerName, sidecarPort)),
			)
			require.NoError(t, err)

			notifyClient := protonotify.NewNotifierClient(
				testutils.NewSecuredConnection(t, sidecarEndpoint, clientTLSConfig),
			)

			notifyStream, err := notifyClient.OpenNotificationStream(ctx)
			require.NoError(t, err)
			t.Log(notifyStream)
			CreateNamespacesAndCommit(t, &notifyStream, ordererStream, txBuilder, c.LoadProfile.Transaction.Policy, "1", "2")

			time.Sleep(20 * time.Second)

			t.Log("Insert TXs")
			txIDs := MakeAndSendTransactionsToOrderer(t, &notifyStream, ordererStream, txBuilder, [][]*protoblocktx.TxNamespace{
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
			}, []protoblocktx.Status{protoblocktx.Status_COMMITTED, protoblocktx.Status_COMMITTED})
			require.Len(t, txIDs, 1)

			time.Sleep(10 * time.Second)

			t.Log("Query Rows")
			ret, err := QueryServiceClient.GetRows(
				ctx,
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
			t.Logf("return namespace ID: %v", ret)

			t.Log("Try to fetch the first block")
			committedBlock := sidecarclient.StartSidecarClient(ctx, t, &sidecarclient.Parameters{
				ChannelID: channelName,
				Client:    testutils.NewTLSClientConfig(clientTLSConfig, sidecarEndpoint),
			}, 0)
			b, ok := channel.NewReader(ctx, committedBlock).Read()
			require.True(t, ok)

			t.Logf("the block: %v", b.String())
			t.Logf("Received block #%d with %d TXs", b.Header.Number, len(b.Data.Data))

			//time.Sleep(20 * time.Second)
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

// AddOrUpdateNamespaces adds policies for namespaces. If already exists, the policy will be updated.
func AddOrUpdateNamespaces(t *testing.T, policy *workload.PolicyProfile, namespaces ...string) *workload.TxBuilder {
	t.Helper()
	for _, ns := range namespaces {
		policy.NamespacePolicies[ns] = &workload.Policy{
			Scheme: signature.Ecdsa,
			Seed:   rand.New(rand.NewSource(10)).Int63(),
		}
	}
	var err error
	TxBuilder, err := workload.NewTxBuilderFromPolicy(policy, nil)
	require.NoError(t, err)

	return TxBuilder
}

func CreateNamespacesAndCommit(t *testing.T, notifyStream *protonotify.Notifier_OpenNotificationStreamClient, ordererStream *testutils.BroadcastStream, txBuilder *workload.TxBuilder, policy *workload.PolicyProfile, namespaces ...string) {
	t.Helper()
	if len(namespaces) == 0 {
		return
	}

	t.Logf("Creating namespaces: %v", namespaces)
	metaTX, err := workload.CreateNamespacesTX(policy, 0, namespaces...)
	require.NoError(t, err)
	MakeAndSendTransactionsToOrderer(
		t,
		notifyStream,
		ordererStream,
		txBuilder,
		[][]*protoblocktx.TxNamespace{metaTX.Namespaces},
		[]protoblocktx.Status{protoblocktx.Status_COMMITTED},
	)
}

// MakeAndSendTransactionsToOrderer creates a block with given transactions, send it to the committer,
// and verify the result.
func MakeAndSendTransactionsToOrderer(
	t *testing.T, notifyStream *protonotify.Notifier_OpenNotificationStreamClient, ordererStream *testutils.BroadcastStream, txBuilder *workload.TxBuilder, txsNs [][]*protoblocktx.TxNamespace, expectedStatus []protoblocktx.Status,
) []string {
	t.Helper()
	txs := make([]*protoloadgen.TX, len(txsNs))

	for i, namespaces := range txsNs {
		tx := &protoblocktx.Tx{
			Namespaces: namespaces,
		}
		if expectedStatus != nil && expectedStatus[i] == protoblocktx.Status_ABORTED_SIGNATURE_INVALID {
			tx.Signatures = make([][]byte, len(namespaces))
			for nsIdx := range namespaces {
				tx.Signatures[nsIdx] = []byte("dummy")
			}
		}
		txs[i] = txBuilder.MakeTx(tx)
	}

	return SendTransactionsToOrderer(t, *notifyStream, ordererStream, txs, expectedStatus)
}

// SendTransactionsToOrderer creates a block with given transactions, send it to the committer, and verify the result.
func SendTransactionsToOrderer(
	t *testing.T, notifyStream protonotify.Notifier_OpenNotificationStreamClient, ordererStream *testutils.BroadcastStream, txs []*protoloadgen.TX, expectedStatus []protoblocktx.Status,
) []string {
	t.Helper()
	expected := &ExpectedStatusInBlock{
		Statuses: expectedStatus,
		TxIDs:    make([]string, len(txs)),
	}
	for i, tx := range txs {
		expected.TxIDs[i] = tx.Id
	}

	err := notifyStream.Send(&protonotify.NotificationRequest{
		TxStatusRequest: &protonotify.TxStatusRequest{
			TxIds: expected.TxIDs,
		},
		Timeout: durationpb.New(3 * time.Minute),
	})
	require.NoError(t, err)
	// Allows processing the request before submitting the payload.
	time.Sleep(1 * time.Second)

	t.Logf("sending batch with txs!")
	err = ordererStream.SendBatch(workload.MapToEnvelopeBatch(0, txs))
	require.NoError(t, err)
	t.Log("no issues")

	return expected.TxIDs
}

//// mapToStatusBatch creates a status batch from a given block.
//func mapToStatusBatch(block *common.Block) []metrics.TxStatus {
//	if block.Data == nil || len(block.Data.Data) == 0 {
//		return nil
//	}
//	blockSize := len(block.Data.Data)
//
//	var statusCodes []byte
//	if block.Metadata != nil && len(block.Metadata.Metadata) > statusIdx {
//		statusCodes = block.Metadata.Metadata[statusIdx]
//	}
//	logger.Infof("Received block #%d with %d TXs and %d statuses [%s]",
//		block.Header.Number, len(block.Data.Data), len(statusCodes), recapStatusCodes(statusCodes),
//	)
//
//	statusBatch := make([]metrics.TxStatus, 0, blockSize)
//	for i, data := range block.Data.Data {
//		_, channelHeader, err := serialization.UnwrapEnvelope(data)
//		if err != nil {
//			logger.Warnf("Failed to unmarshal envelope: %v", err)
//			continue
//		}
//		if common.HeaderType(channelHeader.Type) == common.HeaderType_CONFIG {
//			// We can ignore config transactions as we only count data transactions.
//			continue
//		}
//		status := protoblocktx.Status_COMMITTED
//		if len(statusCodes) > i {
//			status = protoblocktx.Status(statusCodes[i])
//		}
//		statusBatch = append(statusBatch, metrics.TxStatus{
//			TxID:   channelHeader.TxId,
//			Status: status,
//		})
//	}
//	return statusBatch
//}
