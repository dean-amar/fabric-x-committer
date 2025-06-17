/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/mock"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/serialization"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

var testGrpcRetryProfile = connection.RetryProfile{
	InitialInterval: 200 * time.Millisecond,
	MaxInterval:     500 * time.Millisecond,
	Multiplier:      2,
	MaxElapsedTime:  time.Second,
}

//nolint:paralleltest // modifies default grpc retry profile.
func TestBroadcastDeliver(t *testing.T) {
	// We use a short retry grpc-config to shorten the test time.
	// This change prevents this test from being parallelized with other tests.
	prevGrpcProfile := connection.DefaultGrpcRetryProfile
	t.Cleanup(func() {
		connection.DefaultGrpcRetryProfile = prevGrpcProfile
	})
	connection.DefaultGrpcRetryProfile = testGrpcRetryProfile
	ordererService, servers, conf := makeConfig(t)

	allEndpoints := conf.Connection.Endpoints

	// We only take the bottom endpoints for now.
	// Later we take the other endpoints and update the client.
	conf.Connection.Endpoints = allEndpoints[:6]
	client, err := New(&conf)
	require.NoError(t, err)
	t.Cleanup(client.Close)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	stream, err := client.Broadcast(ctx)
	require.NoError(t, err)
	outputBlocksChan := make(chan *common.Block, 100)
	go func() {
		deliverConf := &DeliverConfig{
			StartBlkNum: 0,
			EndBlkNum:   MaxBlockNum,
			OutputBlock: outputBlocksChan,
		}
		// We set the client to stop retry after a second to quickly
		// receive the broadcast errors.
		// But for delivery, we want to continue indefinitely.
		for ctx.Err() == nil {
			err = client.Deliver(ctx, deliverConf)
			t.Logf("Deliver ended with: %v", err)
		}
	}()
	outputBlocks := channel.NewReader(ctx, outputBlocksChan)

	t.Log("Read config block")
	b, ok := outputBlocks.Read()
	require.True(t, ok)
	require.NotNil(t, b)
	require.Len(t, b.Data.Data, 1)

	t.Log("All good")
	submit(t, stream, outputBlocks, expectedSubmit{
		id:      "1",
		success: 3,
	})

	t.Log("One server down")
	servers[2].Servers[0].Stop()
	time.Sleep(3 * time.Second)
	submit(t, stream, outputBlocks, expectedSubmit{
		id:      "2",
		success: 3,
	})

	t.Log("Two servers down")
	servers[2].Servers[1].Stop()
	time.Sleep(3 * time.Second)
	submit(t, stream, outputBlocks, expectedSubmit{
		id:          "3",
		success:     2,
		unavailable: 2,
	})

	t.Log("One incorrect server")
	fakeServer := test.RunGrpcServerForTest(ctx, t, servers[2].Configs[0])
	waitUntilGrpcServerIsReady(ctx, t, &servers[2].Configs[0].Endpoint)

	submit(t, stream, outputBlocks, expectedSubmit{
		id:            "4",
		success:       2,
		unavailable:   1,
		unimplemented: 1,
	})

	t.Log("All good again")
	fakeServer.Stop()
	servers[2].Servers[0] = test.RunGrpcServerForTest(ctx, t, servers[2].Configs[0], func(server *grpc.Server) {
		ab.RegisterAtomicBroadcastServer(server, ordererService)
	})
	waitUntilGrpcServerIsReady(ctx, t, &servers[2].Configs[0].Endpoint)
	submit(t, stream, outputBlocks, expectedSubmit{
		id:      "5",
		success: 3,
	})

	t.Log("Insufficient quorum")
	servers[0].Servers[0].Stop()
	servers[0].Servers[1].Stop()
	servers[1].Servers[0].Stop()
	servers[1].Servers[1].Stop()
	time.Sleep(3 * time.Second)
	submit(t, stream, outputBlocks, expectedSubmit{
		id:          "6",
		error:       true,
		success:     1,
		unavailable: 4,
	})

	t.Log("Update endpoints")
	conf.Connection.Endpoints = allEndpoints[6:]
	err = client.UpdateConnections(&conf.Connection)
	require.NoError(t, err)
	submit(t, stream, outputBlocks, expectedSubmit{
		id:      "7",
		success: 3,
	})
}

type expectedSubmit struct {
	id            string
	error         bool
	success       int
	unavailable   int
	unimplemented int
}

func submit(
	t *testing.T,
	stream *EnvelopedStream,
	outputBlocks channel.Reader[*common.Block],
	expected expectedSubmit,
) {
	t.Helper()
	tx := &protoblocktx.Tx{Id: expected.id}
	_, resp, err := stream.SubmitWithEnv(tx)
	var info string
	if err != nil {
		t.Logf("Response error:\n%s", err)
		info = err.Error()
	} else {
		t.Logf("Response info:\n%s", resp.Info)
		info = resp.Info
	}
	if expected.error {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
		require.Equal(t, common.Status_SUCCESS, resp.Status)
	}

	require.Equal(t, expected.success, strings.Count(info, "SUCCESS"), info)

	// We verify that we didn't get more Unavailable or Unimplemented than expected.
	// These errors sometimes returns DeadlineExceeded instead, so we might not get exact value.
	require.LessOrEqual(t, strings.Count(info, "Unavailable"), expected.unavailable+expected.unimplemented, info)
	require.LessOrEqual(t, strings.Count(info, "Unimplemented"), expected.unimplemented, info)

	// We count all of these errors together to ensure we didn't get fewer errors than expected.
	nonSuccessCount := strings.Count(info, "Unavailable") +
		strings.Count(info, "DeadlineExceeded") +
		strings.Count(info, "Unimplemented")
	require.Equal(t, expected.unavailable+expected.unimplemented, nonSuccessCount, info)

	b, ok := outputBlocks.Read()
	require.True(t, ok)
	require.NotNil(t, b)
	require.Len(t, b.Data.Data, 1)
	data, _, err := serialization.UnwrapEnvelope(b.Data.Data[0])
	require.NoError(t, err)
	blockTx, err := serialization.UnmarshalTx(data)
	require.NoError(t, err)
	require.Equal(t, tx.Id, blockTx.Id)
}

func makeConfig(t *testing.T) (*mock.Orderer, []test.GrpcServers, Config) {
	t.Helper()

	idCount := 3
	serverPerID := 4
	instanceCount := idCount * serverPerID
	t.Logf("Instance count: %d; idCount: %d", instanceCount, idCount)
	ordererService, ordererServer := mock.StartMockOrderingServices(
		t, &mock.OrdererConfig{NumService: instanceCount, BlockSize: 1, SendConfigBlock: true},
	)
	require.Len(t, ordererServer.Servers, instanceCount)

	conf := Config{
		ChannelID:     "mychannel",
		ConsensusType: Bft,
		Connection: ConnectionConfig{
			Retry: &connection.RetryProfile{
				MaxElapsedTime: time.Second,
			},
		},
	}
	servers := make([]test.GrpcServers, idCount)
	for i, c := range ordererServer.Configs {
		id := uint32(i % idCount) //nolint:gosec // integer overflow conversion int -> uint32
		conf.Connection.Endpoints = append(conf.Connection.Endpoints, &connection.OrdererEndpoint{
			ID:       id,
			Endpoint: c.Endpoint,
		})
		s := &servers[id]
		s.Configs = append(s.Configs, c)
		s.Servers = append(s.Servers, ordererServer.Servers[i])
	}
	for i, s := range servers {
		require.Lenf(t, s.Configs, serverPerID, "id: %d", i)
		require.Lenf(t, s.Servers, serverPerID, "id: %d", i)
	}
	for i, e := range conf.Connection.Endpoints {
		t.Logf("ENDPOINT [%02d] %s", i, e.String())
	}
	return ordererService, servers, conf
}

func waitUntilGrpcServerIsReady(ctx context.Context, t *testing.T, endpoint *connection.Endpoint) {
	t.Helper()
	newConn, err := connection.Connect(connection.NewInsecureDialConfig(endpoint))
	require.NoError(t, err)
	defer connection.CloseConnectionsLog(newConn)
	test.WaitUntilGrpcServerIsReady(ctx, t, newConn)
	t.Logf("%v is ready", endpoint)
	// Wait a while to allow the GRPC connection enough time to make a new attempt.
	time.Sleep(time.Second)
}
