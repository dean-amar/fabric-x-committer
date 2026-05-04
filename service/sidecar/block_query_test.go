/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// wrapInEnvelope wraps a request in an envelope for testing.
// ACL is disabled in tests (nil provider), so we use unsigned envelopes.
func wrapInEnvelope(t *testing.T, request proto.Message) *common.Envelope {
	t.Helper()

	requestBytes, err := proto.Marshal(request)
	require.NoError(t, err)

	channelHeader := &common.ChannelHeader{
		Type:      int32(common.HeaderType_ENDORSER_TRANSACTION),
		ChannelId: "testchannel",
	}
	channelHeaderBytes, err := proto.Marshal(channelHeader)
	require.NoError(t, err)

	payload := &common.Payload{
		Header: &common.Header{
			ChannelHeader: channelHeaderBytes,
		},
		Data: requestBytes,
	}
	payloadBytes, err := proto.Marshal(payload)
	require.NoError(t, err)

	return &common.Envelope{
		Payload: payloadBytes,
	}
}

func TestBlockQuery(t *testing.T) {
	t.Parallel()

	bs, txIDs := newBlockStoreWithBlocks(t, 2)

	// Create the query service with nil ACL provider (ACL disabled for tests)
	queryService := newBlockQuery(bs, nil)

	config := test.NewLocalHostServer(test.InsecureTLSConfig)
	test.RunGrpcServerForTest(t.Context(), t, config, func(server *grpc.Server) {
		committerpb.RegisterBlockQueryServiceServer(server, queryService)
	})

	conn := test.NewInsecureConnection(t, &config.Endpoint)
	client := committerpb.NewBlockQueryServiceClient(conn)

	t.Run("GetBlockchainInfo", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &emptypb.Empty{})
		info, err := client.GetBlockchainInfo(t.Context(), envelope)
		require.NoError(t, err)
		require.Equal(t, uint64(2), info.GetHeight())
	})

	t.Run("GetBlockByNumber", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.BlockNumber{Number: 1})
		block, err := client.GetBlockByNumber(t.Context(), envelope)
		require.NoError(t, err)
		require.Equal(t, uint64(1), block.GetHeader().GetNumber())
	})

	t.Run("GetBlockByNumber_NotFound", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.BlockNumber{Number: 999})
		_, err := client.GetBlockByNumber(t.Context(), envelope)
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("GetBlockByTxID", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.TxID{TxId: txIDs[1][0]})
		block, err := client.GetBlockByTxID(t.Context(), envelope)
		require.NoError(t, err)
		require.Equal(t, uint64(1), block.GetHeader().GetNumber())
	})

	t.Run("GetBlockByTxID_EmptyTxID", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.TxID{TxId: ""})
		_, err := client.GetBlockByTxID(t.Context(), envelope)
		require.ErrorContains(t, err, "tx_id must not be empty")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("GetBlockByTxID_NotFound", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.TxID{TxId: "nonexistent"})
		_, err := client.GetBlockByTxID(t.Context(), envelope)
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("GetTxByID", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.TxID{TxId: txIDs[0][0]})
		txEnvelope, err := client.GetTxByID(t.Context(), envelope)
		require.NoError(t, err)
		require.NotNil(t, txEnvelope)
	})

	t.Run("GetTxByID_EmptyTxID", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.TxID{TxId: ""})
		_, err := client.GetTxByID(t.Context(), envelope)
		require.ErrorContains(t, err, "tx_id must not be empty")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("GetTxByID_NotFound", func(t *testing.T) {
		t.Parallel()
		envelope := wrapInEnvelope(t, &committerpb.TxID{TxId: "nonexistent"})
		_, err := client.GetTxByID(t.Context(), envelope)
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})
}
