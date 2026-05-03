/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/utils/test"
)

func TestBlockQuery(t *testing.T) {
	t.Parallel()

	bs, txIDs, signer := newBlockStoreWithBlocks(t, 2)

	// Create the query service and register on a gRPC server.
	queryService := newBlockQuery(bs, func() *common.Block {
		block, err := bs.store.RetrieveBlockByNumber(0)
		require.NoError(t, err)
		return block
	})

	config := test.NewLocalHostServer(test.InsecureTLSConfig)
	test.RunGrpcServerForTest(t.Context(), t, config, func(server *grpc.Server) {
		committerpb.RegisterBlockQueryServiceServer(server, queryService)
	})

	conn := test.NewInsecureConnection(t, &config.Endpoint)
	client := committerpb.NewBlockQueryServiceClient(conn)

	t.Run("GetBlockchainInfo", func(t *testing.T) {
		t.Parallel()
		info, err := client.GetBlockchainInfo(t.Context(), newTestEnvelope(t, signer, &committerpb.BlockNumber{}))
		require.NoError(t, err)
		require.Equal(t, uint64(3), info.GetHeight())
	})

	t.Run("GetBlockByNumber", func(t *testing.T) {
		t.Parallel()
		block, err := client.GetBlockByNumber(t.Context(), newTestEnvelope(t, signer, &committerpb.BlockNumber{Number: 1}))
		require.NoError(t, err)
		require.Equal(t, uint64(1), block.GetHeader().GetNumber())
	})

	t.Run("GetBlockByNumber_NotFound", func(t *testing.T) {
		t.Parallel()
		_, err := client.GetBlockByNumber(t.Context(), newTestEnvelope(t, signer, &committerpb.BlockNumber{Number: 999}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("GetBlockByTxID", func(t *testing.T) {
		t.Parallel()
		block, err := client.GetBlockByTxID(t.Context(), newTestEnvelope(t, signer, &committerpb.TxID{TxId: txIDs[1][0]}))
		require.NoError(t, err)
		require.Equal(t, uint64(2), block.GetHeader().GetNumber())
	})

	t.Run("GetBlockByTxID_EmptyTxID", func(t *testing.T) {
		t.Parallel()
		_, err := client.GetBlockByTxID(t.Context(), newTestEnvelope(t, signer, &committerpb.TxID{TxId: ""}))
		require.ErrorContains(t, err, "tx_id must not be empty")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("GetBlockByTxID_NotFound", func(t *testing.T) {
		t.Parallel()
		_, err := client.GetBlockByTxID(t.Context(), newTestEnvelope(t, signer, &committerpb.TxID{TxId: "nonexistent"}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("GetTxByID", func(t *testing.T) {
		t.Parallel()
		envelope, err := client.GetTxByID(t.Context(), newTestEnvelope(t, signer, &committerpb.TxID{TxId: txIDs[0][0]}))
		require.NoError(t, err)
		require.NotNil(t, envelope)
	})

	t.Run("GetTxByID_EmptyTxID", func(t *testing.T) {
		t.Parallel()
		_, err := client.GetTxByID(t.Context(), newTestEnvelope(t, signer, &committerpb.TxID{TxId: ""}))
		require.ErrorContains(t, err, "tx_id must not be empty")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	})

	t.Run("GetTxByID_NotFound", func(t *testing.T) {
		t.Parallel()
		_, err := client.GetTxByID(t.Context(), newTestEnvelope(t, signer, &committerpb.TxID{TxId: "nonexistent"}))
		require.Error(t, err)
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("GetBlockByNumber_UnauthorizedSigner", func(t *testing.T) {
		t.Parallel()

		unauthorizedSigner := newTestSigningIdentity(t)
		_, err := client.GetBlockByNumber(
			t.Context(),
			newTestEnvelope(t, unauthorizedSigner, &committerpb.BlockNumber{Number: 1}),
		)
		require.Error(t, err)
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.ErrorContains(t, err, "failed to deserialize creator identity")
	})
}

func newTestEnvelope(t *testing.T, signer msp.SigningIdentity, msg proto.Message) *common.Envelope {
	t.Helper()
	env, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_MESSAGE,
		"",
		signer,
		msg,
		0,
		0,
	)
	require.NoError(t, err)
	return env
}

func newTestSigningIdentity(t *testing.T) msp.SigningIdentity {
	t.Helper()

	_, signer := createCommittedConfigBlockForTest(t)
	return signer
}
