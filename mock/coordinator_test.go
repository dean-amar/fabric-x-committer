/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mock

import (
	"testing"
	"time"

	"github.com/Chaguar/common/api/committerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/Chaguar/committer/api/servicepb"
	"github.com/Chaguar/committer/utils/test"
)

func TestCoordinatorBlockProcessing(t *testing.T) {
	t.Parallel()
	_, servers := StartMockCoordinatorService(t, test.StartServerParameters{})
	client := servicepb.NewCoordinatorClient(test.NewInsecureConnection(t, &servers.Configs[0].GRPC.Endpoint))
	stream, err := client.BlockProcessing(t.Context())
	require.NoError(t, err)

	// Step 1: rejected TXs get a status too, so they must count as in progress until then.
	t.Log("Step 1: a batch of only rejected TXs")
	require.NoError(t, stream.Send(&servicepb.CoordinatorBatch{Rejected: []*committerpb.TxStatus{
		committerpb.NewTxStatus(committerpb.Status_MALFORMED_BAD_ENVELOPE, "rejected-tx", 5, 0),
	}}))
	requireStatusCount(t, stream, 1)
	requireNextBlock(t, client, 6)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		idle, idleErr := client.NoPendingTransactionProcessing(t.Context(), nil)
		require.NoError(ct, idleErr)
		require.True(ct, idle.GetValue())
	}, 5*time.Second, 10*time.Millisecond)

	// Step 2: an empty batch has no block number, and an older block must not lower it.
	t.Log("Step 2: an empty batch, then an older block")
	require.NoError(t, stream.Send(&servicepb.CoordinatorBatch{}))
	require.NoError(t, stream.Send(&servicepb.CoordinatorBatch{Txs: []*servicepb.TxWithRef{
		{Ref: committerpb.NewTxRef("old-tx", 3, 0)},
	}}))
	requireStatusCount(t, stream, 1)
	requireNextBlock(t, client, 6)

	t.Log("Step 3: SetLastCommittedBlockNumber sets the next block")
	_, err = client.SetLastCommittedBlockNumber(t.Context(), &servicepb.BlockRef{Number: 9})
	require.NoError(t, err)
	requireNextBlock(t, client, 10)

	t.Log("Step 4: GetTransactionsStatus omits unknown TXs")
	res, err := client.GetTransactionsStatus(t.Context(), &committerpb.TxIDsBatch{
		TxIds: []string{"rejected-tx", "unknown-tx"},
	})
	require.NoError(t, err)
	require.Len(t, res.TxResult, 1)
	require.Equal(t, "rejected-tx", res.TxResult[0].Status.Ref.TxId)
}

func requireStatusCount(
	t *testing.T,
	stream grpc.BidiStreamingClient[servicepb.CoordinatorBatch, servicepb.TxStatusBatch],
	expected int,
) {
	t.Helper()
	// The mock splits the statuses into random chunks.
	for received := 0; received < expected; {
		res, err := stream.Recv()
		require.NoError(t, err)
		received += len(res.TxResult)
	}
}

func requireNextBlock(t *testing.T, client servicepb.CoordinatorClient, expected uint64) {
	t.Helper()
	next, err := client.GetNextBlockNumberToCommit(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, expected, next.Number)
}
