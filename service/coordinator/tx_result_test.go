/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package coordinator

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/Chaguar/common/api/committerpb"
	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"

	"github.com/Chaguar/committer/api/servicepb"
	"github.com/Chaguar/committer/service/coordinator/dependencygraph"
	"github.com/Chaguar/committer/utils/channel"
	"github.com/Chaguar/committer/utils/test"
)

type vcResultStream struct {
	servicepb.ValidationAndCommitService_StartValidateAndCommitStreamClient
	batch *servicepb.TxStatusBatch
	done  bool
}

func (s *vcResultStream) Recv() (*servicepb.TxStatusBatch, error) {
	if s.done {
		return nil, io.EOF
	}
	s.done = true
	return s.batch, nil
}

func TestTxCountWithVersionsAndFeedback(t *testing.T) {
	t.Parallel()
	batch := txStatusBatch("a", "b")
	batch.TxResult[0].BlindWriteVersions = []*committerpb.NamespaceWriteVersions{{
		NsId:   "1",
		Writes: make([]*committerpb.CommittedWriteVersion, 30),
	}}
	batch.CheckpointFeedback = &servicepb.CheckpointFeedback{Signal: servicepb.CheckpointFeedback_HOLD}
	require.EqualValues(t, 3, txCount(batch))
	q := newTxStatusQueue(1)
	require.True(t, q.write(t.Context(), batch))
	require.EqualValues(t, 3, q.readyCount())
	_, ok := q.read(t.Context())
	require.True(t, ok)
	require.Zero(t, q.readyCount())
}

func TestValidatorCommitterFiltersWholeResults(t *testing.T) {
	t.Parallel()
	vc := newValidatorCommitter(nil, newTestPerfMetrics(), newPolicyManager())
	node := &dependencygraph.TransactionNode{VCTx: &servicepb.VcTx{Ref: committerpb.NewTxRef("tracked", 10, 0)}}
	vc.addTxsBeingValidated(dependencygraph.TxNodeBatch{node})
	good := &servicepb.TxResult{
		Status: committerpb.NewTxStatusFromRef(node.VCTx.Ref, committerpb.Status_COMMITTED),
		BlindWriteVersions: []*committerpb.NamespaceWriteVersions{{
			NsId:   "1",
			Writes: []*committerpb.CommittedWriteVersion{{Key: []byte("k"), Version: 0}},
		}},
	}
	untracked := &servicepb.TxResult{
		Status: committerpb.NewTxStatus(committerpb.Status_COMMITTED, "untracked", 10, 1),
		BlindWriteVersions: []*committerpb.NamespaceWriteVersions{{
			NsId:   "1",
			Writes: []*committerpb.CommittedWriteVersion{{Key: []byte("wrong"), Version: 9}},
		}},
	}
	stream := &vcResultStream{batch: &servicepb.TxStatusBatch{TxResult: []*servicepb.TxResult{untracked, good, good}}}
	nodes := make(chan dependencygraph.TxNodeBatch, 1)
	statuses := newTxStatusQueue(1)
	err := vc.receiveStatusAndForwardToOutput(t.Context(), stream, channel.NewWriter(t.Context(), nodes), statuses)
	require.ErrorIs(t, err, io.EOF)
	batch, ok := statuses.read(t.Context())
	require.True(t, ok)
	require.Len(t, batch.TxResult, 1)
	require.Same(t, good, batch.TxResult[0])
	require.Equal(t, dependencygraph.TxNodeBatch{node}, <-nodes)
	require.Zero(t, vc.txBeingValidated.Count())
}

func TestPendingResultForwardedBeforeDependencyRelease(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	vc := newValidatorCommitter(nil, newTestPerfMetrics(), newPolicyManager())
	node := &dependencygraph.TransactionNode{VCTx: &servicepb.VcTx{Ref: committerpb.NewTxRef("retry", 10, 0)}}
	vc.addTxsBeingValidated(dependencygraph.TxNodeBatch{node})
	result := &servicepb.TxResult{
		Status: committerpb.NewTxStatusFromRef(node.VCTx.Ref, committerpb.Status_COMMITTED),
		BlindWriteVersions: []*committerpb.NamespaceWriteVersions{{
			NsId:   "1",
			Writes: []*committerpb.CommittedWriteVersion{{Key: []byte("k"), Version: 7}},
		}},
	}
	stream := &vcResultStream{batch: &servicepb.TxStatusBatch{TxResult: []*servicepb.TxResult{result}}}
	nodes := make(chan dependencygraph.TxNodeBatch)
	statuses := newTxStatusQueue(0)
	var receiveErr error
	done := test.RunServiceForTest(ctx, t, func(ctx context.Context) error {
		receiveErr = vc.receiveStatusAndForwardToOutput(ctx, stream, channel.NewWriter(ctx, nodes), statuses)
		if errors.Is(receiveErr, io.EOF) {
			return nil
		}
		return receiveErr
	}, nil)
	// Both outputs are unbuffered. Releasing nodes first would deadlock before this read.
	batch, ok := statuses.read(ctx)
	require.True(t, ok)
	require.Same(t, result, batch.TxResult[0])
	released, ok := channel.NewReader(ctx, nodes).Read()
	require.True(t, ok)
	require.Equal(t, dependencygraph.TxNodeBatch{node}, released)
	require.True(t, done.WaitForReady(ctx))
	require.ErrorIs(t, receiveErr, io.EOF)
}
