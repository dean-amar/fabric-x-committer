package dependencygraph

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

func TestDependencyGraph(t *testing.T) {
	t.Parallel()

	localDepIncomingTxs := make(chan *TransactionBatch, 10)
	localDepOutgoingTxs := make(chan *transactionNodeBatch, 10)

	metrics := newPerformanceMetrics(monitoring.NewProvider())
	ldc := newLocalDependencyConstructor(localDepIncomingTxs, localDepOutgoingTxs, metrics)

	globalDepOutgoingTxs := make(chan TxNodeBatch, 10)
	validatedTxs := make(chan TxNodeBatch, 10)
	dm := newGlobalDependencyManager(
		&globalDepConfig{
			incomingTxsNode:        localDepOutgoingTxs,
			outgoingDepFreeTxsNode: globalDepOutgoingTxs,
			validatedTxsNode:       validatedTxs,
			waitingTxsLimit:        20,
			metrics:                metrics,
		},
	)
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		ldc.run(ctx, 2)
		return nil
	}, nil)
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		dm.run(ctx)
		return nil
	}, nil)

	t.Log("check reads and writes dependency tracking")
	keys := makeTestKeys(t, 10)

	// t2 depends on t1
	t1 := createTxForTest(
		t, nsID1ForTest, [][]byte{keys[0], keys[1]}, [][]byte{keys[2], keys[3]}, [][]byte{keys[4], keys[5]},
	)
	t2 := createTxForTest(
		t, nsID1ForTest, [][]byte{keys[4], keys[5]}, [][]byte{keys[2], keys[6]}, [][]byte{keys[3], keys[7]},
	)

	localDepIncomingTxs <- &TransactionBatch{
		ID:     1,
		Txs:    []*protoblocktx.Tx{t1, t2},
		TxsNum: []uint32{0, 1},
	}

	// t3 depends on t2 and t1
	t3 := createTxForTest(
		t, nsID1ForTest, [][]byte{keys[7], keys[3]}, [][]byte{keys[2], keys[3]}, [][]byte{keys[8], keys[5]},
	)
	// t4 depends on t2 and t1
	t4 := createTxForTest(
		t, nsID1ForTest, [][]byte{keys[7], keys[6]}, [][]byte{keys[4], keys[1]}, [][]byte{keys[0], keys[9]},
	)

	localDepIncomingTxs <- &TransactionBatch{
		ID:     2,
		Txs:    []*protoblocktx.Tx{t3, t4},
		TxsNum: []uint32{0, 1},
	}

	// only t1 is dependency free
	depFreeTxs := <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT1 := depFreeTxs[0]
	require.Equal(t, t1.Id, actualT1.Tx.ID)

	// t1 has 3 dependent transactions, t2, t3, and t4
	require.Eventually(t, func() bool {
		return actualT1.dependentTxs.Count() == 3
	}, 2*time.Second, 200*time.Millisecond)

	validatedTxs <- TxNodeBatch{actualT1}

	// after t1 is validated, t2 is dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT2 := depFreeTxs[0]
	require.Equal(t, t2.Id, actualT2.Tx.ID)

	// t2 has 2 dependent transactions, t3 and t4
	require.Equal(t, 2, actualT2.dependentTxs.Count())

	validatedTxs <- TxNodeBatch{actualT2}

	// after t2 is validated, both t3 and t4 are dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 2)
	var actualT3, actualT4 *TransactionNode
	if t3.Id == depFreeTxs[0].Tx.ID {
		actualT3 = depFreeTxs[0]
		actualT4 = depFreeTxs[1]
	} else {
		actualT3 = depFreeTxs[1]
		actualT4 = depFreeTxs[0]
	}
	require.Equal(t, t3.Id, actualT3.Tx.ID)
	require.Equal(t, t4.Id, actualT4.Tx.ID)

	validatedTxs <- TxNodeBatch{actualT3, actualT4}

	ensureProcessedAndValidatedMetrics(t, metrics, 4, 4)
	// after validating all txs, the dependency detector should be empty
	ensureEmptyDetector(t, dm.dependencyDetector)

	t.Log("check dependency in namespace")
	keys = makeTestKeys(t, 10)
	// t2 depends on t1, t1 depends on t0.
	t0 := createTxForTest(
		t, types.ConfigNamespaceID, nil, nil, [][]byte{[]byte(types.ConfigKey)},
	)
	t1 = createTxForTest(
		t, types.MetaNamespaceID, nil, [][]byte{[]byte(nsID1ForTest)}, nil,
	)
	t2 = createTxForTest(
		t, nsID1ForTest, [][]byte{keys[4], keys[5]}, [][]byte{keys[2], keys[6]}, [][]byte{keys[3], keys[7]},
	)

	localDepIncomingTxs <- &TransactionBatch{
		ID:     3,
		Txs:    []*protoblocktx.Tx{t0, t1, t2},
		TxsNum: []uint32{0, 1, 2},
	}

	// t3 depends on t2, t1, and t0
	t3 = createTxForTest(
		t, types.MetaNamespaceID, nil, [][]byte{[]byte(nsID1ForTest)}, nil,
	)
	// t4 depends on t3, t2 and t1
	t4 = createTxForTest(
		t, nsID1ForTest, [][]byte{keys[7], keys[6]}, [][]byte{keys[4], keys[1]}, [][]byte{keys[0], keys[9]},
	)

	localDepIncomingTxs <- &TransactionBatch{
		ID:     4,
		Txs:    []*protoblocktx.Tx{t3, t4},
		TxsNum: []uint32{0, 1},
	}

	// only t0 is dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT0 := depFreeTxs[0]
	require.Equal(t, t0.Id, actualT0.Tx.ID)

	// t0 has 2 dependent transactions: t1, and t2
	require.Eventually(t, func() bool {
		return actualT0.dependentTxs.Count() == 2
	}, 2*time.Second, 200*time.Millisecond)

	validatedTxs <- TxNodeBatch{actualT0}

	// only t1 is dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT1 = depFreeTxs[0]
	require.Equal(t, t1.Id, actualT1.Tx.ID)

	// t1 has 3 dependent transactions, t2, t3, and t4
	require.Eventually(t, func() bool {
		return actualT1.dependentTxs.Count() == 3
	}, 2*time.Second, 200*time.Millisecond)

	validatedTxs <- TxNodeBatch{actualT1}

	// after t1 is validated, t2 is dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT2 = depFreeTxs[0]
	require.Equal(t, t2.Id, actualT2.Tx.ID)

	// t2 has 2 dependent transactions, t3 and t4
	require.Equal(t, 2, actualT2.dependentTxs.Count())

	validatedTxs <- TxNodeBatch{actualT2}

	// after t2 is validated, t3 becomes dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT3 = depFreeTxs[0]
	require.Equal(t, t3.Id, actualT3.Tx.ID)

	validatedTxs <- TxNodeBatch{actualT3}

	// after t3 is validated, t4 becomes dependency free
	depFreeTxs = <-globalDepOutgoingTxs
	require.Len(t, depFreeTxs, 1)
	actualT4 = depFreeTxs[0]
	require.Equal(t, t4.Id, actualT4.Tx.ID)

	validatedTxs <- TxNodeBatch{actualT4}

	ensureProcessedAndValidatedMetrics(t, metrics, 9, 9)
	// after validating all txs, the dependency detector should be empty
	ensureEmptyDetector(t, dm.dependencyDetector)
}
