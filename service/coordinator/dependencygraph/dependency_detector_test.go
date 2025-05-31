/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDependencyDetector(t *testing.T) {
	t.Parallel()

	keys := makeTestKeys(t, 6)

	dd := newDependencyDetector()

	tx1Node := createTxNode(t, [][]byte{keys[0], keys[1]}, [][]byte{keys[2], keys[3]}, [][]byte{keys[4], keys[5]})
	dependsOnTx := dd.getDependenciesOf(tx1Node)
	require.Empty(t, dependsOnTx)

	depDetect := newDependencyDetector()
	depDetect.addWaitingTx(tx1Node)
	dd.mergeWaitingTx(depDetect)

	// tx2Node depends on tx1Node as tx2 writes k1 while tx1 reads k1 -- rw dependency.
	tx2Node := createTxNode(t, nil, [][]byte{keys[0]}, nil)
	dependsOnTx = dd.getDependenciesOf(tx2Node)
	expectedDependsOnTx := TxNodeBatch{tx1Node}
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	dd.addWaitingTx(tx2Node)

	// tx3Node depends on tx1Node as tx3 reads k3 while tx1 read-writes k3 -- wr & ww dependency.
	tx3Node := createTxNode(t, [][]byte{keys[2]}, nil, nil)
	dependsOnTx = dd.getDependenciesOf(tx3Node)
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	depDetect = newDependencyDetector()
	depDetect.addWaitingTx(tx3Node)
	dd.mergeWaitingTx(depDetect)

	// tx4Node depends on tx1Node as tx4 writes k5 and k6 while tx1 writes k5 and k6 -- ww dependency.
	tx4Node := createTxNode(t, nil, nil, [][]byte{keys[4], keys[5]})
	dependsOnTx = dd.getDependenciesOf(tx4Node)
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	dd.addWaitingTx(tx4Node)

	// tx5Node depends on tx1Node as tx5 reads k3 while tx1 read-writes k3 -- rw dependency.
	// Further, it has wr and ww dependency on tx1 due to k4.
	tx5Node := createTxNode(t, [][]byte{keys[2]}, [][]byte{keys[3]}, nil)
	dependsOnTx = dd.getDependenciesOf(tx5Node)
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	dd.addWaitingTx(tx5Node)

	// tx6Node depends on tx1Node as tx6 reads k4 while tx1 read-writes k4 -- rw dependency.
	// Further, it has a rw dependency on tx2 due to k1 and a rw dependency on tx5 due to k4.
	tx6Node := createTxNode(t, [][]byte{keys[0], keys[3]}, nil, nil)
	dependsOnTx = dd.getDependenciesOf(tx6Node)
	expectedDependsOnTx = TxNodeBatch{tx5Node, tx2Node, tx1Node}
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	dd.addWaitingTx(tx6Node)

	// tx7Node depends on tx1Node as tx7 writes k4 while tx1 read-writes k4 -- wr dependency.
	// Further, it has a wr dependency on tx6 due to k4 and a rw dependency on tx5 due to k4.
	tx7Node := createTxNode(t, nil, [][]byte{keys[3]}, nil)
	dependsOnTx = dd.getDependenciesOf(tx7Node)
	expectedDependsOnTx = TxNodeBatch{tx6Node, tx5Node, tx1Node}
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	depDetect = newDependencyDetector()
	depDetect.addWaitingTx(tx7Node)
	dd.mergeWaitingTx(depDetect)

	// tx8Node depends on all previous transactions.
	tx8Node := createTxNode(t, [][]byte{keys[3]}, [][]byte{keys[0], keys[2]}, [][]byte{keys[5]})
	dependsOnTx = dd.getDependenciesOf(tx8Node)

	expectedDependsOnTx = TxNodeBatch{
		tx7Node,
		tx6Node,
		tx5Node,
		tx4Node,
		tx3Node,
		tx2Node,
		tx1Node,
	}
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	dd.addWaitingTx(tx8Node)

	// remove 4 transactions from the dependency detector.
	dd.removeWaitingTx(TxNodeBatch{tx1Node})
	dd.removeWaitingTx(TxNodeBatch{tx2Node})
	dd.removeWaitingTx(TxNodeBatch{tx3Node})
	dd.removeWaitingTx(TxNodeBatch{tx4Node})

	// tx9Node would have been dependent on all previous transactions if they were not removed.
	// As we have removed tx1 to tx4, tx9Node should only be dependent on tx5, tx6, tx7, and tx8.
	tx9Node := createTxNode(t, [][]byte{keys[3]}, [][]byte{keys[0], keys[2]}, [][]byte{keys[5]})
	dependsOnTx = dd.getDependenciesOf(tx9Node)
	expectedDependsOnTx = TxNodeBatch{tx8Node, tx7Node, tx6Node, tx5Node}
	require.ElementsMatch(t, expectedDependsOnTx, dependsOnTx)

	dd.addWaitingTx(tx9Node)

	// remove all remaining transactions from the dependency detector.
	dd.removeWaitingTx(TxNodeBatch{tx5Node})
	dd.removeWaitingTx(TxNodeBatch{tx6Node})
	dd.removeWaitingTx(TxNodeBatch{tx7Node})
	dd.removeWaitingTx(TxNodeBatch{tx8Node})
	dd.removeWaitingTx(TxNodeBatch{tx9Node})

	// tx10Node would have been dependent on all previous transactions if they were not removed.
	// As we have removed tx1 to tx9, tx9Node should not be dependent on any transaction.
	tx10Node := createTxNode(t, [][]byte{keys[3]}, [][]byte{keys[0], keys[2]}, [][]byte{keys[5]})
	dependsOnTx = dd.getDependenciesOf(tx10Node)
	require.Empty(t, dependsOnTx)
}
