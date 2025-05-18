/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
)

var nsID1ForTest = "1"

func TestTransactionNode(t *testing.T) {
	t.Parallel()

	keys := makeTestKeys(t, 7)

	tx1Node := createTxNode(
		t,
		[][]byte{keys[0], keys[1]}, // readsOnly
		[][]byte{keys[2], keys[3]}, // readWrites
		[][]byte{keys[4], keys[5]}, // blindWrites
	)

	tx2Node := createTxNode(
		t,
		[][]byte{keys[2]},          // readsOnly
		[][]byte{keys[0]},          // readWrites
		[][]byte{keys[4], keys[6]}, // blindWrites
	)

	tx2DependsOnTx := TxNodeBatch{
		tx1Node,
	}
	tx2Node.addDependenciesAndUpdateDependents(tx2DependsOnTx)
	require.False(t, tx2Node.isDependencyFree())
	require.Equal(t, tx2DependsOnTx, tx2Node.dependsOnTxs)
	checkDependentTxs(
		t,
		TxNodeBatch{ // expectedDependentTxs
			tx2Node,
		},
		&tx1Node.dependentTxs, // actualDependentTxs
	)

	tx3Node := createTxNode(
		t,
		[][]byte{keys[5]}, // readsOnly
		[][]byte{keys[3]}, // readWrites
		[][]byte{keys[6]}, // blindWrites
	)

	tx3DependsOnTx := TxNodeBatch{
		tx1Node,
		tx2Node,
	}
	tx3Node.addDependenciesAndUpdateDependents(tx3DependsOnTx)
	require.False(t, tx2Node.isDependencyFree())
	require.Equal(t, tx3DependsOnTx, tx3Node.dependsOnTxs)
	checkDependentTxs(
		t,
		TxNodeBatch{ // expectedDependentTxs
			tx2Node,
			tx3Node,
		},
		&tx1Node.dependentTxs, // actualDependentTxs
	)
	checkDependentTxs(
		t,
		TxNodeBatch{ // expectedDependentTxs
			tx3Node,
		},
		&tx2Node.dependentTxs, // actualDependentTxs
	)

	freedTxs := tx1Node.freeDependents()
	require.Equal(t, TxNodeBatch{tx2Node}, freedTxs)
	require.Empty(t, tx2Node.dependsOnTxs)
}

func createTxNode(t *testing.T, readOnly, readWrite, blindWrite [][]byte) *TransactionNode {
	t.Helper()
	tx := createTxForTest(t, nsID1ForTest, readOnly, readWrite, blindWrite)
	txNode := newTransactionNode(0, 0, tx)

	expectedReads := make([]string, 0, len(readOnly))
	expectedWrites := make([]string, 0, len(blindWrite))
	expectedReadsAndWrites := make([]string, 0, len(readWrite))

	nsID := tx.Namespaces[0].NsId

	for _, k := range readOnly {
		expectedReads = append(expectedReads, constructCompositeKey(nsID, k))
	}
	expectedReads = append(
		expectedReads,
		constructCompositeKey(types.MetaNamespaceID, []byte(nsID)),
	)

	for _, k := range readWrite {
		expectedReadsAndWrites = append(expectedReadsAndWrites, constructCompositeKey(nsID, k))
	}

	for _, k := range blindWrite {
		expectedWrites = append(expectedWrites, constructCompositeKey(nsID, k))
	}

	checkNewTxNode(
		t,
		tx,
		&readWriteKeys{
			expectedReads,
			expectedWrites,
			expectedReadsAndWrites,
		},
		txNode,
	)

	return txNode
}

func createTxForTest( //nolint: revive
	_ *testing.T, nsID string, readOnly, readWrite, blindWrite [][]byte,
) *protoblocktx.Tx {
	reads := make([]*protoblocktx.Read, len(readOnly))
	for i, k := range readOnly {
		reads[i] = &protoblocktx.Read{Key: k}
	}

	readWrites := make([]*protoblocktx.ReadWrite, len(readWrite))
	for i, k := range readWrite {
		readWrites[i] = &protoblocktx.ReadWrite{Key: k}
	}

	blindWrites := make([]*protoblocktx.Write, len(blindWrite))
	for i, k := range blindWrite {
		blindWrites[i] = &protoblocktx.Write{Key: k}
	}

	return &protoblocktx.Tx{
		Id: uuid.New().String(),
		Namespaces: []*protoblocktx.TxNamespace{
			{
				NsId:        nsID,
				ReadsOnly:   reads,
				ReadWrites:  readWrites,
				BlindWrites: blindWrites,
			},
		},
	}
}

func checkNewTxNode(
	t *testing.T,
	tx *protoblocktx.Tx,
	readsWrites *readWriteKeys,
	txNode *TransactionNode,
) {
	t.Helper()
	require.Equal(t, tx.Id, txNode.Tx.ID)
	require.Equal(t, tx.Namespaces, txNode.Tx.Namespaces)
	require.True(t, txNode.isDependencyFree())
	require.ElementsMatch(t, readsWrites.readsOnly, txNode.rwKeys.readsOnly)
	require.ElementsMatch(t, readsWrites.writesOnly, txNode.rwKeys.writesOnly)
	require.Equal(t, 0, txNode.dependentTxs.Count())
}

func checkDependentTxs(
	t *testing.T, expectedTransactionList TxNodeBatch, dependentTxs *utils.SyncMap[*TransactionNode, any],
) {
	t.Helper()
	actualTransactionList := slices.Collect(dependentTxs.IterKeys())
	require.Len(t, expectedTransactionList, len(actualTransactionList))
	require.ElementsMatch(t, expectedTransactionList, actualTransactionList)
}
