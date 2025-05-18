/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protovcservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

type prepareTestEnv struct {
	preparer    *transactionPreparer
	txBatch     chan *protovcservice.TransactionBatch
	preparedTxs chan *preparedTransactions
}

func newPrepareTestEnv(t *testing.T) *prepareTestEnv {
	t.Helper()
	txBatch := make(chan *protovcservice.TransactionBatch, 10)
	preparedTxs := make(chan *preparedTransactions, 10)
	metrics := newVCServiceMetrics()
	p := newPreparer(txBatch, preparedTxs, metrics)
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return p.run(ctx, 1)
	}, nil)

	return &prepareTestEnv{
		preparer:    p,
		txBatch:     txBatch,
		preparedTxs: preparedTxs,
	}
}

func TestPrepareTxWithReadsOnly(t *testing.T) {
	t.Parallel()

	env := newPrepareTestEnv(t)

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")
	k6 := []byte("key6")

	tx := &protovcservice.TransactionBatch{
		Transactions: []*protovcservice.Transaction{
			{
				ID: "tx1",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v1,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k1, Version: v1},
							{Key: k2, Version: v1},
							{Key: k3, Version: nil},
						},
					},
					{
						NsId:      "2",
						NsVersion: v1,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k4, Version: v0},
							{Key: k5, Version: nil},
						},
					},
				},
				BlockNumber: 1,
				TxNum:       1,
			},
			{
				ID: "tx2",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v1,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k1, Version: v1},
							{Key: k4, Version: v1},
							{Key: k5, Version: nil},
						},
					},
					{
						NsId:      "2",
						NsVersion: v1,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k4, Version: v1},
							{Key: k5, Version: v0},
							{Key: k6, Version: nil},
						},
					},
				},
				BlockNumber: 4,
				TxNum:       2,
			},
		},
	}

	expectedPreparedTxs := &preparedTransactions{
		nsToReads: namespaceToReads{
			"1": &reads{
				keys:     [][]byte{k1, k2, k3, k4, k5},
				versions: [][]byte{v1, v1, nil, v1, nil},
			},
			"2": &reads{
				keys:     [][]byte{k4, k5, k4, k5, k6},
				versions: [][]byte{v0, nil, v1, v0, nil},
			},
			types.MetaNamespaceID: &reads{
				keys:     [][]byte{[]byte("1"), []byte("2")},
				versions: [][]byte{v1, v1},
			},
		},
		readToTxIDs: readToTransactions{
			comparableRead{"1", string(k1), string(v1)}: []TxID{
				"tx1", "tx2",
			},
			comparableRead{"1", string(k2), string(v1)}: []TxID{"tx1"},
			comparableRead{"1", string(k3), ""}:         []TxID{"tx1"},
			comparableRead{"1", string(k4), string(v1)}: []TxID{"tx2"},
			comparableRead{"1", string(k5), ""}:         []TxID{"tx2"},
			comparableRead{"2", string(k4), string(v0)}: []TxID{"tx1"},
			comparableRead{"2", string(k5), ""}:         []TxID{"tx1"},
			comparableRead{"2", string(k4), string(v1)}: []TxID{"tx2"},
			comparableRead{"2", string(k5), string(v0)}: []TxID{"tx2"},
			comparableRead{"2", string(k6), ""}:         []TxID{"tx2"},
			comparableRead{types.MetaNamespaceID, "1", string(v1)}: []TxID{
				"tx1", "tx2",
			},
			comparableRead{types.MetaNamespaceID, "2", string(v1)}: []TxID{
				"tx1", "tx2",
			},
		},
		txIDToNsNonBlindWrites: transactionToWrites{},
		txIDToNsBlindWrites:    transactionToWrites{},
		txIDToNsNewWrites:      transactionToWrites{},
		invalidTxIDStatus:      make(map[TxID]protoblocktx.Status),
		txIDToHeight: transactionIDToHeight{
			"tx1": types.NewHeight(1, 1),
			"tx2": types.NewHeight(4, 2),
		},
	}

	env.txBatch <- tx
	preparedTxs := <-env.preparedTxs
	ensurePreparedTx(t, expectedPreparedTxs, preparedTxs)
}

func TestPrepareTxWithBlindWritesOnly(t *testing.T) {
	t.Parallel()

	env := newPrepareTestEnv(t)

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")

	v2 := types.VersionNumber(2).Bytes()

	tx := &protovcservice.TransactionBatch{
		Transactions: []*protovcservice.Transaction{
			{
				ID: "tx1",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v1,
						BlindWrites: []*protoblocktx.Write{
							{Key: k1, Value: []byte("1")},
							{Key: k2, Value: []byte("1")},
							{Key: k3, Value: nil},
						},
					},
					{
						NsId:      "2",
						NsVersion: v1,
						BlindWrites: []*protoblocktx.Write{{
							Key:   k1,
							Value: []byte("5"),
						}},
					},
				},
				BlockNumber: 10,
				TxNum:       5,
			},
			{
				ID: "tx2",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v2,
						BlindWrites: []*protoblocktx.Write{
							{Key: k4, Value: []byte("1")},
							{Key: k5, Value: nil},
						},
					},
				},
				BlockNumber: 6,
				TxNum:       3,
			},
		},
	}

	expectedPreparedTxs := &preparedTransactions{
		nsToReads: namespaceToReads{
			types.MetaNamespaceID: &reads{
				keys: [][]byte{
					[]byte("1"), []byte("2"), []byte("1"),
				},
				versions: [][]byte{v1, v1, v2},
			},
		},
		readToTxIDs: readToTransactions{
			comparableRead{types.MetaNamespaceID, "1", string(v1)}: []TxID{"tx1"},
			comparableRead{types.MetaNamespaceID, "2", string(v1)}: []TxID{"tx1"},
			comparableRead{types.MetaNamespaceID, "1", string(v2)}: []TxID{"tx2"},
		},
		txIDToNsNonBlindWrites: transactionToWrites{},
		txIDToNsBlindWrites: transactionToWrites{
			"tx1": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k1, k2, k3},
					values:   [][]byte{[]byte("1"), []byte("1"), nil},
					versions: [][]byte{nil, nil, nil},
				},
				"2": &namespaceWrites{
					keys:     [][]byte{k1},
					values:   [][]byte{[]byte("5")},
					versions: [][]byte{nil},
				},
			},
			"tx2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k4, k5},
					values:   [][]byte{[]byte("1"), nil},
					versions: [][]byte{nil, nil},
				},
			},
		},
		txIDToNsNewWrites: transactionToWrites{},
		invalidTxIDStatus: make(map[TxID]protoblocktx.Status),
		txIDToHeight: transactionIDToHeight{
			"tx1": types.NewHeight(10, 5),
			"tx2": types.NewHeight(6, 3),
		},
	}

	env.txBatch <- tx
	preparedTxs := <-env.preparedTxs
	ensurePreparedTx(t, expectedPreparedTxs, preparedTxs)
}

func TestPrepareTxWithReadWritesOnly(t *testing.T) {
	t.Parallel()

	env := newPrepareTestEnv(t)

	v2 := types.VersionNumber(2).Bytes()

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")
	k6 := []byte("key6")
	k7 := []byte("key7")

	tx := &protovcservice.TransactionBatch{
		Transactions: []*protovcservice.Transaction{
			{
				ID: "tx1",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v2,
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k1, Version: v1, Value: []byte("v1")},
							{Key: k2, Version: v1, Value: []byte("v2")},
							{Key: k3, Version: nil, Value: []byte("v3")},
						},
					},
					{
						NsId:      "2",
						NsVersion: v2,
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k4, Version: v0, Value: []byte("v4")},
							{Key: k5, Version: nil, Value: []byte("v5")},
						},
					},
				},
				BlockNumber: 7,
				TxNum:       4,
			},
			{
				ID: "tx2",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v2,
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k4, Version: v1, Value: []byte("v4")},
							{Key: k5, Version: nil, Value: []byte("v5")},
						},
					},
					{
						NsId:      "2",
						NsVersion: v2,
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k6, Version: nil, Value: []byte("v6")},
							{Key: k7, Version: nil, Value: nil},
						},
					},
				},
				BlockNumber: 7,
				TxNum:       5,
			},
		},
	}

	expectedPreparedTxs := &preparedTransactions{
		nsToReads: namespaceToReads{
			"1": &reads{
				keys:     [][]byte{k1, k2, k4},
				versions: [][]byte{v1, v1, v1},
			},
			"2": &reads{
				keys:     [][]byte{k4},
				versions: [][]byte{v0},
			},
			types.MetaNamespaceID: &reads{
				keys:     [][]byte{[]byte("1"), []byte("2")},
				versions: [][]byte{v2, v2},
			},
		},
		readToTxIDs: readToTransactions{
			comparableRead{"1", string(k1), string(v1)}: []TxID{"tx1"},
			comparableRead{"1", string(k2), string(v1)}: []TxID{"tx1"},
			comparableRead{"1", string(k3), ""}:         []TxID{"tx1"},
			comparableRead{"1", string(k4), string(v1)}: []TxID{"tx2"},
			comparableRead{"1", string(k5), ""}:         []TxID{"tx2"},
			comparableRead{"2", string(k4), string(v0)}: []TxID{"tx1"},
			comparableRead{"2", string(k5), ""}:         []TxID{"tx1"},
			comparableRead{"2", string(k6), ""}:         []TxID{"tx2"},
			comparableRead{"2", string(k7), ""}:         []TxID{"tx2"},
			comparableRead{types.MetaNamespaceID, "1", string(v2)}: []TxID{
				"tx1", "tx2",
			},
			comparableRead{types.MetaNamespaceID, "2", string(v2)}: []TxID{
				"tx1", "tx2",
			},
		},
		txIDToNsNonBlindWrites: transactionToWrites{
			"tx1": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k1, k2},
					values:   [][]byte{[]byte("v1"), []byte("v2")},
					versions: [][]byte{v2, v2},
				},
				"2": &namespaceWrites{
					keys:     [][]byte{k4},
					values:   [][]byte{[]byte("v4")},
					versions: [][]byte{v1},
				},
			},
			"tx2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k4},
					values:   [][]byte{[]byte("v4")},
					versions: [][]byte{v2},
				},
			},
		},
		txIDToNsBlindWrites: transactionToWrites{},
		txIDToNsNewWrites: transactionToWrites{
			"tx1": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k3},
					values:   [][]byte{[]byte("v3")},
					versions: [][]byte{nil},
				},
				"2": &namespaceWrites{
					keys:     [][]byte{k5},
					values:   [][]byte{[]byte("v5")},
					versions: [][]byte{nil},
				},
			},
			"tx2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k5},
					values:   [][]byte{[]byte("v5")},
					versions: [][]byte{nil},
				},
				"2": &namespaceWrites{
					keys:     [][]byte{k6, k7},
					values:   [][]byte{[]byte("v6"), nil},
					versions: [][]byte{nil, nil},
				},
			},
		},
		invalidTxIDStatus: make(map[TxID]protoblocktx.Status),
		txIDToHeight: transactionIDToHeight{
			"tx1": types.NewHeight(7, 4),
			"tx2": types.NewHeight(7, 5),
		},
	}

	env.txBatch <- tx
	preparedTxs := <-env.preparedTxs
	ensurePreparedTx(t, expectedPreparedTxs, preparedTxs)
}

func TestPrepareTx(t *testing.T) { //nolint:maintidx // cannot improve.
	t.Parallel()

	env := newPrepareTestEnv(t)

	v2 := types.VersionNumber(2).Bytes()
	v3 := types.VersionNumber(3).Bytes()
	v4 := types.VersionNumber(4).Bytes()
	v8 := types.VersionNumber(8).Bytes()
	v9 := types.VersionNumber(9).Bytes()
	v10 := types.VersionNumber(10).Bytes()

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")
	k6 := []byte("key6")
	k7 := []byte("key7")
	k8 := []byte("key8")
	k9 := []byte("key9")
	k10 := []byte("key10")

	tx := &protovcservice.TransactionBatch{
		Transactions: []*protovcservice.Transaction{
			{
				ID: "tx1",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v1,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k1, Version: v1},
							{Key: k2, Version: v2},
						},
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k3, Version: v3, Value: []byte("v3")},
						},
						BlindWrites: []*protoblocktx.Write{
							{Key: k4, Value: []byte("v4")},
						},
					},
					{
						NsId:      "2",
						NsVersion: v2,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k5, Version: nil},
						},
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k6, Version: nil, Value: []byte("v6")},
						},
						BlindWrites: []*protoblocktx.Write{
							{Key: k7, Value: []byte("v7")},
						},
					},
				},
				BlockNumber: 8,
				TxNum:       0,
			},
			{
				ID: "tx2",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v3,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k8, Version: v8},
						},
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k9, Version: v9, Value: []byte("v9")},
						},
						BlindWrites: []*protoblocktx.Write{
							{Key: k10, Value: []byte("v10")},
						},
					},
				},
				BlockNumber: 9,
				TxNum:       3,
			},
			{
				// We ensure no duplicate reads with duplicated TX.
				ID: "tx2.2",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      "1",
						NsVersion: v3,
						ReadsOnly: []*protoblocktx.Read{
							{Key: k8, Version: v8},
						},
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: k9, Version: v9, Value: []byte("v9")},
						},
						BlindWrites: []*protoblocktx.Write{
							{Key: k10, Value: []byte("v10")},
						},
					},
				},
				BlockNumber: 9,
				TxNum:       4,
			},
			{
				ID: "tx3",
				PrelimInvalidTxStatus: &protovcservice.InvalidTxStatus{
					Code: protoblocktx.Status_ABORTED_NO_WRITES,
				},
				BlockNumber: 6,
				TxNum:       2,
			},
			{
				ID: "tx4",
				PrelimInvalidTxStatus: &protovcservice.InvalidTxStatus{
					Code: protoblocktx.Status_ABORTED_DUPLICATE_NAMESPACE,
				},
				BlockNumber: 5,
				TxNum:       2,
			},
			{
				ID: "tx5",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId:      types.MetaNamespaceID,
						NsVersion: v4,
						ReadWrites: []*protoblocktx.ReadWrite{
							{Key: []byte("1"), Version: v1, Value: []byte("meta")},
						},
					},
				},
				BlockNumber: 6,
				TxNum:       2,
			},
			{
				ID: "tx6",
				Namespaces: []*protoblocktx.TxNamespace{
					{
						NsId: types.ConfigNamespaceID,
						BlindWrites: []*protoblocktx.Write{
							{Key: []byte(types.ConfigKey), Value: []byte("config")},
						},
					},
				},
				BlockNumber: 6,
				TxNum:       2,
			},
		},
	}

	expectedPreparedTxs := &preparedTransactions{
		nsToReads: namespaceToReads{
			"1": &reads{
				keys:     [][]byte{k1, k2, k3, k8, k9},
				versions: [][]byte{v1, v2, v3, v8, v9},
			},
			"2": &reads{
				keys:     [][]byte{k5},
				versions: [][]byte{nil},
			},
			types.MetaNamespaceID: &reads{
				keys: [][]byte{
					[]byte("1"), []byte("2"), []byte("1"),
				},
				versions: [][]byte{v1, v2, v3},
			},
			types.ConfigNamespaceID: &reads{
				keys:     [][]byte{[]byte(types.ConfigKey)},
				versions: [][]byte{v4},
			},
		},
		readToTxIDs: readToTransactions{
			comparableRead{"1", string(k1), string(v1)}:                          []TxID{"tx1"},
			comparableRead{"1", string(k2), string(v2)}:                          []TxID{"tx1"},
			comparableRead{"1", string(k3), string(v3)}:                          []TxID{"tx1"},
			comparableRead{"1", string(k8), string(v8)}:                          []TxID{"tx2", "tx2.2"},
			comparableRead{"1", string(k9), string(v9)}:                          []TxID{"tx2", "tx2.2"},
			comparableRead{"2", string(k5), ""}:                                  []TxID{"tx1"},
			comparableRead{"2", string(k6), ""}:                                  []TxID{"tx1"},
			comparableRead{types.MetaNamespaceID, "1", string(v1)}:               []TxID{"tx1", "tx5"},
			comparableRead{types.MetaNamespaceID, "2", string(v2)}:               []TxID{"tx1"},
			comparableRead{types.MetaNamespaceID, "1", string(v3)}:               []TxID{"tx2", "tx2.2"},
			comparableRead{types.ConfigNamespaceID, types.ConfigKey, string(v4)}: []TxID{"tx5"},
		},
		txIDToNsNonBlindWrites: transactionToWrites{
			"tx1": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k3},
					values:   [][]byte{[]byte("v3")},
					versions: [][]byte{v4},
				},
			},
			"tx2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k9},
					values:   [][]byte{[]byte("v9")},
					versions: [][]byte{v10},
				},
			},
			"tx2.2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k9},
					values:   [][]byte{[]byte("v9")},
					versions: [][]byte{v10},
				},
			},
			"tx5": namespaceToWrites{
				types.MetaNamespaceID: &namespaceWrites{
					keys:     [][]byte{[]byte("1")},
					values:   [][]byte{[]byte("meta")},
					versions: [][]byte{v2},
				},
			},
		},
		txIDToNsBlindWrites: transactionToWrites{
			"tx1": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k4},
					values:   [][]byte{[]byte("v4")},
					versions: [][]byte{nil},
				},
				"2": &namespaceWrites{
					keys:     [][]byte{k7},
					values:   [][]byte{[]byte("v7")},
					versions: [][]byte{nil},
				},
			},
			"tx2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k10},
					values:   [][]byte{[]byte("v10")},
					versions: [][]byte{nil},
				},
			},
			"tx2.2": namespaceToWrites{
				"1": &namespaceWrites{
					keys:     [][]byte{k10},
					values:   [][]byte{[]byte("v10")},
					versions: [][]byte{nil},
				},
			},
			"tx6": namespaceToWrites{
				types.ConfigNamespaceID: &namespaceWrites{
					keys:     [][]byte{[]byte(types.ConfigKey)},
					values:   [][]byte{[]byte("config")},
					versions: [][]byte{nil},
				},
			},
		},
		txIDToNsNewWrites: transactionToWrites{
			"tx1": namespaceToWrites{
				"2": &namespaceWrites{
					keys:     [][]byte{k6},
					values:   [][]byte{[]byte("v6")},
					versions: [][]byte{nil},
				},
			},
		},
		invalidTxIDStatus: map[TxID]protoblocktx.Status{
			"tx3": protoblocktx.Status_ABORTED_NO_WRITES,
			"tx4": protoblocktx.Status_ABORTED_DUPLICATE_NAMESPACE,
		},
		txIDToHeight: transactionIDToHeight{
			"tx1":   types.NewHeight(8, 0),
			"tx2":   types.NewHeight(9, 3),
			"tx2.2": types.NewHeight(9, 4),
			"tx3":   types.NewHeight(6, 2),
			"tx4":   types.NewHeight(5, 2),
		},
	}

	env.txBatch <- tx
	preparedTxs := <-env.preparedTxs
	ensurePreparedTx(t, expectedPreparedTxs, preparedTxs)
}

func ensurePreparedTx(t *testing.T, expectedPreparedTxs, actualPreparedTxs *preparedTransactions) {
	t.Helper()
	require.Equal(t, expectedPreparedTxs.nsToReads, actualPreparedTxs.nsToReads)
	requireEqualMapOfLists(t, expectedPreparedTxs.readToTxIDs, actualPreparedTxs.readToTxIDs)
	require.Equal(t, expectedPreparedTxs.txIDToNsNonBlindWrites, actualPreparedTxs.txIDToNsNonBlindWrites)
	require.Equal(t, expectedPreparedTxs.txIDToNsBlindWrites, actualPreparedTxs.txIDToNsBlindWrites)
	require.Equal(t, expectedPreparedTxs.txIDToNsNewWrites, actualPreparedTxs.txIDToNsNewWrites)
	require.Equal(t, expectedPreparedTxs.invalidTxIDStatus, actualPreparedTxs.invalidTxIDStatus)
}

func requireEqualMapOfLists[K comparable, V any](t *testing.T, expected, actual map[K][]V) {
	t.Helper()
	for k, expectedV := range expected {
		actualV, ok := actual[k]
		require.True(t, ok, k)
		require.ElementsMatch(t, expectedV, actualV, k)
	}
}
