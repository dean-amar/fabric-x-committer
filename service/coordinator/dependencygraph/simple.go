/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"context"
	"sync"

	"github.com/hyperledger/fabric-x-committer/utils/channel"
)

type (
	// SimpleManager is the simpler version of the dependency graph module.
	// It uses only 3 go routines, and a single map.
	SimpleManager struct {
		in              <-chan *TransactionBatch
		out             chan<- TxNodeBatch
		val             <-chan TxNodeBatch
		taskQueue       chan task
		keyToWaitingTXs map[string]*waiting
	}

	task struct {
		txs       []*TransactionNode
		validated []*waiting
	}

	waiting struct {
		key   string
		queue []*waiterGroup
	}

	waiterGroup struct {
		group     []*TransactionNode
		doneCount int
		writer    bool
	}
)

// NewSimpleManager create a simple dependency graph manager.
func NewSimpleManager(c *Config) *SimpleManager {
	return &SimpleManager{
		in:              c.IncomingTxs,
		out:             c.OutgoingDepFreeTxsNode,
		val:             c.IncomingValidatedTxsNode,
		taskQueue:       make(chan task, cap(c.IncomingTxs)),
		keyToWaitingTXs: make(map[string]*waiting),
	}
}

// Run starts the dependency graph manager.
func (m *SimpleManager) Run(ctx context.Context) {
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		defer wg.Done()
		m.txInToTask(ctx)
	}()
	go func() {
		defer wg.Done()
		m.validatedInToTask(ctx)
	}()
	go func() {
		defer wg.Done()
		m.taskProcessing(ctx)
	}()
	wg.Wait()
}

// txInToTask -- in (TransactionBatch) -> taskQueue (TxNodeBatch).
func (m *SimpleManager) txInToTask(ctx context.Context) {
	in := channel.NewReader(ctx, m.in)
	taskQueue := channel.NewWriter(ctx, m.taskQueue)
	for ctx.Err() == nil {
		batch, ok := in.Read()
		if !ok {
			return
		}

		depTX := make([]*TransactionNode, len(batch.Txs))
		for i, tx := range batch.Txs {
			node := newTransactionNode(batch.BlockNumber, batch.TxsNum[i], tx)
			node.waitingKeys = make([]*waiting, 0, node.rwKeys.size())
			depTX[i] = node
		}
		taskQueue.Write(task{txs: depTX})
	}
}

// validatedInToTask -- val (TxNodeBatch) -> taskQueue (keys).
func (m *SimpleManager) validatedInToTask(ctx context.Context) {
	val := channel.NewReader(ctx, m.val)
	taskQueue := channel.NewWriter(ctx, m.taskQueue)
	for ctx.Err() == nil {
		batch, ok := val.Read()
		if !ok {
			return
		}

		var ws []*waiting
		for _, node := range batch {
			ws = append(ws, node.waitingKeys...)
		}
		if len(ws) > 0 {
			taskQueue.Write(task{validated: ws})
		}
	}
}

// taskProcessing -- taskQueue (TxNodeBatch/keys) -> out (TxNodeBatch).
func (m *SimpleManager) taskProcessing(ctx context.Context) {
	taskQueue := channel.NewReader(ctx, m.taskQueue)
	out := channel.NewWriter(ctx, m.out)
	for ctx.Err() == nil {
		t, ok := taskQueue.Read()
		if !ok {
			return
		}

		var depFree TxNodeBatch
		if len(t.txs) > 0 {
			depFree = m.processBatch(t.txs)
		} else if len(t.validated) > 0 {
			depFree = m.processValidatedKeys(t.validated)
		}
		if len(depFree) > 0 {
			out.Write(depFree)
		}
	}
}

func (m *SimpleManager) processBatch(batch []*TransactionNode) TxNodeBatch {
	depFree := make(TxNodeBatch, 0, len(batch))
	for _, depTX := range batch {
		// With writes.
		for _, rw := range [][]string{depTX.rwKeys.readsAndWrites, depTX.rwKeys.writesOnly} {
			for _, k := range rw {
				m.checkTXFree(depTX, k, true)
			}
		}
		// Read only.
		for _, k := range depTX.rwKeys.readsOnly {
			m.checkTXFree(depTX, k, false)
		}

		if depTX.waitForKeysCount == 0 {
			depFree = append(depFree, depTX)
		}
	}
	return depFree
}

func (m *SimpleManager) processValidatedKeys(ws []*waiting) TxNodeBatch {
	depFree := make(TxNodeBatch, 0, len(ws))
	for _, w := range ws {
		depFree = m.appendFree(w, depFree)
	}
	return depFree
}

// checkTXFree check there are active TXs that are using a key, and if so, it adds the TX to thw wait queue.
//
//nolint:revive // false positive: control flag.
func (m *SimpleManager) checkTXFree(tx *TransactionNode, k string, writer bool) {
	w, loaded := m.keyToWaitingTXs[k]
	if loaded {
		if w.add(tx, writer) {
			tx.waitForKeysCount++
		}
	} else {
		w = &waiting{
			key:   k,
			queue: []*waiterGroup{{writer: writer, group: []*TransactionNode{tx}}},
		}
		m.keyToWaitingTXs[k] = w
	}
	tx.waitingKeys = append(tx.waitingKeys, w)
}

// appendFree indicate a key processing item is done, and appends free nodes if applicable.
func (m *SimpleManager) appendFree(w *waiting, out TxNodeBatch) TxNodeBatch {
	nextWaiters, noMoreWait := w.popAndGetNext()
	if noMoreWait {
		delete(m.keyToWaitingTXs, w.key)
		return out
	}

	for _, txWait := range nextWaiters {
		txWait.waitForKeysCount--
		if txWait.waitForKeysCount == 0 {
			out = append(out, txWait)
		}
	}
	return out
}

// add append to the waiting queue.
// returns true if the wait is needed.
func (w *waiting) add(tx *TransactionNode, writer bool) bool { //nolint:revive // false positive: control flag.
	sz := len(w.queue)

	// When there are no other items, or the previous item or this item is a writer,
	// we should add a new group.
	if sz == 0 || writer || w.queue[sz-1].writer {
		w.queue = append(w.queue, &waiterGroup{group: []*TransactionNode{tx}, writer: writer})
		// We can return true if the item is not the first in the queue.
		return sz != 0
	}

	// In this case, the latest group are readers and this item is also a reader.
	// We can append this reader.
	lastQueue := w.queue[sz-1]
	lastQueue.group = append(lastQueue.group, tx)
	// We can return true if the reader group is not the first one.
	return sz != 1
}

// popAndGetNext removes a TX from the waiters.
// Returns the next waiter group to release.
// Returns true if no other TX is waiting.
func (w *waiting) popAndGetNext() ([]*TransactionNode, bool) {
	prev := w.queue[0]
	prev.doneCount++
	if prev.doneCount < len(prev.group) {
		return nil, false
	}

	w.queue = w.queue[1:]
	if len(w.queue) == 0 {
		return nil, true
	}
	return w.queue[0].group, false
}
