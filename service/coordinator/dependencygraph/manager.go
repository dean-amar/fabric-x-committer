/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring/promutil"
)

type (
	// Manager is the main component of the dependency graph module.
	// It is responsible for managing the local dependency constructor
	// and the global dependency manager.
	Manager struct {
		localDepConstructor         *localDependencyConstructor
		globalDepManager            *globalDependencyManager
		config                      *Config
		outgoingTxsNodeWithLocalDep chan *transactionNodeBatch
		metrics                     *perfMetrics
	}

	// Config holds the configuration for the dependency graph manager.
	Config struct {
		// IncomingTxs is the channel for dependency manager to receive
		// incoming transactions.
		IncomingTxs <-chan *TransactionBatch
		// OutgoingDepFreeTxsNode is the channel dependency manager to send
		// dependency free transactions for validation and commit.
		OutgoingDepFreeTxsNode chan<- TxNodeBatch
		// IncomingValidatedTxsNode is the channel for dependency manager
		// to receive validated transactions.
		IncomingValidatedTxsNode <-chan TxNodeBatch
		// NumOfLocalDepConstructors defines the number of local
		// dependency constructors.
		NumOfLocalDepConstructors int
		// WaitingTxsLimit defines the maximum number of transactions
		// that can be waiting at the dependency manager.
		WaitingTxsLimit int
		// PrometheusMetricsProvider is the provider for Prometheus metrics.
		PrometheusMetricsProvider *monitoring.Provider
	}
)

// NewManager creates a new dependency graph manager.
func NewManager(c *Config) *Manager {
	metrics := newPerformanceMetrics(c.PrometheusMetricsProvider)

	outgoingTxsNodeWithLocalDep := make(chan *transactionNodeBatch, cap(c.IncomingTxs))
	ldp := newLocalDependencyConstructor(c.IncomingTxs, outgoingTxsNodeWithLocalDep, metrics)

	gdConf := &globalDepConfig{
		incomingTxsNode:        outgoingTxsNodeWithLocalDep,
		outgoingDepFreeTxsNode: c.OutgoingDepFreeTxsNode,
		validatedTxsNode:       c.IncomingValidatedTxsNode,
		waitingTxsLimit:        c.WaitingTxsLimit,
		metrics:                metrics,
	}

	gdp := newGlobalDependencyManager(gdConf)

	return &Manager{
		localDepConstructor:         ldp,
		globalDepManager:            gdp,
		config:                      c,
		outgoingTxsNodeWithLocalDep: outgoingTxsNodeWithLocalDep,
		metrics:                     metrics,
	}
}

// Run starts the dependency graph manager by starting the
// local dependency constructors and global dependency graph manager.
func (m *Manager) Run(ctx context.Context) {
	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		m.monitorQueues(gCtx)
		return nil
	})

	g.Go(func() error {
		m.localDepConstructor.run(gCtx, m.config.NumOfLocalDepConstructors)
		return nil
	})

	g.Go(func() error {
		m.globalDepManager.run(gCtx)
		return nil
	})

	_ = g.Wait()
}

func (m *Manager) monitorQueues(ctx context.Context) {
	// TODO: make sampling time configurable
	ticker := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		promutil.SetGauge(m.metrics.ldgInputTxBatchQueueSize, len(m.localDepConstructor.incomingTransactions))
		promutil.SetGauge(m.metrics.gdgInputTxBatchQueueSize, len(m.globalDepManager.incomingTransactionsNode))
	}
}
