/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	promgo "github.com/prometheus/client_model/go"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
)

type (
	// PerfMetrics is a struct that contains the metrics for the block generator.
	PerfMetrics struct {
		*monitoring.Provider

		blockSentTotal            prometheus.Counter
		blockReceivedTotal        prometheus.Counter
		transactionSentTotal      prometheus.Counter
		transactionReceivedTotal  prometheus.Counter
		transactionCommittedTotal prometheus.Counter
		transactionAbortedTotal   prometheus.Counter

		latencyTracker *latencyReceiverSender
	}

	// MetricState is a collection of the current values of the metrics.
	MetricState struct {
		BlocksSent            uint64
		BlocksReceived        uint64
		TransactionsSent      uint64
		TransactionsReceived  uint64
		TransactionsCommitted uint64
		TransactionsAborted   uint64
	}

	// TxStatus is used to report a batch item.
	TxStatus struct {
		TxID   string
		Status protoblocktx.Status
	}
)

// NewLoadgenServiceMetrics creates a new PerfMetrics instance.
func NewLoadgenServiceMetrics(c *Config) *PerfMetrics {
	p := monitoring.NewProvider()
	buckets := c.Latency.BucketConfig.Buckets()
	sampler := &c.Latency.SamplerConfig
	return &PerfMetrics{
		Provider: p,
		blockSentTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "loadgen",
			Name:      "block_sent_total",
			Help:      "Total number of blocks sent by the block generator",
		}),
		blockReceivedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "loadgen",
			Name:      "block_received_total",
			Help:      "Total number of blocks received by the block generator",
		}),
		transactionSentTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "loadgen",
			Name:      "transaction_sent_total",
			Help:      "Total number of transactions sent by the block generator",
		}),
		transactionReceivedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "loadgen",
			Name:      "transaction_received_total",
			Help:      "Total number of transactions received by the block generator",
		}),
		transactionCommittedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "loadgen",
			Name:      "transaction_committed_total",
			Help:      "Total number of transaction commit statuses received by the block generator",
		}),
		transactionAbortedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "loadgen",
			Name:      "transaction_aborted_total",
			Help:      "Total number of transaction abort statuses received by the block generator",
		}),
		latencyTracker: &latencyReceiverSender{
			validLatency: p.NewHistogram(prometheus.HistogramOpts{
				Namespace: "loadgen",
				Name:      "valid_transaction_latency_seconds",
				Help:      "Latency of transactions in seconds",
				Buckets:   buckets,
			}),
			invalidLatency: p.NewHistogram(prometheus.HistogramOpts{
				Namespace: "loadgen",
				Name:      "invalid_transaction_latency_seconds",
				Help:      "Latency of invalid transactions in seconds",
				Buckets:   buckets,
			}),
			blockSampler: sampler.BlockSampler(),
			txSampler:    sampler.TxSampler(),
		},
	}
}

// GetState returns the number of committed transactions.
func (c *PerfMetrics) GetState() MetricState {
	return MetricState{
		BlocksSent:            getCounterValue(c.blockSentTotal),
		BlocksReceived:        getCounterValue(c.blockReceivedTotal),
		TransactionsSent:      getCounterValue(c.transactionSentTotal),
		TransactionsReceived:  getCounterValue(c.transactionReceivedTotal),
		TransactionsCommitted: getCounterValue(c.transactionCommittedTotal),
		TransactionsAborted:   getCounterValue(c.transactionAbortedTotal),
	}
}

func getCounterValue(c prometheus.Counter) uint64 {
	gm := promgo.Metric{}
	if err := c.Write(&gm); err != nil {
		logger.Infof("Failed reading counter value: %v", err)
		return 0
	}
	return uint64(gm.Counter.GetValue())
}

// OnSendBlock is a function that increments the block sent total and calls the latency tracker.
func (c *PerfMetrics) OnSendBlock(block *protocoordinatorservice.Block) {
	promutil.AddToCounter(c.blockSentTotal, 1)
	promutil.AddToCounter(c.transactionSentTotal, len(block.Txs))
	c.latencyTracker.onSendBlock(block)
}

// OnSendTransaction is a function that increments the transaction sent total and calls the latency tracker.
func (c *PerfMetrics) OnSendTransaction(txID string) {
	promutil.AddToCounter(c.transactionSentTotal, 1)
	c.latencyTracker.onSendTransaction(txID)
}

// OnReceiveBatch increments the transaction received total and calls the latency tracker.
func (c *PerfMetrics) OnReceiveBatch(batch []TxStatus) {
	if len(batch) == 0 {
		return
	}
	promutil.AddToCounter(c.blockReceivedTotal, 1)
	promutil.AddToCounter(c.transactionReceivedTotal, len(batch))
	successCount := 0
	for _, b := range batch {
		success := b.Status == protoblocktx.Status_COMMITTED
		if success {
			successCount++
		}
		c.latencyTracker.onReceiveTransaction(b.TxID, success)
	}
	promutil.AddToCounter(c.transactionCommittedTotal, successCount)
	promutil.AddToCounter(c.transactionAbortedTotal, len(batch)-successCount)
}
