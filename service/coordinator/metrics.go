/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package coordinator

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
)

type perfMetrics struct {
	*monitoring.Provider

	// received and processed transactions
	transactionReceivedTotal                   prometheus.Counter
	transactionCommittedStatusSentTotal        prometheus.Counter
	transactionMVCCConflictStatusSentTotal     prometheus.Counter
	transactionInvalidSignatureStatusSentTotal prometheus.Counter
	transactionDuplicateTxStatusSentTotal      prometheus.Counter

	// queue sizes
	sigverifierInputTxBatchQueueSize           prometheus.Gauge
	sigverifierOutputValidatedTxBatchQueueSize prometheus.Gauge
	vcserviceOutputTxStatusBatchQueueSize      prometheus.Gauge
	vcserviceOutputValidatedTxBatchQueueSize   prometheus.Gauge

	// processed transactions by each manager
	sigverifierTransactionProcessedTotal prometheus.Counter
	vcserviceTransactionProcessedTotal   prometheus.Counter

	// connection failure
	verifiersConnection               *monitoring.ConnectionMetrics
	verifiersRetriedTransactionTotal  prometheus.Counter
	vcservicesConnection              *monitoring.ConnectionMetrics
	vcservicesRetriedTransactionTotal prometheus.Counter
}

func newPerformanceMetrics() *perfMetrics {
	p := monitoring.NewProvider()

	return &perfMetrics{
		Provider: p,
		transactionReceivedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "grpc",
			Name:      "received_transaction_total",
			Help:      "Total number of transactions received by the coordinator service from the client.",
		}),
		transactionCommittedStatusSentTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "grpc",
			Name:      "sent_transaction_committed_status_total",
			Help:      "Total number of transactions committed status sent by the coordinator service to the client.",
		}),
		transactionMVCCConflictStatusSentTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "grpc",
			Name:      "sent_transaction_mvcc_conflict_status_total",
			Help: "Total number of transactions mvcc conflict status sent by" +
				" the coordinator service to the client.",
		}),
		transactionInvalidSignatureStatusSentTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "grpc",
			Name:      "sent_transaction_invalid_signature_status_total",
			Help: "Total number of transactions invalid signature status sent by" +
				" the coordinator service to the client.",
		}),
		transactionDuplicateTxStatusSentTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "grpc",
			Name:      "sent_transaction_duplicate_tx_status_total",
			Help: "Total number of transactions duplicate tx status sent by the" +
				" coordinator service to the client.",
		}),
		sigverifierInputTxBatchQueueSize: p.NewGauge(prometheus.GaugeOpts{
			Namespace: "coordinator",
			Subsystem: "sigverifier",
			Name:      "input_tx_batch_queue_size",
			Help:      "Size of the input transaction batch queue of the signature verifier manager.",
		}),
		sigverifierOutputValidatedTxBatchQueueSize: p.NewGauge(prometheus.GaugeOpts{
			Namespace: "coordinator",
			Subsystem: "sigverifier",
			Name:      "output_validated_tx_batch_queue_size",
			Help:      "Size of the output validated transaction batch queue of the signature verifier manager.",
		}),
		vcserviceOutputTxStatusBatchQueueSize: p.NewGauge(prometheus.GaugeOpts{
			Namespace: "coordinator",
			Subsystem: "vcservice",
			Name:      "output_tx_status_batch_queue_size",
			Help: "Size of the output transaction status batch queue of " +
				"the validation and committer service manager.",
		}),
		vcserviceOutputValidatedTxBatchQueueSize: p.NewGauge(prometheus.GaugeOpts{
			Namespace: "coordinator",
			Subsystem: "vcservice",
			Name:      "output_validated_tx_batch_queue_size",
			Help: "Size of the output validated transaction batch queue " +
				"of the validation and committer service manager.",
		}),
		sigverifierTransactionProcessedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "sigverifier",
			Name:      "transaction_processed_total",
			Help:      "Total number of transactions processed by the signature verifier manager.",
		}),
		vcserviceTransactionProcessedTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "vcservice",
			Name:      "transaction_processed_total",
			Help:      "Total number of transactions processed by the validation and committer service manager.",
		}),
		verifiersConnection: p.NewConnectionMetrics(monitoring.ConnectionMetricsOpts{
			Namespace:       "coordinator",
			RemoteNamespace: "verifier",
		}),
		verifiersRetriedTransactionTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "vcservice",
			Name:      "retired_transaction_total",
			Help:      "Total number of transactions retried by the validation and committer service manager.",
		}),
		vcservicesConnection: p.NewConnectionMetrics(monitoring.ConnectionMetricsOpts{
			Namespace:       "coordinator",
			RemoteNamespace: "vcservice",
		}),
		vcservicesRetriedTransactionTotal: p.NewCounter(prometheus.CounterOpts{
			Namespace: "coordinator",
			Subsystem: "sigverifier",
			Name:      "retired_transaction_total",
			Help:      "Total number of transactions retried by the signature verifier manager.",
		}),
	}
}
