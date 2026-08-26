/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
)

const (
	namespace = "authservice"

	subsystemGRPC = "grpc"

	methodAuthenticate = "authenticate"
	methodAuthorize    = "authorize"
	methodReAuthorize  = "reauthorize"

	// Request outcomes, used as the "outcome" label on the requests counter.
	outcomeOK              = "ok"
	outcomeDenied          = "denied"
	outcomeUnauthenticated = "unauthenticated"
	outcomeUnavailable     = "unavailable"
	outcomeError           = "error"
)

var timeBuckets = []float64{.0001, .001, .002, .003, .004, .005, .01, .03, .05, .1, .3, .5, 1, 2, 3, 4, 5, 10}

type perfMetrics struct {
	*monitoring.Provider

	requests          *prometheus.CounterVec
	requestsLatency   *prometheus.HistogramVec
	configSequence    prometheus.Gauge
	tokenStoreSize    prometheus.Gauge
	serverConnections prometheus.Gauge
}

func newAuthServiceMetrics() *perfMetrics {
	p := monitoring.NewProvider()

	return &perfMetrics{
		Provider: p,
		requests: p.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "requests_total",
			Help:      "Number of authenticate/authorize requests by outcome.",
		}, []string{"method", "outcome"}),
		requestsLatency: p.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "requests_latency_seconds",
			Help:      "The latency (seconds) of authenticate/authorize requests.",
			Buckets:   timeBuckets,
		}, []string{"method"}),
		configSequence: p.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "config_sequence",
			Help:      "The channel-configuration sequence the current evaluation bundle was built from.",
		}),
		tokenStoreSize: p.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "token_store_size",
			Help:      "Number of token records held in the in-memory cache.",
		}),
		serverConnections: monitoring.NewConnectionStatsMetrics(p, monitoring.MetricsParameters{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
		}),
	}
}
