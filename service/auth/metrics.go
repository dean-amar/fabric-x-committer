/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/serve"
)

const (
	namespace = "authservice"

	subsystemGRPC = "grpc"
)

type perfMetrics struct {
	*monitoring.Provider

	serverMetrics     *serve.ServerMetrics
	configSequence    prometheus.Gauge
	configLastRefresh prometheus.Gauge
	tokenStoreSize    prometheus.Gauge
}

func newAuthServiceMetrics() *perfMetrics {
	p := monitoring.NewProvider()

	return &perfMetrics{
		Provider: p,
		serverMetrics: serve.NewServerMetrics(p, monitoring.MetricsParameters{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
		}),
		configSequence: p.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "config_sequence",
			Help:      "The channel-configuration sequence the current evaluation bundle was built from.",
		}),
		// A refresh failure is logged and retried rather than failing closed, so this timestamp is the
		// only way an operator can tell "configuration is stable" from "configuration has been
		// unreachable for hours". Alert on it falling behind several refresh intervals.
		configLastRefresh: p.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "config_last_refresh_timestamp_seconds",
			Help:      "Unix time of the last successful channel-configuration refresh.",
		}),
		tokenStoreSize: p.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystemGRPC,
			Name:      "token_store_size",
			Help:      "Number of token records held in the in-memory cache.",
		}),
	}
}
