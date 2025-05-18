/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitoring

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
)

type (
	// ThroughputDirection can in or out.
	ThroughputDirection = string

	// ConnectionMetricsOpts describes connection metrics parameters.
	ConnectionMetricsOpts struct {
		Namespace       string
		RemoteNamespace string
	}

	// ConnectionMetrics supports common connection metrics.
	ConnectionMetrics struct {
		Status       *prometheus.GaugeVec
		FailureTotal *prometheus.CounterVec
		connected    atomic.Bool
	}
)

// Direction constants.
const (
	In  ThroughputDirection = "in"
	Out ThroughputDirection = "out"
)

// Connected observed connected.
func (m *ConnectionMetrics) Connected(grpcTarget string) {
	promutil.SetGaugeVec(m.Status, []string{grpcTarget}, connection.Connected)
	m.connected.Store(true)
}

// Disconnected observe disconnected. The failure count is increased only if the status was connected.
func (m *ConnectionMetrics) Disconnected(grpcTarget string) {
	promutil.SetGaugeVec(m.Status, []string{grpcTarget}, connection.Disconnected)
	if m.connected.CompareAndSwap(true, false) {
		promutil.AddToCounterVec(m.FailureTotal, []string{grpcTarget}, 1)
	}
}
