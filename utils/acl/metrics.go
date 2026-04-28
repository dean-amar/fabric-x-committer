/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metrics for ACL operations.
// These metrics provide observability into ACL enforcement, helping identify
// access patterns, denied requests, and performance characteristics.
type Metrics struct {
	// checksTotal counts the total number of ACL checks performed.
	// Labels: method (gRPC method), result (allowed/denied)
	checksTotal *prometheus.CounterVec

	// checkDuration measures the time taken to perform ACL checks.
	// Labels: method (gRPC method)
	checkDuration *prometheus.HistogramVec

	// certValidationErrors counts certificate validation failures.
	// Labels: reason (expired/invalid_chain/invalid_role/missing_cert)
	certValidationErrors *prometheus.CounterVec

	// policyLookupFailures counts cases where no policy is defined for a method.
	// Labels: method (gRPC method)
	policyLookupFailures *prometheus.CounterVec
}

// NewMetrics creates and registers all ACL-related Prometheus metrics.
// If metrics are already registered (e.g., in tests), it returns a new Metrics
// instance without re-registering.
func NewMetrics() *Metrics {
	m := &Metrics{
		checksTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "fabricx",
				Subsystem: "acl",
				Name:      "checks_total",
				Help:      "Total number of ACL checks performed",
			},
			[]string{"method", "result"},
		),
		checkDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "fabricx",
				Subsystem: "acl",
				Name:      "check_duration_seconds",
				Help:      "Time taken to perform ACL checks",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		certValidationErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "fabricx",
				Subsystem: "acl",
				Name:      "cert_validation_errors_total",
				Help:      "Total number of certificate validation errors",
			},
			[]string{"reason"},
		),
		policyLookupFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "fabricx",
				Subsystem: "acl",
				Name:      "policy_lookup_failures_total",
				Help:      "Total number of policy lookup failures (no policy defined for method)",
			},
			[]string{"method"},
		),
	}

	// Try to register metrics, ignore errors if already registered (e.g., in tests)
	_ = prometheus.Register(m.checksTotal)
	_ = prometheus.Register(m.checkDuration)
	_ = prometheus.Register(m.certValidationErrors)
	_ = prometheus.Register(m.policyLookupFailures)

	return m
}

// RecordCheckAllowed records a successful ACL check (access granted).
func (m *Metrics) RecordCheckAllowed(method string) {
	m.checksTotal.WithLabelValues(method, "allowed").Inc()
}

// RecordCheckDenied records a failed ACL check (access denied).
func (m *Metrics) RecordCheckDenied(method string) {
	m.checksTotal.WithLabelValues(method, "denied").Inc()
}

// RecordCheckDuration records the duration of an ACL check.
func (m *Metrics) RecordCheckDuration(method string, durationSeconds float64) {
	m.checkDuration.WithLabelValues(method).Observe(durationSeconds)
}

// RecordCertValidationError records a certificate validation error.
// Reason should be one of: "expired", "invalid_chain", "invalid_role", "missing_cert", "no_peer_info", "no_tls_info"
func (m *Metrics) RecordCertValidationError(reason string) {
	m.certValidationErrors.WithLabelValues(reason).Inc()
}

// RecordPolicyLookupFailure records a case where no policy is defined for a method.
func (m *Metrics) RecordPolicyLookupFailure(method string) {
	m.policyLookupFailures.WithLabelValues(method).Inc()
}
