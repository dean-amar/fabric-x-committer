/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
)

// ServerMetrics holds the server-side connection and RPC metrics a service records. The RPC
// metrics are labeled by the full gRPC method ("/pkg.Service/Method").
type ServerMetrics struct {
	// RequestsTotal counts started RPCs (unary and streaming).
	RequestsTotal *prometheus.CounterVec
	// LatencySeconds observes RPC duration, labeled by method and by the RPC's
	// gRPC status code. Streaming RPCs are not observed, as their duration is the lifetime
	// of the stream rather than request latency; StreamDurationSeconds records those instead.
	LatencySeconds *prometheus.HistogramVec
	// StreamDurationSeconds observes how long a streaming RPC was active from start to end, labeled
	// by method and by the stream's gRPC status code.
	StreamDurationSeconds *prometheus.HistogramVec
	// ActiveStreams reflects the number of streaming RPCs currently in progress.
	ActiveStreams *prometheus.GaugeVec
	// ActiveConnections is incremented when the server accepts a connection and decremented
	// when it is torn down, so it reflects the number of connections currently open.
	ActiveConnections prometheus.Gauge
	// MessagesReceivedTotal counts individual messages the server received. A streaming RPC is one
	// RequestsTotal observation however much flows through it, so this is what makes per-stream
	// throughput visible.
	MessagesReceivedTotal *prometheus.CounterVec
	// MessagesSentTotal counts individual messages the server sent, the outbound counterpart of
	// MessagesReceivedTotal.
	MessagesSentTotal *prometheus.CounterVec
	// MessageReceivedSizeBytes observes the wire size of each message received: the compressed
	// payload plus gRPC framing, excluding HTTP/2 framing.
	MessageReceivedSizeBytes *prometheus.HistogramVec
	// MessageSentSizeBytes observes the wire size of each message sent, on the same basis as
	// MessageReceivedSizeBytes.
	MessageSentSizeBytes *prometheus.HistogramVec
}

const method = "method"

// NewServerMetrics creates the server-side metrics recorded by the gRPC stats handler.
func NewServerMetrics(p *monitoring.Provider, params monitoring.MetricsParameters) *ServerMetrics {
	return &ServerMetrics{
		RequestsTotal: p.NewCounterVec(prometheus.CounterOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "requests_total",
			Help:      "Number of RPCs started by the service",
		}, []string{method}),
		LatencySeconds: p.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "requests_latency_seconds",
			Help:      "The latency (seconds) of requests by the service, by method and gRPC status code",
			Buckets:   monitoring.LatencyBuckets,
		}, []string{method, "status"}),
		StreamDurationSeconds: p.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "stream_duration_seconds",
			Help:      "The duration (seconds) a stream was active from start to end, by method and gRPC status code",
			Buckets:   monitoring.StreamDurationBuckets,
		}, []string{method, "status"}),
		ActiveStreams: p.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "active_streams",
			Help:      "Number of gRPC streams currently open on the server",
		}, []string{method}),
		ActiveConnections: p.NewGauge(prometheus.GaugeOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "active_connections",
			Help:      "Number of client connections currently open on the server",
		}),
		MessagesReceivedTotal: p.NewCounterVec(prometheus.CounterOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "messages_received_total",
			Help:      "Number of messages received by the server",
		}, []string{method}),
		MessagesSentTotal: p.NewCounterVec(prometheus.CounterOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "messages_sent_total",
			Help:      "Number of messages sent by the server",
		}, []string{method}),
		MessageReceivedSizeBytes: p.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "message_received_size_bytes",
			Help:      "The wire size (bytes) of messages received by the server",
			Buckets:   monitoring.MessageSizeBuckets,
		}, []string{method}),
		MessageSentSizeBytes: p.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: params.Namespace,
			Subsystem: params.Subsystem,
			Name:      "message_sent_size_bytes",
			Help:      "The wire size (bytes) of messages sent by the server",
			Buckets:   monitoring.MessageSizeBuckets,
		}, []string{method}),
	}
}
