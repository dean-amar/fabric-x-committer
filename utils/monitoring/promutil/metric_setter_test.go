/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package promutil

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

func TestAddToCounter(t *testing.T) {
	t.Parallel()
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_total",
		Help: "A test counter.",
	})
	AddToCounter(c, 5)
	test.RequireIntMetricValue(t, 5, c)
}

func TestAddToCounterVec(t *testing.T) {
	t.Parallel()
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_total",
		Help: "A test counter vector.",
	}, []string{"label"})
	AddToCounterVec(cv, []string{"foo"}, 3)
	c := cv.WithLabelValues("foo")
	test.RequireIntMetricValue(t, 3, c)
}

func TestAddToGauge(t *testing.T) {
	t.Parallel()
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test",
		Help: "A test gauge.",
	})
	g.Set(10)
	AddToGauge(g, 5)
	test.RequireIntMetricValue(t, 15, g)
}

func TestSetGauge(t *testing.T) {
	t.Parallel()
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test",
		Help: "A test gauge for setting.",
	})
	SetGauge(g, 20)
	test.RequireIntMetricValue(t, 20, g)
}

func TestSetGaugeVec(t *testing.T) {
	t.Parallel()
	gv := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test",
		Help: "A test gauge vector.",
	}, []string{"label"})
	SetGaugeVec(gv, []string{"bar"}, 30)
	g := gv.WithLabelValues("bar")
	test.RequireIntMetricValue(t, 30, g)
}

func TestObserve(t *testing.T) {
	t.Parallel()
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "test",
		Help:    "A test histogram.",
		Buckets: prometheus.LinearBuckets(0, 1, 5),
	})
	duration := 2 * time.Second
	Observe(h, duration)
	m := &dto.Metric{}
	require.NoError(t, h.Write(m))
	require.InDelta(t, float64(2), m.GetHistogram().GetSampleSum(), 0)
}

func TestObserveSize(t *testing.T) {
	t.Parallel()
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "test",
		Help:    "A test histogram for size.",
		Buckets: prometheus.LinearBuckets(0, 10, 5),
	})
	ObserveSize(h, 50)
	m := &dto.Metric{}
	require.NoError(t, h.Write(m))
	require.InDelta(t, float64(50), m.GetHistogram().GetSampleSum(), 0)
}
