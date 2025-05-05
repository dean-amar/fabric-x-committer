package promutil

import (
	"io"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promgo "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CheckMetrics checks the metrics endpoint for the expected metrics.
func CheckMetrics(t *testing.T, client *http.Client, url string, expectedMetrics []string) {
	t.Helper()
	resp, err := client.Get(url)
	require.NoError(t, err)

	defer func() {
		_ = resp.Body.Close()
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	bys, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	metricsOutput := string(bys)

	for _, expected := range expectedMetrics {
		require.Contains(t, metricsOutput, expected)
	}
}

// GetMetricValue returns the value of a prometheus metric.
func GetMetricValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	gm := promgo.Metric{}
	require.NoError(t, m.Write(&gm))

	switch {
	case gm.Gauge != nil:
		return gm.Gauge.GetValue()
	case gm.Counter != nil:
		return gm.Counter.GetValue()
	case gm.Untyped != nil:
		return gm.Untyped.GetValue()
	case gm.Summary != nil:
		return gm.Summary.GetSampleSum()
	case gm.Histogram != nil:
		return gm.Histogram.GetSampleSum()
	default:
		require.Fail(t, "unsupported metric")
		return 0
	}
}

// GetIntMetricValue returns the value of a prometheus metric, rounded to the nearest integer.
func GetIntMetricValue(t *testing.T, m prometheus.Metric) int {
	t.Helper()
	val := GetMetricValue(t, m)
	return int(math.Round(val))
}

// RequireIntMetricValue fail the test if the integer metric is not equal to the expected value.
func RequireIntMetricValue(t *testing.T, expected int, m prometheus.Metric) {
	t.Helper()
	require.Equal(t, expected, GetIntMetricValue(t, m))
}

// EventuallyIntMetric fail the test if the integer metric is not equal to the expected value after the given duration.
func EventuallyIntMetric( //nolint:revive // number of arguments is derived from the [require] package.
	t *testing.T, expected int, m prometheus.Metric, waitFor, tick time.Duration, msgAndArgs ...any,
) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		v := GetIntMetricValue(t, m)
		require.Equal(c, expected, v)
	}, waitFor, tick, msgAndArgs...)
}
