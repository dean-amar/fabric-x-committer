/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/integration/runner"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
)

func TestLoadGen(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		serviceFlags int
	}{
		{
			name:         "orderer",
			serviceFlags: runner.FullTxPathWithLoadGen,
		},
		{
			name:         "committer",
			serviceFlags: runner.CommitterTxPathWithLoadGen,
		},
		{
			name:         "coordinator",
			serviceFlags: runner.LoadGenForCoordinator | runner.Coordinator | runner.VC | runner.Verifier,
		},
		{
			name:         "VC",
			serviceFlags: runner.LoadGenForVCService | runner.VC,
		},
		{
			name:         "verifier",
			serviceFlags: runner.LoadGenForVerifier | runner.Verifier,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gomega.RegisterTestingT(t)
			c := runner.NewRuntime(t, &runner.Config{
				NumVerifiers: 2,
				NumVCService: 2,
				BlockTimeout: 2 * time.Second,
				BlockSize:    500,
			})
			c.Start(t, tc.serviceFlags)

			metricsURL, err := monitoring.MakeMetricsURL(c.SystemConfig.Endpoints.LoadGen.Metrics.Address())
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				count := promutil.GetMetricValueFromURL(t, metricsURL, "loadgen_transaction_committed_total")
				t.Logf("count %d", count)
				return count > 1_000
			}, 90*time.Second, 1*time.Second)
		})
	}
}

func TestLoadGenCommitterWithLimit(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockTimeout: 2 * time.Second,
		BlockSize:    500,
	})
	c.SystemConfig.LoadGenBlockLimit = 4
	c.Start(t, runner.CommitterTxPathWithLoadGen)

	expectedTXs := 500*3 + 2 // +2 for config and namespace TXs
	require.Eventually(t, func() bool {
		count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
		t.Logf("count %d", count)
		return count >= expectedTXs
	}, 90*time.Second, 1*time.Second)
	require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))

	count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
	require.Equal(t, expectedTXs, count)
}
