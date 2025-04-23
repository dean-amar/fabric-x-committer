package test

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/integration/runner"
)

func TestLoadGen(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		serviceFlags int
	}{
		{
			name:         "Orderer Load Generator",
			serviceFlags: runner.FullTxPathWithLoadGen,
		},
		{
			name:         "Committer Load Generator",
			serviceFlags: runner.CommitterTxPathWithLoadGen,
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

			require.Eventually(t, func() bool {
				count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
				t.Logf("count %d", count)
				return count > 1_000
			}, 90*time.Second, 3*time.Second)
			require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))
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
	}, 90*time.Second, 500*time.Millisecond)
	require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))

	count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
	require.Equal(t, expectedTXs, count)
}
