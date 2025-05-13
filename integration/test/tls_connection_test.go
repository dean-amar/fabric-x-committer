package test

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/integration/runner"
)

func TestTLSConnection(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockTimeout: 2 * time.Second,
		BlockSize:    500,
		TLS: runner.TLSSettings{
			UseTLS:    true,
			MutualTLS: true,
		},
	})

	//c.Start(t, runner.CommitterTxPathWithLoadGen)
	c.Start(t, runner.FullTxPathWithLoadGen)
	//c.Start(t, runner.FullTxPathWithQuery)
	//c.Start(t, runner.LoadGenForCoordinator|runner.Coordinator|runner.VC|runner.Verifier)
	require.Eventually(t, func() bool {
		count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
		t.Logf("count %d", count)
		return count > 10_000
	}, 90*time.Second, 500*time.Millisecond)
	require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))
}
