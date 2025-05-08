package test

import (
	"github.com/onsi/gomega"
	"github.ibm.com/decentralized-trust-research/scalable-committer/integration/runner"
	"testing"
	"time"
)

func TestTLSConnection(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockTimeout: 2 * time.Second,
		BlockSize:    500,
		TLS: &runner.RuntimeTlsConfig{
			UseTLS:    true,
			MutualTLS: true,
		},
	})
	t.Log(c)

	time.Sleep(20 * time.Second)
	//c.Start(t, runner.FullTxPath)
}
