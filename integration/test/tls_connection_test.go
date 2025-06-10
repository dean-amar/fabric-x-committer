/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc/dbtest"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/integration/runner"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

func TestMutualTLSConnection(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockTimeout: 2 * time.Second,
		BlockSize:    500,
		TLS:          connection.TLSMutual,
	})

	c.Start(t, runner.FullTxPathWithLoadGen)

	require.Eventually(t, func() bool {
		count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
		t.Logf("count %d", count)
		return count > 1_000
	}, 20*time.Second, 500*time.Millisecond)
	require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))
}

func TestOneSidedTLSConnection(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockTimeout: 2 * time.Second,
		BlockSize:    500,
		TLS:          connection.TLSServer,
	})

	c.Start(t, runner.FullTxPathWithLoadGen)

	require.Eventually(t, func() bool {
		count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
		t.Logf("count %d", count)
		return count > 1_000
	}, 90*time.Second, 500*time.Millisecond)
	require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))
}

func TestFullTLSConnections(t *testing.T) {
	t.Setenv(dbtest.DeploymentTypeEnv, "container")
	t.Setenv(dbtest.DatabaseUseTLS, "true")
	t.Setenv(dbtest.DatabaseTypeEnv, "yugabyte")

	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockTimeout: 2 * time.Second,
		BlockSize:    500,
		TLS:          connection.TLSMutual,
	})

	c.Start(t, runner.FullTxPathWithLoadGen)

	require.Eventually(t, func() bool {
		count := c.CountStatus(t, protoblocktx.Status_COMMITTED)
		t.Logf("count %d", count)
		return count > 1_000
	}, 90*time.Second, 500*time.Millisecond)
	require.Zero(t, c.CountAlternateStatus(t, protoblocktx.Status_COMMITTED))
}
