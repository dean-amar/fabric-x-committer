/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"testing"
	"time"

	"github.com/onsi/gomega"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/integration/runner"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/verifier"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
)

func TestBadlyFormedTxs(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)
	c := runner.NewRuntime(t, &runner.Config{
		NumVerifiers: 2,
		NumVCService: 2,
		BlockSize:    5,
		BlockTimeout: 2 * time.Second,
	})
	c.Start(t, runner.FullTxPath)

	c.CreateCryptoForNs(t, "1", signature.Ecdsa)

	//nolint:paralleltest
	for _, tt := range verifier.BadTxFormatTestCases {
		t.Run(tt.Tx.Id, func(t *testing.T) {
			c.SendTransactionsToOrderer(t, []*protoblocktx.Tx{tt.Tx})
			c.ValidateExpectedResultsInCommittedBlock(t, &runner.ExpectedStatusInBlock{
				TxIDs: []string{tt.Tx.Id}, Statuses: []protoblocktx.Status{tt.ExpectedStatus},
			})
		})
	}
}
