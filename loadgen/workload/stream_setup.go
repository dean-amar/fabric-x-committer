/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package workload

import (
	"context"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
)

type (
	// StreamWithSetup implements the TxStream interface.
	StreamWithSetup struct {
		WorkloadSetupTXs channel.Reader[*protoblocktx.Tx]
		TxStream         *TxStream
		BlockSize        uint64
	}

	// TxGeneratorWithSetup is a TX generator that first submit TXs from the WorkloadSetupTXs,
	// and blocks until indicated that it was committed.
	// Then, it submits transactions from the tx stream.
	TxGeneratorWithSetup struct {
		WorkloadSetupTXs channel.Reader[*protoblocktx.Tx]
		TxGen            *RateLimiterGenerator[*protoblocktx.Tx]
	}
)

// MakeTxGenerator instantiate clientTxGenerator.
func (c *StreamWithSetup) MakeTxGenerator() *TxGeneratorWithSetup {
	cg := &TxGeneratorWithSetup{WorkloadSetupTXs: c.WorkloadSetupTXs}
	if c.TxStream != nil {
		cg.TxGen = c.TxStream.MakeGenerator()
	}
	return cg
}

// Next generate the next TX.
func (g *TxGeneratorWithSetup) Next(ctx context.Context, size int) []*protoblocktx.Tx {
	if g.WorkloadSetupTXs != nil {
		if tx, ok := g.WorkloadSetupTXs.Read(); ok {
			return []*protoblocktx.Tx{tx}
		}
		g.WorkloadSetupTXs = nil
	}
	if g.TxGen != nil {
		return g.TxGen.NextN(ctx, size)
	}
	return nil
}
