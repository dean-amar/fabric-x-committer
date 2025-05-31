/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package workload

import (
	"context"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
)

type (
	// StreamWithSetup implements the TxStream interface.
	StreamWithSetup struct {
		WorkloadSetupTXs channel.Reader[*protoblocktx.Tx]
		TxStream         *TxStream
		BlockSize        uint64
	}

	// BlockGeneratorWithSetup is a block generator that first submit blocks from the WorkloadSetupTXs,
	// and blocks until indicated that it was committed.
	// Then, it submits blocks from the tx stream.
	BlockGeneratorWithSetup struct {
		WorkloadSetupTXs channel.Reader[*protoblocktx.Tx]
		BlockGen         *BlockGenerator
	}

	// TxGeneratorWithSetup is a TX generator that first submit TXs from the WorkloadSetupTXs,
	// and blocks until indicated that it was committed.
	// Then, it submits transactions from the tx stream.
	TxGeneratorWithSetup struct {
		WorkloadSetupTXs channel.Reader[*protoblocktx.Tx]
		TxGen            *RateLimiterGenerator[*protoblocktx.Tx]
	}
)

// MakeBlocksGenerator instantiate clientBlockGenerator.
func (c *StreamWithSetup) MakeBlocksGenerator() *BlockGeneratorWithSetup {
	cg := &BlockGeneratorWithSetup{WorkloadSetupTXs: c.WorkloadSetupTXs}
	if c.TxStream != nil {
		cg.BlockGen = &BlockGenerator{
			TxGenerator: c.TxStream.MakeGenerator(),
			BlockSize:   c.BlockSize,
		}
	}
	return cg
}

// MakeTxGenerator instantiate clientTxGenerator.
func (c *StreamWithSetup) MakeTxGenerator() *TxGeneratorWithSetup {
	cg := &TxGeneratorWithSetup{WorkloadSetupTXs: c.WorkloadSetupTXs}
	if c.TxStream != nil {
		cg.TxGen = c.TxStream.MakeGenerator()
	}
	return cg
}

// Next generate the next block.
func (g *BlockGeneratorWithSetup) Next(ctx context.Context) *protocoordinatorservice.Block {
	if g.WorkloadSetupTXs != nil {
		if tx, ok := g.WorkloadSetupTXs.Read(); ok {
			return &protocoordinatorservice.Block{
				Txs:    []*protoblocktx.Tx{tx},
				TxsNum: []uint32{0},
			}
		}
		g.WorkloadSetupTXs = nil
	}
	if g.BlockGen != nil {
		return g.BlockGen.Next(ctx)
	}
	return nil
}

// Next generate the next TX.
func (g *TxGeneratorWithSetup) Next(ctx context.Context) *protoblocktx.Tx {
	if g.WorkloadSetupTXs != nil {
		if tx, ok := g.WorkloadSetupTXs.Read(); ok {
			return tx
		}
		g.WorkloadSetupTXs = nil
	}
	if g.TxGen != nil {
		return g.TxGen.Next(ctx)
	}
	return nil
}
