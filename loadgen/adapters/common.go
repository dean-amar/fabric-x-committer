/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapters

import (
	"context"
	"sync/atomic"

	"github.com/cockroachdb/errors"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/metrics"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

type (
	// ClientResources holds client's pre-generated resources to be used by the adapters.
	ClientResources struct {
		Metrics *metrics.PerfMetrics
		Profile *workload.Profile
		Limit   *GenerateLimit
	}

	// Phases specify the generation phases to enable.
	Phases struct {
		Config     bool `mapstructure:"config" yaml:"config"`
		Namespaces bool `mapstructure:"namespaces" yaml:"namespaces"`
		Load       bool `mapstructure:"load" yaml:"load"`
	}

	// GenerateLimit describes a stopping condition for generating load according to the collected metrics.
	// Zero value indicate no limit.
	// The limit on the number of TXs is applied at block granularity. I.e., more TXs might be created than expected
	// if a block overshot.
	// The load generator stops when both requirements are met, i.e., one of them might overshoot.
	// For the orderer adapter, the blocks limit is ignored for broadcasting as we don't track submitted blocks.
	// For adapters that use concurrent submitters, we cannot enforce exact limits.
	// The sidecar and coordinator adapters are sequential, so they don't have these issues.
	GenerateLimit struct {
		Blocks       uint64 `mapstructure:"blocks" yaml:"blocks"`
		Transactions uint64 `mapstructure:"transactions" yaml:"transactions"`
	}

	// TxStream makes generators such that all can be used in parallel.
	TxStream interface {
		MakeTxGenerator() workload.Generator[*protoblocktx.Tx]
		MakeBlocksGenerator() workload.Generator[*protocoordinatorservice.Block]
	}

	// commonAdapter is used as a base class for the adapters.
	commonAdapter struct {
		res          *ClientResources
		nextBlockNum atomic.Uint64
	}
)

var (
	logger = logging.New("load-gen-adapters")

	// ErrInvalidAdapterConfig indicates that none of the adapter's config were given.
	ErrInvalidAdapterConfig = errors.New("invalid config passed")
)

// PhasesIntersect returns the phases that are both in p1 and p2.
// If one of them is empty, it is assumed not to be specified.
func PhasesIntersect(p1, p2 Phases) Phases {
	if p1.Empty() {
		return p2
	}
	if p2.Empty() {
		return p1
	}
	return Phases{
		Config:     p1.Config && p2.Config,
		Namespaces: p1.Namespaces && p2.Namespaces,
		Load:       p1.Load && p2.Load,
	}
}

// Empty returns true if no phase was applied.
func (p *Phases) Empty() bool {
	return p == nil || (!p.Config && !p.Namespaces && !p.Load)
}

// Progress a committed transaction indicate progress for most adapters.
func (c *commonAdapter) Progress() uint64 {
	return c.res.Metrics.GetState().TransactionsCommitted
}

// Supports specify which phases an adapter supports.
func (*commonAdapter) Supports() Phases {
	return Phases{
		Config:     true,
		Namespaces: true,
		Load:       true,
	}
}

func (c *commonAdapter) sendBlocks(
	ctx context.Context,
	txStream TxStream,
	send func(*protocoordinatorservice.Block) error,
) error {
	blockGen := txStream.MakeBlocksGenerator()
	for ctx.Err() == nil {
		block := blockGen.Next()
		if block == nil {
			// If the context ended, the generator returns nil.
			return nil
		}
		block.Number = c.nextBlockNum.Add(1) - 1
		logger.Debugf("Sending block %d with %d TXs", block.Number, len(block.Txs))
		if err := send(block); err != nil {
			return errors.Wrap(connection.FilterStreamRPCError(err), "failed sending block")
		}
		c.res.Metrics.OnSendBlock(block)
		if c.res.isSendLimit() {
			return nil
		}
	}
	return nil
}

func (r *ClientResources) isSendLimit() bool {
	if !r.Limit.HasLimit() {
		return false
	}
	state := r.Metrics.GetState()
	return isReachedLimit(state.BlocksSent, r.Limit.Blocks) &&
		isReachedLimit(state.TransactionsSent, r.Limit.Transactions)
}

func (r *ClientResources) isTXSendLimit() bool {
	if r.Limit == nil || r.Limit.Transactions == 0 {
		return false
	}
	state := r.Metrics.GetState()
	return isReachedLimit(state.TransactionsSent, r.Limit.Transactions)
}

func (r *ClientResources) isReceiveLimit() bool {
	if !r.Limit.HasLimit() {
		return false
	}
	state := r.Metrics.GetState()
	return isReachedLimit(state.BlocksReceived, r.Limit.Blocks) &&
		isReachedLimit(state.TransactionsReceived, r.Limit.Transactions)
}

// HasLimit returns true if any limit is set.
func (g *GenerateLimit) HasLimit() bool {
	return g != nil && (g.Blocks > 0 || g.Transactions > 0)
}

func isReachedLimit(value, limit uint64) bool {
	return limit == 0 || value >= limit
}
