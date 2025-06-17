/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapters

import (
	"context"

	"github.com/cockroachdb/errors"
	"golang.org/x/sync/errgroup"

	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/broadcastdeliver"
)

type (
	// OrdererAdapter applies load on the sidecar.
	OrdererAdapter struct {
		commonAdapter
		config *OrdererClientConfig
	}
)

// NewOrdererAdapter instantiate OrdererAdapter.
func NewOrdererAdapter(config *OrdererClientConfig, res *ClientResources) *OrdererAdapter {
	return &OrdererAdapter{
		commonAdapter: commonAdapter{res: res},
		config:        config,
	}
}

// RunWorkload applies load on the sidecar.
func (c *OrdererAdapter) RunWorkload(ctx context.Context, txStream *workload.StreamWithSetup) error {
	broadcastSubmitter, err := broadcastdeliver.New(&c.config.Orderer)
	if err != nil {
		return errors.Wrap(err, "failed to create orderer clients")
	}
	defer broadcastSubmitter.Close()

	dCtx, dCancel := context.WithCancel(ctx)
	defer dCancel()
	g, gCtx := errgroup.WithContext(dCtx)
	g.Go(func() error {
		defer dCancel() // We stop sending if we can't track the received items.
		return runReceiver(gCtx, &receiverConfig{
			ChannelID: c.config.Orderer.ChannelID,
			Endpoint:  c.config.SidecarEndpoint,
			Res:       c.res,
		})
	})

	for range c.config.BroadcastParallelism {
		g.Go(func() error {
			stream, err := broadcastSubmitter.Broadcast(gCtx)
			if err != nil {
				return errors.Wrap(err, "failed to create a broadcast stream")
			}
			g.Go(func() error {
				err := c.sendTransactions(gCtx, txStream, stream)
				// Insufficient quorum may happen when the context ends due to unavailable servers.
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			})
			return nil
		})
	}
	return errors.Wrap(g.Wait(), "workload done")
}

// Supports specify which phases an adapter supports.
// The sidecar does not support config transactions as it filters them.
// To generate a config TX, the orderer must submit a config block.
func (*OrdererAdapter) Supports() Phases {
	return Phases{
		Config:     false,
		Namespaces: true,
		Load:       true,
	}
}

// sendTransactions submits Fabric TXs. It uses the envelope's TX ID to track the TXs latency.
func (c *OrdererAdapter) sendTransactions(
	ctx context.Context, txStream *workload.StreamWithSetup, stream *broadcastdeliver.EnvelopedStream,
) error {
	txGen := txStream.MakeTxGenerator()
	for ctx.Err() == nil {
		tx := txGen.Next(ctx, 1)
		if len(tx) == 0 {
			// The context ended.
			return nil
		}
		txID, resp, err := stream.SubmitWithEnv(tx[0])
		if err != nil {
			return errors.Wrap(err, "failed to submit transaction")
		}
		logger.Debugf("Sent TX %s, got ack: %s", txID, resp.Info)
		c.res.Metrics.OnSendTransaction(txID)
		if c.res.isTXSendLimit() {
			return nil
		}
	}
	return nil
}
