/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapters

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/mock"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/serialization"
)

type (
	// SidecarAdapter applies load on the sidecar.
	SidecarAdapter struct {
		commonAdapter
		config *SidecarClientConfig
	}
)

// NewSidecarAdapter instantiate SidecarAdapter.
func NewSidecarAdapter(config *SidecarClientConfig, res *ClientResources) *SidecarAdapter {
	return &SidecarAdapter{
		commonAdapter: commonAdapter{res: res},
		config:        config,
	}
}

// RunWorkload applies load on the sidecar.
func (c *SidecarAdapter) RunWorkload(ctx context.Context, txStream TxStream) error {
	if len(c.config.OrdererServers) == 0 {
		return errors.New("no orderer servers configured")
	}
	orderer, err := mock.NewMockOrderer(&mock.OrdererConfig{
		ServerConfigs: c.config.OrdererServers,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create orderer")
	}

	dCtx, dCancel := context.WithCancel(ctx)
	defer dCancel()
	g, gCtx := errgroup.WithContext(dCtx)

	g.Go(func() error {
		return connection.StartService(gCtx, orderer, nil, nil)
	})
	for _, conf := range c.config.OrdererServers {
		conf := conf
		g.Go(func() error {
			return connection.RunGrpcServerMainWithError(gCtx, conf, func(s *grpc.Server) {
				ab.RegisterAtomicBroadcastServer(s, orderer)
			})
		})
	}

	// The sidecar adapter submits a config block manually.
	policy := *c.res.Profile.Transaction.Policy
	policy.OrdererEndpoints = connection.NewOrdererEndpoints(0, "msp", c.config.OrdererServers...)
	configBlock, err := workload.CreateConfigBlock(&policy)
	if err != nil {
		return errors.Wrap(err, "failed to create config block")
	}
	orderer.SubmitBlock(ctx, configBlock)
	c.nextBlockNum.Add(1)

	g.Go(func() error {
		defer dCancel() // We stop sending if we can't track the received items.
		return runReceiver(gCtx, &receiverConfig{
			ChannelID: c.config.ChannelID,
			Endpoint:  c.config.SidecarEndpoint,
			Res:       c.res,
		})
	})
	g.Go(func() error {
		return c.sendBlocks(gCtx, txStream, func(block *protocoordinatorservice.Block) error {
			fabricBlock, err := c.mapSidecarBlock(block)
			if err != nil {
				return err
			}
			if !orderer.SubmitBlock(gCtx, fabricBlock) {
				return errors.New("failed to submit block")
			}
			return nil
		})
	})
	return errors.Wrap(g.Wait(), "workload done")
}

// Supports specify which phases an adapter supports.
// The sidecar does not support config transactions as it filters them.
// To generate a config TX, the orderer must submit a config block.
func (*SidecarAdapter) Supports() Phases {
	return Phases{
		Config:     false,
		Namespaces: true,
		Load:       true,
	}
}

func (c *SidecarAdapter) mapSidecarBlock(block *protocoordinatorservice.Block) (*common.Block, error) {
	data := make([][]byte, len(block.Txs))
	for i, tx := range block.Txs {
		env, _, err := serialization.CreateEnvelope(c.config.ChannelID, nil, tx)
		if err != nil {
			return nil, errors.Wrap(err, "failed creating envelope")
		}
		data[i], err = proto.Marshal(env)
		if err != nil {
			return nil, errors.Wrap(err, "failed marshaling envelope")
		}
	}
	return &common.Block{
		Header: &common.BlockHeader{
			Number: block.Number,
		},
		Data: &common.BlockData{
			Data: data,
		},
	}, nil
}
