/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package broadcastdeliver

import (
	"context"
	"math"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	"github.com/hyperledger/fabric/protoutil"
	"google.golang.org/grpc"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/serialization"
)

type (
	// DeliverCftClient allows delivering blocks from one connection at a time.
	// If one connection fails, it will try to connect to another one.
	DeliverCftClient struct {
		ConnectionManager *OrdererConnectionManager
		Signer            protoutil.Signer
		ChannelID         string
		StreamCreator     func(ctx context.Context, conn grpc.ClientConnInterface) (DeliverStream, error)
	}

	// DeliverConfig holds the configuration needed for deliver to run.
	DeliverConfig struct {
		StartBlkNum int64
		EndBlkNum   uint64
		OutputBlock chan<- *common.Block
	}

	// DeliverStream requires the following interface.
	DeliverStream interface {
		Send(*common.Envelope) error
		RecvBlockOrStatus() (*common.Block, *common.Status, error)
	}
)

// MaxBlockNum is used for endless deliver.
const MaxBlockNum uint64 = math.MaxUint64

// Deliver start receiving blocks starting from config.StartBlkNum to config.OutputBlock.
// The value of config.StartBlkNum is updated with the latest block number.
func (c *DeliverCftClient) Deliver(ctx context.Context, config *DeliverConfig) error {
	resiliencyManager := c.ConnectionManager.GetResiliencyManager(WithAPI(Deliver))
	for ctx.Err() == nil {
		if config.StartBlkNum > 0 && uint64(config.StartBlkNum) > config.EndBlkNum {
			logger.Debugf("Deliver finished successfully")
			return nil
		}
		logger.Debugf("Deliver is waiting for connection")
		if c.ConnectionManager.IsStale(resiliencyManager) {
			resiliencyManager = c.ConnectionManager.GetResiliencyManager(WithAPI(Deliver))
		}
		curConn, err := resiliencyManager.GetNextConnection(ctx)
		if err != nil {
			logger.Debugf("Deliver failed to get next connection: %s", err)
			// We stop delivering if we fail to get an alive connection.
			return errors.Wrap(err, "failed to get next connection")
		}
		curConn.LastError = c.receiveFromBlockDeliverer(ctx, curConn, config)
		logger.Debugf("Error receiving blocks: %v", curConn.LastError)
	}
	logger.Debugf("Deliver context ended: %v", ctx.Err())
	return errors.Wrap(ctx.Err(), "context ended")
}

func (c *DeliverCftClient) receiveFromBlockDeliverer(
	ctx context.Context, conn *OrdererConnection, config *DeliverConfig,
) error {
	logger.Infof("Connecting to %s", conn.Target())
	stream, err := c.StreamCreator(ctx, conn)
	if err != nil {
		logger.Infof("failed connecting to %s: %s", conn.Target(), err)
		return errors.Wrap(err, "failed to create stream")
	}

	logger.Infof("Sending seek request from block %d on channel %s.", config.StartBlkNum, c.ChannelID)
	seekEnv, err := seekSince(config.StartBlkNum, config.EndBlkNum, c.ChannelID, c.Signer)
	if err != nil {
		return errors.Wrap(err, "failed to create seek request")
	}
	if err := stream.Send(seekEnv); err != nil {
		return errors.Wrap(err, "failed to send seek request")
	}
	logger.Info("Seek request sent.")

	outputBlock := channel.NewWriter(ctx, config.OutputBlock)
	for ctx.Err() == nil {
		block, status, err := stream.RecvBlockOrStatus()
		if err != nil {
			return errors.Wrap(err, "failed to receive block")
		}
		if status != nil {
			return errors.Newf("disconnecting deliver service with status %s", status)
		}

		//nolint:gosec // integer overflow conversion uint64 -> int64
		config.StartBlkNum = int64(block.Header.Number) + 1
		logger.Debugf("next expected block number is %d", config.StartBlkNum)
		outputBlock.Write(block)

		// If we managed to receive one block, we can reset the connection's backoff.
		conn.ResetBackoff()
	}

	return nil
}

// TODO: We have seek info only for the orderer but not for the ledger service. It needs
//       to implemented as fabric ledger also allows different seek info.

const (
	seekSinceOldestBlock = -2
	seekSinceNewestBlock = -1
)

var (
	oldest = &orderer.SeekPosition{Type: &orderer.SeekPosition_Oldest{Oldest: &orderer.SeekOldest{}}}
	newest = &orderer.SeekPosition{Type: &orderer.SeekPosition_Newest{Newest: &orderer.SeekNewest{}}}
)

func seekSince(
	startBlockNumber int64,
	endBlkNum uint64,
	channelID string,
	signer protoutil.Signer,
) (*common.Envelope, error) {
	var startPosition *orderer.SeekPosition
	switch startBlockNumber {
	case seekSinceOldestBlock:
		startPosition = oldest
	case seekSinceNewestBlock:
		startPosition = newest
	default:
		if startBlockNumber < -2 {
			return nil, errors.New("wrong seek value")
		}
		startPosition = &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{
			Number: uint64(startBlockNumber), //nolint:gosec // integer overflow conversion int64 -> uint64
		}}}
	}

	if signer == nil {
		signer = &serialization.NoOpSigner{}
	}

	return protoutil.CreateSignedEnvelope(common.HeaderType_DELIVER_SEEK_INFO, channelID, signer, &orderer.SeekInfo{
		Start: startPosition,
		Stop: &orderer.SeekPosition{Type: &orderer.SeekPosition_Specified{Specified: &orderer.SeekSpecified{
			Number: endBlkNum,
		}}},
		Behavior: orderer.SeekInfo_BLOCK_UNTIL_READY,
	}, 0, 0)
}
