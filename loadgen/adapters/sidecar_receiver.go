/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapters

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/loadgen/metrics"
	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/utils"
	"github.com/hyperledger/fabric-x-committer/utils/auth"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/delivercommitter"
	"github.com/hyperledger/fabric-x-committer/utils/deliverorderer"
	"github.com/hyperledger/fabric-x-committer/utils/ordererdial"
	"github.com/hyperledger/fabric-x-committer/utils/serialization"
)

type sidecarReceiverParameters struct {
	Res          *ClientResources
	ClientConfig *connection.ClientConfig
}

const (
	committedBlocksQueueSize = 1024
	statusIdx                = int(common.BlockMetadataIndex_TRANSACTIONS_FILTER)
)

// runSidecarReceiver start receiving blocks from the sidecar.
func runSidecarReceiver(ctx context.Context, params *sidecarReceiverParameters) error {
	dialOpts, err := clientAuthDialOptions(&params.Res.Profile.Policy, params.ClientConfig.TLS)
	if err != nil {
		return errors.Wrap(err, "failed to build client-auth dial options for the sidecar receiver")
	}
	return runDeliveryReceiver(ctx, params.Res, func(gCtx context.Context, committedBlock chan *common.Block) error {
		return delivercommitter.ToQueue(gCtx, delivercommitter.Parameters{
			ClientConfig: params.ClientConfig,
			OutputBlock:  committedBlock,
			DialOpts:     dialOpts,
		})
	})
}

// clientAuthDialOptions builds the gRPC dial options that attach a signed envelope to
// client-facing dials of ACL-enforced services (e.g. the sidecar's Deliver service). The
// signer is loaded from the load profile's policy crypto artifacts (the same artifacts used
// to sign generated transactions), so a channel member's identity authenticates delivery too.
//
// A policy without artifacts (the common case for non-ACL deployments) yields a nil signer,
// which makes auth.UnaryClientInterceptor/StreamClientInterceptor no-op passthroughs — the
// options are safe to attach unconditionally.
func clientAuthDialOptions(policy *workload.PolicyProfile, tlsConfig connection.TLSConfig) ([]grpc.DialOption, error) {
	signer, err := loadDeliverySigner(policy.ArtifactsPath)
	if err != nil {
		return nil, err
	}
	certHash, err := auth.ClientTLSCertHash(tlsConfig)
	if err != nil {
		return nil, err
	}
	cfg := auth.ClientAuthConfig{
		Signer:      signer,
		ChannelID:   policy.ChannelID,
		TLSCertHash: certHash,
	}
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(auth.UnaryClientInterceptor(cfg)),
		grpc.WithChainStreamInterceptor(auth.StreamClientInterceptor(cfg)),
	}, nil
}

// loadDeliverySigner loads a channel-member signer for client-side ACL envelopes from the
// peer crypto artifacts at artifactsPath. It returns a nil signer (no error) when no
// artifacts are configured, which is the case for non-ACL loadgen runs.
//
//nolint:ireturn // msp.SigningIdentity is an interface by design.
func loadDeliverySigner(artifactsPath string) (msp.SigningIdentity, error) {
	if artifactsPath == "" {
		return nil, nil //nolint:nilnil // absence of artifacts is not an error; see doc comment.
	}
	identities, err := testcrypto.GetPeersIdentities(artifactsPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load peer identities for client auth")
	}
	if len(identities) == 0 {
		return nil, nil //nolint:nilnil // no identity available; the caller falls back to a no-op.
	}
	return identities[0], nil
}

// runOrdererReceiver start receiving blocks from the orderer.
func runOrdererReceiver(ctx context.Context, res *ClientResources, c *ordererdial.Config) error {
	return runDeliveryReceiver(ctx, res, func(gCtx context.Context, committedBlock chan *common.Block) error {
		return deliverorderer.ToQueueWithNoFT(gCtx, deliverorderer.NoFTParameters{
			ClientConfig: c,
			OutputBlock:  committedBlock,
			NextBlockNum: 0,
		})
	})
}

// runDeliveryReceiver start receiving blocks from a delivery service.
func runDeliveryReceiver(
	ctx context.Context, res *ClientResources, deliverMethod func(context.Context, chan *common.Block) error,
) error {
	g, gCtx := errgroup.WithContext(ctx)
	committedBlock := make(chan *common.Block, committedBlocksQueueSize)
	g.Go(func() error {
		return deliverMethod(gCtx, committedBlock)
	})
	g.Go(func() error {
		receiveCommittedBlock(gCtx, committedBlock, res)
		return context.Canceled
	})
	return errors.Wrap(g.Wait(), "receiver done")
}

func receiveCommittedBlock(
	ctx context.Context,
	blockQueue <-chan *common.Block,
	res *ClientResources,
) {
	pCtx, pCancel := context.WithCancel(ctx)
	defer pCancel()
	committedBlock := channel.NewReader(pCtx, blockQueue)
	processedBlocks := channel.Make[[]metrics.TxStatus](pCtx, cap(blockQueue))

	// Pipeline the de-serialization process.
	go func() {
		for pCtx.Err() == nil {
			block, ok := committedBlock.Read()
			if !ok {
				return
			}
			processedBlocks.Write(mapToStatusBatch(block))
		}
	}()

	for pCtx.Err() == nil {
		statusBatch, ok := processedBlocks.Read()
		if !ok {
			return
		}
		res.Metrics.OnReceiveBatch(statusBatch)
		if res.isReceiveLimit() {
			return
		}
	}
}

// mapToStatusBatch creates a status batch from a given block.
func mapToStatusBatch(block *common.Block) []metrics.TxStatus {
	if block.Data == nil || len(block.Data.Data) == 0 {
		return nil
	}
	blockSize := len(block.Data.Data)

	var statusCodes []byte
	if block.Metadata != nil && len(block.Metadata.Metadata) > statusIdx {
		statusCodes = block.Metadata.Metadata[statusIdx]
	}
	logger.Infof(
		"Received block #%d with %d TXs and %d statuses [%s]",
		block.Header.Number, len(block.Data.Data), len(statusCodes), recapStatusCodes(statusCodes),
	)

	statusBatch := make([]metrics.TxStatus, 0, blockSize)
	for i, data := range block.Data.Data {
		envLite, err := serialization.UnwrapEnvelopeLite(data)
		if err != nil {
			logger.Warnf("Failed to unmarshal envelope: %v", err)
			continue
		}
		if common.HeaderType(envLite.HeaderType) == common.HeaderType_CONFIG {
			// We can ignore config transactions as we only count data transactions.
			continue
		}
		status := committerpb.Status_COMMITTED
		if len(statusCodes) > i {
			status = committerpb.Status(statusCodes[i])
		}
		statusBatch = append(statusBatch, metrics.TxStatus{
			TxID:   envLite.TxID,
			Status: status,
		})
	}
	return statusBatch
}

// recapStatusCodes recaps of the status codes of a block.
func recapStatusCodes(statusCodes []byte) string {
	codes := utils.CountAppearances(statusCodes)
	items := make([]string, 0, len(codes))
	for code, count := range codes {
		items = append(
			items,
			fmt.Sprintf("%s x %d", committerpb.Status(code).String(), count),
		)
	}
	return strings.Join(items, ", ")
}
