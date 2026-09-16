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
	"github.com/hyperledger/fabric-x-common/protoutil"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/loadgen/metrics"
	"github.com/hyperledger/fabric-x-committer/utils"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
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
	// Auth is the auth service the delivery stream authenticates against. It is required when the
	// sidecar enforces ACL, and nil otherwise: block delivery is a protected resource, so without a
	// token an enforcing sidecar answers PermissionDenied.
	Auth *connection.ClientConfig
	// Identity signs the authentication envelope. It is passed in rather than taken from the load
	// profile because each adapter holds a different one, and the profile's own policy identity is
	// optional - the shipped sample leaves it unset and configures the orderer client's instead.
	Identity *ordererdial.IdentityConfig
}

const (
	committedBlocksQueueSize = 1024
	statusIdx                = int(common.BlockMetadataIndex_TRANSACTIONS_FILTER)
)

// runSidecarReceiver start receiving blocks from the sidecar. When an auth service is configured the
// stream authenticates against it: block delivery is an ACL-protected resource, so an enforcing sidecar
// answers PermissionDenied without a token.
func runSidecarReceiver(ctx context.Context, params *sidecarReceiverParameters) error {
	var creds credentials.PerRPCCredentials
	if params.Auth != nil {
		// The auth connection outlives every RPC on the stream: the token source re-authenticates on it
		// whenever the cached token nears expiry.
		authConn, err := connection.NewSingleConnection(params.Auth)
		if err != nil {
			return errors.Wrap(err, "failed to connect to the auth service")
		}
		defer connection.CloseConnectionsLog(authConn)

		signer, err := ordererdial.NewIdentitySigner(params.Identity)
		if err != nil {
			return errors.Wrap(err, "failed to create the signing identity")
		}
		if signer == nil {
			return errors.New("an auth service is configured but no signing identity is available")
		}
		tlsCreds, err := connection.NewClientTLSCredentials(params.ClientConfig.TLS)
		if err != nil {
			return errors.Wrap(err, "failed to load the delivery client TLS credentials")
		}
		// Only mutual TLS puts a certificate on the connection, which is what binds the token to it.
		var certHash []byte
		if tlsCreds.Mode == connection.MutualTLSMode {
			certHash, err = protoutil.HashTLSCertificate(tlsCreds.Cert)
			if err != nil {
				return errors.Wrap(err, "failed to hash the delivery client certificate")
			}
		}
		// The token is minted once, here: it must outlive the run, so the AuthService's token-ttl has
		// to cover it. An expired token is rejected by the sidecar rather than silently renewed.
		creds, err = acl.MintToken(ctx, &acl.MintParams{
			Client:              servicepb.NewAuthServiceClient(authConn),
			Signer:              signer,
			ChannelID:           params.Res.Profile.Policy.ChannelID,
			TLSCertHash:         certHash,
			SecureTransportOnly: tlsCreds.Mode != connection.NoneTLSMode,
		})
		if err != nil {
			return err
		}
	}

	return runDeliveryReceiver(ctx, params.Res, func(gCtx context.Context, committedBlock chan *common.Block) error {
		return delivercommitter.ToQueue(gCtx, delivercommitter.Parameters{
			ClientConfig: params.ClientConfig,
			OutputBlock:  committedBlock,
			Credentials:  creds,
		})
	})
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
