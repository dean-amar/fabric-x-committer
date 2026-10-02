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
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"golang.org/x/sync/errgroup"

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
	// Auth lists the auth service instances the delivery stream authenticates against, required when the
	// sidecar enforces ACL and nil otherwise: block delivery is a protected resource.
	Auth *connection.MultiClientConfig
	// Identity signs the authentication envelope. Passed in rather than read from the load profile because
	// each adapter holds a different one, and the profile's own policy identity is optional.
	Identity *ordererdial.IdentityConfig
}

const (
	committedBlocksQueueSize = 1024
	statusIdx                = int(common.BlockMetadataIndex_TRANSACTIONS_FILTER)
)

// runSidecarReceiver receives blocks from the sidecar. Block delivery is ACL-protected, so when an auth
// service is configured, every delivery stream - each reconnect included - carries a live token.
func runSidecarReceiver(ctx context.Context, params *sidecarReceiverParameters) error {
	var credentials *acl.Credentials
	if params.Auth != nil {
		authConn, err := connection.NewLoadBalancedConnection(params.Auth)
		if err != nil {
			return errors.Wrap(err, "failed to connect to the auth service")
		}
		defer connection.CloseConnectionsLog(authConn)

		issueParams, err := newIssueParams(params, servicepb.NewAuthServiceClient(authConn))
		if err != nil {
			return err
		}
		credentials = &acl.Credentials{Params: issueParams}
	}
	return runDeliveryReceiver(ctx, params.Res, func(gCtx context.Context, committedBlock chan *common.Block) error {
		return delivercommitter.ToQueue(gCtx, delivercommitter.Parameters{
			ClientConfig: params.ClientConfig,
			Credentials:  credentials,
			OutputBlock:  committedBlock,
		})
	})
}

// newIssueParams resolves the identity the delivery stream authenticates as.
func newIssueParams(
	params *sidecarReceiverParameters, client servicepb.AuthServiceClient,
) (*acl.IssueParams, error) {
	signer, err := ordererdial.NewIdentitySigner(params.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the signing identity")
	}
	if signer == nil {
		// No identity is configured, so sign with a peer identity from the generated crypto the
		// profile already points at; it satisfies the channel's Readers policy.
		identities, idErr := testcrypto.GetPeersIdentities(params.Res.Profile.Policy.ArtifactsPath)
		if idErr != nil {
			return nil, errors.Wrap(idErr, "failed to load a signing identity from the artifacts path")
		}
		if len(identities) == 0 {
			return nil, errors.New("an auth service is configured but no signing identity is available")
		}
		signer = identities[0]
	}
	// The token binds to the certificate the delivery stream presents, not the one used to reach the
	// auth service.
	certHash, err := acl.TLSCertHash(params.ClientConfig.TLS)
	if err != nil {
		return nil, err
	}
	return &acl.IssueParams{
		Client:      client,
		Signer:      signer,
		ChannelID:   params.Res.Profile.Policy.ChannelID,
		TLSCertHash: certHash,
	}, nil
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
