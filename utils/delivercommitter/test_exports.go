/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package delivercommitter

import (
	"context"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/msp"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// Start starts a delivery to fetch committed blocks from the sidecar/ledger service.
// p.NextBlockNum is updated with the latest block number.
// It returns a channel to receive the committed blocks.
//
// signer and channelID authorize the connection against the sidecar's ACL. Pass a nil
// signer for servers that do not enforce ACL (e.g. the bare block-store test server).
//
//nolint:revive // argument-limit: test helper mirrors delivercommitter.Parameters fields.
func Start(
	ctx context.Context,
	t *testing.T,
	conf *connection.ClientConfig,
	startBlockNum uint64,
	signer msp.SigningIdentity,
	channelID string,
) chan *common.Block {
	t.Helper()
	receivedBlocksFromLedgerService := make(chan *common.Block, 10)
	test.RunServiceForTest(ctx, t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(ToQueue(ctx, Parameters{
			ClientConfig: conf,
			OutputBlock:  receivedBlocksFromLedgerService,
			NextBlockNum: startBlockNum,
			Signer:       signer,
			ChannelID:    channelID,
		}))
	}, nil)
	return receivedBlocksFromLedgerService
}
