/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package delivercommitter

import (
	"context"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// Start starts a delivery to fetch committed blocks from the sidecar/ledger service.
// p.NextBlockNum is updated with the latest block number.
// It returns a channel to receive the committed blocks.
func Start(ctx context.Context, t *testing.T, p Parameters) chan *common.Block {
	t.Helper()
	receivedBlocksFromLedgerService := make(chan *common.Block, 10)
	p.OutputBlock = receivedBlocksFromLedgerService
	test.RunServiceForTest(ctx, t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(ToQueue(ctx, p))
	}, nil)
	return receivedBlocksFromLedgerService
}
