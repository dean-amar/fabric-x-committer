package sidecarclient

import (
	"context"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/broadcastdeliver"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

// StartSidecarClient starts a deliver client to fetch committed blocks from the sidecar/ledger service.
func StartSidecarClient(
	ctx context.Context,
	t *testing.T,
	config *Config,
	startBlkNum int64,
) chan *common.Block {
	t.Helper()
	receivedBlocksFromLedgerService := make(chan *common.Block, 10)
	deliverClient, err := New(config)
	require.NoError(t, err)
	test.RunServiceForTest(ctx, t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(deliverClient.Deliver(ctx,
			&DeliverConfig{
				StartBlkNum: startBlkNum,
				EndBlkNum:   broadcastdeliver.MaxBlockNum,
				OutputBlock: receivedBlocksFromLedgerService,
			},
		))
	}, nil)
	return receivedBlocksFromLedgerService
}
