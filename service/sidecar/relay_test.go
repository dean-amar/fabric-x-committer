/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/mock"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

type relayTestEnv struct {
	relay                      *relay
	coordinator                *mock.Coordinator
	incomingBlockToBeCommitted chan *common.Block
	committedBlock             chan *common.Block
	configBlocks               []*common.Block
	metrics                    *perfMetrics
	waitingTxsLimit            int
}

const (
	valid     = byte(protoblocktx.Status_COMMITTED)
	duplicate = byte(protoblocktx.Status_ABORTED_DUPLICATE_TXID)
)

func newRelayTestEnv(t *testing.T) *relayTestEnv {
	t.Helper()
	coord, coordinatorServer := mock.StartMockCoordinatorService(t)
	coordinatorEndpoint := coordinatorServer.Configs[0].Endpoint

	metrics := newPerformanceMetrics()
	relayService := newRelay(
		time.Second,
		metrics,
	)

	conn, err := connection.Connect(connection.NewInsecureDialConfig(&coordinatorEndpoint))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })

	logger.Infof("sidecar connected to coordinator at %s", &coordinatorEndpoint)

	env := &relayTestEnv{
		relay:                      relayService,
		coordinator:                coord,
		incomingBlockToBeCommitted: make(chan *common.Block, 10),
		committedBlock:             make(chan *common.Block, 10),
		metrics:                    metrics,
		waitingTxsLimit:            100,
	}

	client := protocoordinatorservice.NewCoordinatorClient(conn)
	test.RunServiceForTest(t.Context(), t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(relayService.run(ctx, &relayRunConfig{
			coordClient:                    client,
			nextExpectedBlockByCoordinator: 0,
			configUpdater: func(block *common.Block) {
				env.configBlocks = append(env.configBlocks, block)
			},
			incomingBlockToBeCommitted: env.incomingBlockToBeCommitted,
			outgoingCommittedBlock:     env.committedBlock,
			waitingTxsLimit:            env.waitingTxsLimit,
		}))
	}, nil)
	return env
}

func TestRelayNormalBlock(t *testing.T) {
	t.Parallel()
	relayEnv := newRelayTestEnv(t)
	relayEnv.coordinator.SetDelay(10 * time.Second)

	blk0 := createBlockForTest(0, nil, [3]string{"tx1", "tx2", "tx3"})
	require.Nil(t, blk0.Metadata)
	relayEnv.incomingBlockToBeCommitted <- blk0

	promutil.EventuallyIntMetric(t, 3, relayEnv.metrics.transactionsSentTotal,
		5*time.Second, 10*time.Millisecond)
	promutil.EventuallyIntMetric(t, 3, relayEnv.metrics.waitingTransactionsQueueSize,
		5*time.Second, 10*time.Millisecond)
	require.Equal(t, int64(relayEnv.waitingTxsLimit-3), relayEnv.relay.waitingTxsSlots.Load(t))

	committedBlock0 := <-relayEnv.committedBlock
	promutil.RequireIntMetricValue(t, 3, relayEnv.metrics.transactionsStatusReceivedTotal.WithLabelValues(
		protoblocktx.Status_COMMITTED.String(),
	))
	promutil.EventuallyIntMetric(t, 0, relayEnv.metrics.waitingTransactionsQueueSize,
		5*time.Second, 10*time.Millisecond)
	require.Equal(t, int64(relayEnv.waitingTxsLimit), relayEnv.relay.waitingTxsSlots.Load(t))

	expectedMetadata := &common.BlockMetadata{
		Metadata: [][]byte{nil, nil, {valid, valid, valid}},
	}
	require.Equal(t, expectedMetadata, committedBlock0.Metadata)
	require.Equal(t, blk0, committedBlock0)

	m := relayEnv.metrics
	require.Greater(t, promutil.GetMetricValue(t, m.blockMappingInRelaySeconds), float64(0))
	require.Greater(t, promutil.GetMetricValue(t, m.mappedBlockProcessingInRelaySeconds), float64(0))
	require.Greater(t, promutil.GetMetricValue(t, m.transactionStatusesProcessingInRelaySeconds), float64(0))

	relayEnv.relay.waitingTxsSlots.Store(t, int64(0))
	blk1 := createBlockForTest(1, nil, [3]string{"tx1", "tx2", "tx3"})
	relayEnv.incomingBlockToBeCommitted <- blk1
	require.Never(t, func() bool {
		return promutil.GetMetricValue(t, m.transactionsSentTotal) > 3
	}, 3*time.Second, 1*time.Second)
	relayEnv.relay.waitingTxsSlots.Store(t, int64(3))
	relayEnv.relay.waitingTxsSlots.Broadcast()
	promutil.EventuallyIntMetric(t, 6, relayEnv.metrics.transactionsSentTotal, 5*time.Second, 10*time.Millisecond)
}

func TestBlockWithDuplicateTransactions(t *testing.T) {
	t.Parallel()
	relayEnv := newRelayTestEnv(t)
	blk0 := createBlockForTest(0, nil, [3]string{"tx1", "tx1", "tx1"})
	require.Nil(t, blk0.Metadata)
	relayEnv.incomingBlockToBeCommitted <- blk0
	committedBlock0 := <-relayEnv.committedBlock
	expectedMetadata := &common.BlockMetadata{
		Metadata: [][]byte{nil, nil, {valid, duplicate, duplicate}},
	}
	require.Equal(t, expectedMetadata, committedBlock0.Metadata)
	require.Equal(t, blk0, committedBlock0)

	blk1 := createBlockForTest(1, nil, [3]string{"tx2", "tx3", "tx2"})
	require.Nil(t, blk1.Metadata)
	relayEnv.incomingBlockToBeCommitted <- blk1
	committedBlock1 := <-relayEnv.committedBlock
	expectedMetadata = &common.BlockMetadata{
		Metadata: [][]byte{nil, nil, {valid, valid, duplicate}},
	}
	require.Equal(t, expectedMetadata, committedBlock1.Metadata)
	require.Equal(t, blk1, committedBlock1)
}

func TestRelayConfigBlock(t *testing.T) {
	t.Parallel()
	relayEnv := newRelayTestEnv(t)
	configBlk := createConfigBlockForTest(nil, 0)
	relayEnv.incomingBlockToBeCommitted <- configBlk
	committedBlock := <-relayEnv.committedBlock
	require.Equal(t, configBlk, committedBlock)
	require.Equal(t, &common.BlockMetadata{
		Metadata: [][]byte{nil, nil, {valid}},
	}, committedBlock.Metadata)
	require.Len(t, relayEnv.configBlocks, 1)
	require.Equal(t, configBlk, relayEnv.configBlocks[0])
}

func createConfigBlockForTest(_ *testing.T, number uint64) *common.Block {
	data := protoutil.MarshalOrPanic(&common.Envelope{
		Payload: protoutil.MarshalOrPanic(&common.Payload{
			Header: &common.Header{
				ChannelHeader: protoutil.MarshalOrPanic(&common.ChannelHeader{
					Type: int32(common.HeaderType_CONFIG),
				}),
			},
		},
		),
	},
	)

	return &common.Block{
		Header: &common.BlockHeader{Number: number},
		Data:   &common.BlockData{Data: [][]byte{data}},
	}
}

// createBlockForTest creates sample block with three txIDs.
func createBlockForTest(number uint64, preBlockHash []byte, txIDs [3]string) *common.Block {
	return &common.Block{
		Header: &common.BlockHeader{
			Number:       number,
			PreviousHash: preBlockHash,
		},
		Data: &common.BlockData{
			Data: [][]byte{
				createEnvelopeBytesForTest(txIDs[0]),
				createEnvelopeBytesForTest(txIDs[1]),
				createEnvelopeBytesForTest(txIDs[2]),
			},
		},
	}
}

func createEnvelopeBytesForTest(txID string) []byte {
	header := &common.Header{
		ChannelHeader: protoutil.MarshalOrPanic(&common.ChannelHeader{
			ChannelId: "ch1",
			TxId:      txID,
			Type:      int32(common.HeaderType_MESSAGE),
		}),
	}
	return protoutil.MarshalOrPanic(&common.Envelope{
		Payload: protoutil.MarshalOrPanic(&common.Payload{
			Header: header,
			Data:   protoutil.MarshalOrPanic(&protoblocktx.Tx{Id: txID}),
		}),
	})
}
