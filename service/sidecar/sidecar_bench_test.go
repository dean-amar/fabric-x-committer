/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/Chaguar/common/api/committerpb"
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/Chaguar/committer/api/servicepb"
	"github.com/Chaguar/committer/loadgen/workload"
	"github.com/Chaguar/committer/mock"
	"github.com/Chaguar/committer/utils/channel"
	"github.com/Chaguar/committer/utils/connection"
	"github.com/Chaguar/committer/utils/serve"
	"github.com/Chaguar/committer/utils/test"
)

// BenchmarkSidecarEndToEnd measures the whole sidecar on one machine: delivery with signature
// verification, mapping, a real gRPC stream to the coordinator, status collection and the ledger
// append. Only the orderer and the coordinator are stubbed. b.N counts transactions, all of which
// are built before the timer starts and held in memory for the run, about 700 bytes each.
func BenchmarkSidecarEndToEnd(b *testing.B) {
	flogging.ActivateSpec("fatal")
	// The ledger knobs show what the append path costs: sync-interval=1 is the default (fsync every
	// block), 100 is a deployment tuned for throughput; the TX ID index adds an entry per transaction.
	for _, blockSize := range []int{100, 500, 1_000, 5_000, 10_000} {
		for _, syncInterval := range []uint64{1, 100} {
			for _, txIDIndex := range []bool{false, true} {
				name := fmt.Sprintf("blockSize=%d/sync-interval=%d/tx-id-index=%v", blockSize, syncInterval, txIDIndex)
				b.Run(name, func(b *testing.B) {
					benchmarkSidecarEndToEnd(b, blockSize, LedgerConfig{
						Path:             b.TempDir(),
						SyncInterval:     syncInterval,
						DisableTxIDIndex: !txIDIndex,
					})
				})
			}
		}
	}
}

func benchmarkSidecarEndToEnd(b *testing.B, blockSize int, ledger LedgerConfig) {
	b.Helper()
	blocks := generateBenchBlocks(b, b.N, blockSize)

	coordinator := test.ServeManyForTest(b.Context(), b, test.StartServerParameters{NumService: 1},
		&benchCoordinator{healthcheck: serve.DefaultHealthCheckService()})
	ordererEnv := mock.NewOrdererTestEnv(b, &mock.OrdererTestParameters{
		ChanID: "bench",
		NumIDs: 1,
		OrdererConfig: &mock.OrdererConfig{
			// Blocks are submitted whole with their data hash, so the orderer only numbers and
			// signs them.
			BlockSize:      1,
			BlockTimeout:   time.Hour,
			PrepareInPlace: true,
			// The ring holds the whole run, since a ring that wraps loses blocks (#911).
			OutBlockCapacity: len(blocks) + 1,
			SendGenesisBlock: true,
		},
	})
	sidecar, err := New(&Config{
		Committer: test.NewTLSClientConfig(connection.TLSConfig{}, &coordinator.Configs[0].GRPC.Endpoint),
		Ledger:    ledger,
		Notification: NotificationServiceConfig{
			MaxTimeout:         time.Minute,
			MaxActiveTxIDs:     100_000,
			MaxTxIDsPerRequest: 1_000,
			StreamWriteTimeout: 30 * time.Second,
		},
		LastCommittedBlockSetInterval: time.Second,
		// Large enough that the relay never waits on the stub coordinator.
		WaitingTxsLimit:   500_000,
		ChannelBufferSize: 20,
		Orderer:           ordererEnv.OrdererConnConfig,
	})
	require.NoError(b, err)
	done := test.RunServiceAndServeForTest(b.Context(), b, sidecar,
		test.NewLocalHostServiceConfig(connection.TLSConfig{}))

	// The genesis block is block 0; waiting for it keeps start-up out of the measurement.
	awaitLedgerHeight(b, sidecar, done, 1)
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()
	b.ResetTimer()
	go func() {
		for _, blk := range blocks {
			if ordererEnv.Orderer.SubmitBlock(ctx, blk) != nil {
				return
			}
		}
	}()
	awaitLedgerHeight(b, sidecar, done, uint64(len(blocks))+1)
	b.StopTimer()
	test.ReportTxPerSecond(b)
}

// benchCoordinator echoes COMMITTED for every TX, one status batch per batch received.
// mock.Coordinator shuffles and chunks statuses and tracks TX IDs behind one mutex, which costs more
// per TX than the sidecar does.
type benchCoordinator struct {
	servicepb.UnimplementedCoordinatorServer
	healthcheck *health.Server
}

// RegisterService registers the stub's gRPC services.
func (c *benchCoordinator) RegisterService(s serve.Servers) {
	servicepb.RegisterCoordinatorServer(s.GRPC, c)
	healthgrpc.RegisterHealthServer(s.GRPC, c.healthcheck)
}

// BlockProcessing echoes a COMMITTED status for every TX it receives.
func (*benchCoordinator) BlockProcessing(
	stream grpc.BidiStreamingServer[servicepb.CoordinatorBatch, servicepb.TxStatusBatch],
) error {
	for stream.Context().Err() == nil {
		batch, err := stream.Recv()
		if err != nil {
			return errors.Wrap(err, "failed to receive a batch")
		}
		results := make([]*servicepb.TxResult, 0, len(batch.Txs)+len(batch.Rejected))
		for _, status := range batch.Rejected {
			results = append(results, &servicepb.TxResult{Status: status})
		}
		for _, tx := range batch.Txs {
			results = append(results, &servicepb.TxResult{
				Status: &committerpb.TxStatus{Ref: tx.Ref, Status: committerpb.Status_COMMITTED},
			})
		}
		if err := stream.Send(&servicepb.TxStatusBatch{TxResult: results}); err != nil {
			return errors.Wrap(err, "failed to send statuses")
		}
	}
	return errors.Wrap(stream.Context().Err(), "context ended")
}

// GetNextBlockNumberToCommit reports an empty ledger, so the sidecar has nothing to recover.
func (*benchCoordinator) GetNextBlockNumberToCommit(
	context.Context, *emptypb.Empty,
) (*servicepb.BlockRef, error) {
	return &servicepb.BlockRef{Number: 0}, nil
}

// NoPendingTransactionProcessing reports an idle coordinator.
func (*benchCoordinator) NoPendingTransactionProcessing(
	context.Context, *emptypb.Empty,
) (*wrapperspb.BoolValue, error) {
	return wrapperspb.Bool(true), nil
}

// SetLastCommittedBlockNumber discards the sidecar's periodic progress report.
func (*benchCoordinator) SetLastCommittedBlockNumber(
	context.Context, *servicepb.BlockRef,
) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// generateBenchBlocks builds txCount transactions on every core and groups them into blocks of at
// most blockSize. The generators are stopped before it returns, so they don't compete with the
// sidecar for CPU while the timer runs.
func generateBenchBlocks(b *testing.B, txCount, blockSize int) []*common.Block {
	b.Helper()
	profile := benchTxProfile()
	profile.Workers = uint32(runtime.NumCPU()) //nolint:gosec // int -> uint32.
	stream, err := workload.NewTxStream(profile, &workload.StreamOptions{BuffersSize: 10, GenBatch: 1024},
		workload.NewTxCounter(profile.Transaction))
	require.NoError(b, err)
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()
	streamDone := test.RunServiceForTest(ctx, b, stream.Run, nil)
	generator := stream.MakeGenerator()

	blocks := make([]*common.Block, 0, (txCount+blockSize-1)/blockSize)
	for remaining := txCount; remaining > 0; {
		n := uint64(min(blockSize, remaining)) //nolint:gosec // int -> uint64.
		txs := generator.Consume(ctx, workload.ConsumeParameters{RequestedItems: n, MinItems: n})
		require.NotEmpty(b, txs)
		// The orderer prepares the block in place, numbering it and reusing this data hash.
		blocks = append(blocks, workload.MapToOrdererBlock(0, txs))
		remaining -= len(txs)
	}
	cancel()
	streamDone.WaitForReady(b.Context())
	return blocks
}

// awaitLedgerHeight waits until the ledger reaches height, failing if the sidecar stops first.
func awaitLedgerHeight(b *testing.B, sidecar *Service, done *channel.Ready, height uint64) {
	b.Helper()
	for sidecar.blockStore.GetBlockHeight() < height {
		ctx, cancel := context.WithTimeout(b.Context(), time.Millisecond)
		stopped := done.WaitForReady(ctx)
		cancel()
		if stopped {
			b.Fatalf("the sidecar stopped at ledger height %d of %d", sidecar.blockStore.GetBlockHeight(), height)
		}
	}
}
