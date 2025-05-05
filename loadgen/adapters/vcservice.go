package adapters

import (
	"context"

	"github.com/cockroachdb/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials/insecure"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protovcservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/metrics"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

type (
	// VcAdapter applies load on the VC.
	VcAdapter struct {
		commonAdapter
		config *VCClientConfig
	}
)

// NewVCAdapter instantiate VcAdapter.
func NewVCAdapter(config *VCClientConfig, res *ClientResources) *VcAdapter {
	return &VcAdapter{
		commonAdapter: commonAdapter{res: res},
		config:        config,
	}
}

// RunWorkload applies load on the VC.
func (c *VcAdapter) RunWorkload(ctx context.Context, txStream TxStream) error {
	connections, connErr := connection.OpenConnections(c.config.Endpoints, insecure.NewCredentials())
	if connErr != nil {
		return errors.Wrap(connErr, "failed opening connection to vc-service")
	}
	defer connection.CloseConnectionsLog(connections...)

	streams := make([]protovcservice.ValidationAndCommitService_StartValidateAndCommitStreamClient, 0, len(connections))
	for i, conn := range connections {
		client := protovcservice.NewValidationAndCommitServiceClient(conn)
		_, err := client.SetupSystemTablesAndNamespaces(ctx, nil)
		if err != nil {
			return errors.Wrap(err, "failed to setup system tables and namespaces")
		}
		if i == 0 {
			if lastBlockNum, err := client.GetLastCommittedBlockNumber(ctx, nil); err != nil {
				// We do not return error as we can proceed assuming no blocks were committed.
				logger.Infof("failed getting last committed block number: %v", err)
			} else {
				c.nextBlockNum.Store(lastBlockNum.Number + 1)
			}
		}

		logger.Info("Opening VC stream")
		stream, streamErr := client.StartValidateAndCommitStream(ctx)
		if streamErr != nil {
			return errors.Wrapf(streamErr, "failed opening stream to %s", conn.Target())
		}
		streams = append(streams, stream)
	}

	dCtx, dCancel := context.WithCancel(ctx)
	defer dCancel()
	g, gCtx := errgroup.WithContext(dCtx)
	for _, stream := range streams {
		g.Go(func() error {
			return c.sendBlocks(ctx, txStream, func(block *protocoordinatorservice.Block) error {
				return stream.Send(mapVCBatch(block))
			})
		})
		g.Go(func() error {
			defer dCancel() // We stop sending if we can't track the received items.
			return c.receiveStatus(gCtx, stream)
		})
	}
	return errors.Wrap(g.Wait(), "workload done")
}

func (c *VcAdapter) receiveStatus(
	ctx context.Context, stream protovcservice.ValidationAndCommitService_StartValidateAndCommitStreamClient,
) error {
	for ctx.Err() == nil {
		responseBatch, err := stream.Recv()
		if err != nil {
			return errors.Wrap(connection.FilterStreamRPCError(err), "failed receiving response batch")
		}

		logger.Debugf("Received VC batch with %d items", len(responseBatch.Status))

		statusBatch := make([]metrics.TxStatus, 0, len(responseBatch.Status))
		for id, status := range responseBatch.Status {
			statusBatch = append(statusBatch, metrics.TxStatus{TxID: id, Status: status.Code})
		}
		c.res.Metrics.OnReceiveBatch(statusBatch)
		if c.res.isReceiveLimit() {
			return nil
		}
	}
	return nil
}

func mapVCBatch(block *protocoordinatorservice.Block) *protovcservice.TransactionBatch {
	txs := make([]*protovcservice.Transaction, len(block.Txs))
	for i, tx := range block.Txs {
		txs[i] = &protovcservice.Transaction{
			ID:          tx.Id,
			Namespaces:  tx.Namespaces,
			BlockNumber: block.Number,
			TxNum:       block.TxsNum[i],
		}
	}
	return &protovcservice.TransactionBatch{Transactions: txs}
}
