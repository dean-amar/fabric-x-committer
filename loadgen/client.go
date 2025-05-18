/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package loadgen

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"golang.org/x/sync/errgroup"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/adapters"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/metrics"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

type (
	// Client for applying load on the services.
	Client struct {
		conf      *ClientConfig
		txStream  *workload.TxStream
		resources adapters.ClientResources
		adapter   ServiceAdapter
	}

	// ServiceAdapter encapsulates the common interface for adapters.
	ServiceAdapter interface {
		// RunWorkload apply the generated workload.
		RunWorkload(ctx context.Context, txStream adapters.TxStream) error
		// Progress returns a value that indicates progress as the number grows.
		Progress() uint64
		// Supports specify which phases an adapter supports.
		Supports() adapters.Phases
	}

	// clientStream implements the TxStream interface.
	clientStream struct {
		workloadSetupTXs channel.Reader[*protoblocktx.Tx]
		txStream         *workload.TxStream
		blockSize        uint64
	}

	// clientBlockGenerator is a block generator that first submit blocks from the workloadSetupTXs,
	// and blocks until indicated that it was committed.
	// Then, it submits blocks from the tx stream.
	clientBlockGenerator struct {
		workloadSetupTXs channel.Reader[*protoblocktx.Tx]
		blockGen         *workload.BlockGenerator
	}

	// clientTxGenerator is a TX generator that first submit TXs from the workloadSetupTXs,
	// and blocks until indicated that it was committed.
	// Then, it submits transactions from the tx stream.
	clientTxGenerator struct {
		workloadSetupTXs channel.Reader[*protoblocktx.Tx]
		txGen            *workload.RateLimiterGenerator[*protoblocktx.Tx]
	}
)

var logger = logging.New("load-gen-client")

// NewLoadGenClient creates a new client instance.
func NewLoadGenClient(conf *ClientConfig) (*Client, error) {
	logger.Infof("Config passed: %s", &utils.LazyJSON{O: conf})

	c := &Client{
		conf:     conf,
		txStream: workload.NewTxStream(conf.LoadProfile, conf.Stream),
		resources: adapters.ClientResources{
			Profile: conf.LoadProfile,
			Limit:   conf.Limit,
		},
	}
	c.resources.Metrics = metrics.NewLoadgenServiceMetrics(&conf.Monitoring)

	adapter, err := getAdapter(&conf.Adapter, &c.resources)
	if err != nil {
		return nil, err
	}
	c.adapter = adapter
	conf.Generate = adapters.PhasesIntersect(conf.Generate, adapter.Supports())
	return c, nil
}

func getAdapter(conf *adapters.AdapterConfig, res *adapters.ClientResources) (ServiceAdapter, error) {
	switch {
	case conf.CoordinatorClient != nil:
		return adapters.NewCoordinatorAdapter(conf.CoordinatorClient, res), nil
	case conf.VCClient != nil:
		return adapters.NewVCAdapter(conf.VCClient, res), nil
	case conf.OrdererClient != nil:
		return adapters.NewOrdererAdapter(conf.OrdererClient, res), nil
	case conf.SidecarClient != nil:
		return adapters.NewSidecarAdapter(conf.SidecarClient, res), nil
	case conf.VerifierClient != nil:
		return adapters.NewSVAdapter(conf.VerifierClient, res), nil
	default:
		return nil, adapters.ErrInvalidAdapterConfig
	}
}

// Run applies load on the service.
func (c *Client) Run(ctx context.Context) error {
	logger.Infof("Starting workload generation")
	defer logger.Infof("End workload generation")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return c.resources.Metrics.StartPrometheusServer(gCtx, c.conf.Monitoring.Server)
	})
	g.Go(func() error {
		return c.txStream.Run(gCtx)
	})
	c.txStream.WaitForReady(gCtx)

	workloadSetupTXs := make(chan *protoblocktx.Tx, 1)
	cs := &clientStream{
		blockSize:        c.conf.LoadProfile.Block.Size,
		workloadSetupTXs: channel.NewReader(gCtx, workloadSetupTXs),
	}
	if c.conf.Generate.Load {
		cs.txStream = c.txStream
	}
	g.Go(func() error {
		defer cancel() // We should stop if the workload is over.
		return c.adapter.RunWorkload(gCtx, cs)
	})

	if err := c.submitWorkloadSetupTXs(gCtx, workloadSetupTXs); err != nil {
		logger.Errorf("Failed to process tx: %v", err)
		cancel()
		if gErr := g.Wait(); gErr != nil {
			return errors.Wrap(gErr, "failed to process TX")
		}
		return err
	}

	if !c.conf.Generate.Load {
		cancel()
	}
	return g.Wait()
}

// submitWorkloadSetupTXs writes the workload setup TXs to the channel, and waits for them to be committed.
func (c *Client) submitWorkloadSetupTXs(ctx context.Context, txs chan *protoblocktx.Tx) error {
	defer close(txs)

	workloadSetupTXs, err := makeWorkloadSetupTXs(c.conf)
	if err != nil {
		return err
	}

	txChan := channel.NewWriter(ctx, txs)
	curProgress := c.adapter.Progress()
	for _, tx := range workloadSetupTXs {
		logger.Infof("Submitting TX [%s]. Progress: %d", tx.Id, curProgress)
		if !txChan.Write(tx) {
			return errors.New("context ended before submitting TX")
		}

		for lastProgress := curProgress; curProgress == lastProgress; curProgress = c.adapter.Progress() {
			select {
			case <-ctx.Done():
				return errors.New("context ended before acknowledging TX")
			case <-time.Tick(time.Second):
			}
		}
		logger.Infof("TX [%s] submitted. Progress: %d", tx.Id, curProgress)
	}
	return nil
}

func makeWorkloadSetupTXs(config *ClientConfig) ([]*protoblocktx.Tx, error) {
	workloadSetupTXs := make([]*protoblocktx.Tx, 0, 2)
	if config.Generate.Config {
		configTX, err := workload.CreateConfigTx(config.LoadProfile.Transaction.Policy)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create a config tx")
		}
		workloadSetupTXs = append(workloadSetupTXs, configTX)
	}
	if config.Generate.Namespaces {
		metaNsTX, err := workload.CreateNamespacesTX(config.LoadProfile.Transaction.Policy)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create namespaces meta tx")
		}
		workloadSetupTXs = append(workloadSetupTXs, metaNsTX)
	}
	return workloadSetupTXs, nil
}

// MakeBlocksGenerator instantiate clientBlockGenerator.
func (c *clientStream) MakeBlocksGenerator() workload.Generator[*protocoordinatorservice.Block] {
	cg := &clientBlockGenerator{
		workloadSetupTXs: c.workloadSetupTXs,
	}
	if c.txStream != nil {
		cg.blockGen = &workload.BlockGenerator{
			TxGenerator: c.txStream.MakeGenerator(),
			BlockSize:   c.blockSize,
		}
	}
	return cg
}

// MakeTxGenerator instantiate clientTxGenerator.
func (c *clientStream) MakeTxGenerator() workload.Generator[*protoblocktx.Tx] {
	cg := &clientTxGenerator{
		workloadSetupTXs: c.workloadSetupTXs,
	}
	if c.txStream != nil {
		cg.txGen = c.txStream.MakeGenerator()
	}
	return cg
}

// Next generate the next block.
func (g *clientBlockGenerator) Next() *protocoordinatorservice.Block {
	if g.workloadSetupTXs != nil {
		if tx, ok := g.workloadSetupTXs.Read(); ok {
			return &protocoordinatorservice.Block{
				Txs:    []*protoblocktx.Tx{tx},
				TxsNum: []uint32{0},
			}
		}
		g.workloadSetupTXs = nil
	}
	if g.blockGen != nil {
		return g.blockGen.Next()
	}
	return nil
}

// Next generate the next TX.
func (g *clientTxGenerator) Next() *protoblocktx.Tx {
	if g.workloadSetupTXs != nil {
		if tx, ok := g.workloadSetupTXs.Read(); ok {
			return tx
		}
		g.workloadSetupTXs = nil
	}
	if g.txGen != nil {
		return g.txGen.Next()
	}
	return nil
}
