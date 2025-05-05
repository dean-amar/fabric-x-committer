package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protocoordinatorservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

var logger = logging.New("tracker")

// latencyReceiverSender is used to track TX E2E latency.
type latencyReceiverSender struct {
	latencyTracker utils.SyncMap[string, time.Time]
	validLatency   prometheus.Histogram
	invalidLatency prometheus.Histogram
	blockSampler   NumberTracingSampler
	txSampler      KeyTracingSampler
}

// onReceiveTransaction is called when a TX is received.
//
//nolint:revive // parameter 'success' seems to be a control flag, but it is not.
func (c *latencyReceiverSender) onReceiveTransaction(txID string, success bool) {
	start, loaded := c.latencyTracker.LoadAndDelete(txID)
	if !loaded {
		return
	}
	logger.Debugf("Tracked transaction %s returned with status: %v", txID, success)
	duration := time.Since(start).Seconds()
	if success {
		c.validLatency.Observe(duration)
	} else {
		c.invalidLatency.Observe(duration)
	}
}

// onSendBlock is called when a block is submitted.
func (c *latencyReceiverSender) onSendBlock(block *protocoordinatorservice.Block) {
	logger.Debugf("Sent block [%d:%d]", block.Number, len(block.Txs))
	if !c.blockSampler(block.Number) {
		return
	}
	logger.Debugf("Block [%d:%d] is tracked.", block.Number, len(block.Txs))
	t := time.Now()
	for _, tx := range block.Txs {
		c.latencyTracker.Store(tx.Id, t)
	}
}

// onSendTransaction is called when a TX is submitted.
func (c *latencyReceiverSender) onSendTransaction(txID string) {
	if c.txSampler(txID) {
		c.latencyTracker.Store(txID, time.Now())
	}
}
