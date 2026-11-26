/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapters

import (
	"testing"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"

	"github.com/Chaguar/committer/loadgen/metrics"
	"github.com/Chaguar/committer/loadgen/workload"
	"github.com/Chaguar/committer/utils/signature"
	"github.com/Chaguar/committer/utils/test"
)

// BenchmarkSubmitPath measures the rate sendBlocks can offer with a sender that does nothing: generation
// plus the adapter's block mapping, TX ID extraction and send metrics. MapToOrdererBlock hashes every
// envelope, so it is the costliest mapper and the result bounds the mapping cost of every adapter.
// The settings are BenchmarkGenTx's at 128 workers; a rate below BenchmarkGenTx/<scheme>/workers-128
// means the single mapping goroutine, not signing, caps what the load generator can offer.
func BenchmarkSubmitPath(b *testing.B) {
	flogging.ActivateSpec("fatal")
	for _, scheme := range []signature.Scheme{signature.NoScheme, signature.Eddsa, signature.Ecdsa} {
		b.Run(scheme, func(b *testing.B) {
			profile := workload.DefaultProfile(128)
			profile.Block.MaxSize = 10_000
			profile.Policy.NamespacePolicies[workload.DefaultGeneratedNamespaceID].Scheme = scheme
			streamOptions := &workload.StreamOptions{BuffersSize: 100, GenBatch: 4096}

			txCounter := workload.NewTxCounter(profile.Transaction)
			txStream, err := workload.NewTxStream(profile, streamOptions, txCounter)
			require.NoError(b, err)
			ctx := b.Context()
			test.RunServiceForTest(ctx, b, txStream.Run, nil)

			limit := &GenerateLimit{}
			adapter := &commonAdapter{res: &ClientResources{
				Metrics: metrics.NewLoadgenServiceMetrics(&metrics.Config{}, txCounter, txStream),
				Profile: profile,
				// A one-block mapping queue: blocks mapped ahead of the limit are work the rate does not count.
				Stream: &workload.StreamOptions{BuffersSize: 1},
				Limit:  limit,
			}}
			stream := &workload.StreamWithSetup{TxStream: txStream}

			noOpSender := func(*common.Block) error { return nil }
			send := func(n uint64) uint64 {
				sentBefore := adapter.res.Metrics.GetState().TransactionsSent
				limit.Transactions = sentBefore + n
				require.NoError(b, sendBlocks(ctx, adapter, stream, workload.MapToOrdererBlock, noOpSender))
				return adapter.res.Metrics.GetState().TransactionsSent - sentBefore
			}

			// Warm up with one batch from every worker, as BenchmarkGenTx does, so the timer excludes startup.
			send(uint64(profile.Workers) * uint64(streamOptions.GenBatch))
			b.ResetTimer()
			sent := send(uint64(b.N)) //nolint:gosec // int -> uint64.
			b.StopTimer()
			// The sent count, not b.N: the limit is checked per block, so a run can overshoot it.
			b.ReportMetric(float64(sent)/b.Elapsed().Seconds(), "tx/s")
		})
	}
}
