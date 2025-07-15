/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/utils"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/logging"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

type batchWithLatency struct {
	batch TxNodeBatch
	done  time.Time
}

//nolint:gocognit // single method for simplicity.
func BenchmarkDependencyGraph(b *testing.B) {
	logging.SetupWithConfig(&logging.Config{Enabled: false})

	// Parameters
	latency := 10 * time.Second
	batchSize := 1024

	testDependencies := make([]workload.DependencyDescription, 10)
	allDep := []string{workload.DependencyReadOnly, workload.DependencyReadWrite, workload.DependencyBlindWrite}
	// We start with one to have no dependencies.
	i := 1
	for _, src := range allDep {
		for _, dst := range allDep {
			testDependencies[i] = workload.DependencyDescription{
				Probability: 0.3,
				Gap:         workload.NewNormalDistribution(500, 10),
				Src:         src,
				Dst:         dst,
			}
			i++
		}
	}

	for idx, dep := range testDependencies {
		p := workload.DefaultProfile(8)
		name := "no-dep"
		if idx > 0 {
			p.Conflicts.Dependencies = []workload.DependencyDescription{dep}
			name = fmt.Sprintf("%s AND %s", dep.Src, dep.Dst)
		}

		b.Run(name, func(b *testing.B) {
			g := workload.StartGenerator(b, p)

			for _, item := range []struct {
				name    string
				exec    func(t testing.TB, c *Config)
				workers int
			}{
				{
					name:    "simple-dep-graph",
					exec:    startSimpleDependency,
					workers: 1,
				},
				{
					name:    "dep-graph-2",
					exec:    startDependencyManager,
					workers: 2,
				},
				{
					name:    "dep-graph-4",
					exec:    startDependencyManager,
					workers: 4,
				},
				{
					name:    "dep-graph-8",
					exec:    startDependencyManager,
					workers: 8,
				},
			} {
				b.Run(item.name, func(b *testing.B) {
					// The main queues.
					in := make(chan *TransactionBatch, 8)
					out := make(chan TxNodeBatch, 8)
					val := make(chan TxNodeBatch, 8)

					// Starts the dependency manager.
					item.exec(b, defaultManagerConfig(in, out, val, item.workers))

					outCtx := channel.NewReader(b.Context(), out)
					valCtx := channel.NewWriter(b.Context(), val)
					inCtx := channel.NewWriter(b.Context(), in)
					latencySimulatorQueue := channel.Make[*batchWithLatency](b.Context(), 1024*1024)

					// Simulates the batch processing latency.
					go func() {
						for b.Context().Err() == nil {
							wtl, ok := latencySimulatorQueue.Read()
							if !ok {
								return
							}
							waitFor := time.Until(wtl.done)
							if waitFor > 0 {
								select {
								case <-time.After(waitFor):
								case <-b.Context().Done():
								}
							}
							valCtx.Write(wtl.batch)
						}
					}()

					nums := utils.Range(0, uint32(batchSize)) //nolint:gosec // int -> uint32.
					b.ResetTimer()
					// Generates the load to the manager's queue.
					go func() {
						var i uint64
						for b.Context().Err() == nil {
							txs := g.NextN(b.Context(), batchSize)
							inCtx.Write(&TransactionBatch{
								ID:          i,
								BlockNumber: i,
								Txs:         txs,
								TxsNum:      nums,
							})
							i++
						}
					}()
					// Reads the output of the manager, and forward it to the latency simulator.
					var total int
					for total < b.N {
						batch, ok := outCtx.Read()
						if !ok {
							return
						}
						latencySimulatorQueue.Write(&batchWithLatency{
							batch: batch,
							done:  time.Now().Add(latency),
						})
						total += len(batch)
					}
					b.StopTimer()
				})
			}
		})
	}
}

func startDependencyManager(tb testing.TB, c *Config) {
	tb.Helper()
	m := NewManager(c)
	test.RunServiceForTest(tb.Context(), tb, func(ctx context.Context) error {
		m.Run(ctx)
		return nil
	}, nil)
}

func startSimpleDependency(tb testing.TB, c *Config) {
	tb.Helper()
	m := NewSimpleManager(c)
	test.RunServiceForTest(tb.Context(), tb, func(ctx context.Context) error {
		m.Run(ctx)
		return nil
	}, nil)
}

func defaultManagerConfig(in chan *TransactionBatch, out, val chan TxNodeBatch, workers int) *Config {
	return &Config{
		IncomingTxs:               in,
		OutgoingDepFreeTxsNode:    out,
		IncomingValidatedTxsNode:  val,
		NumOfLocalDepConstructors: workers,
		WaitingTxsLimit:           20_000_000,
		PrometheusMetricsProvider: monitoring.NewProvider(),
	}
}
