/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dependencygraph

import (
	"context"

	"github.com/cockroachdb/errors"
	"golang.org/x/sync/errgroup"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
)

// workerPool supports parallel task execution with predictable resource consumption.
type workerPool struct {
	parallelism int
	inputCh     chan WorkerExecutor
}

// WorkerExecutor function to execute.
type WorkerExecutor = func()

// newWorkerPool creates a new workerPool.
//   - parallelism: How many go routines will be launched and available for the executions.
//   - channelCapacity: The capacity of the waiting queue for routines that have been submitted,
//     but haven't found an available slot.
//
// If all available go routines (parallelism) are occupied with executions, then the buffer will start to fill.
// If (parallelism + channelCapacity) executions have been submitted (see workerPool.Execute),
// then workerPool.Execute will block execution until an execution completes and a slot becomes available.
func newWorkerPool(parallelism, channelCapacity int) *workerPool {
	if parallelism == 0 {
		panic("parallelism must be > 0")
	}
	return &workerPool{
		inputCh:     make(chan WorkerExecutor, channelCapacity),
		parallelism: parallelism,
	}
}

// run runs the workers.
func (w *workerPool) run(ctx context.Context) error {
	g, gCtx := errgroup.WithContext(ctx)
	for range w.parallelism {
		g.Go(func() error {
			return w.handleChannelInput(gCtx)
		})
	}
	return errors.Wrap(g.Wait(), "worker pool ended")
}

func (w *workerPool) handleChannelInput(ctx context.Context) error {
	inputCh := channel.NewReader(ctx, w.inputCh)
	for {
		item, ok := inputCh.Read()
		if !ok {
			return errors.Wrap(ctx.Err(), "context ended")
		}
		item()
	}
}

// Submit submits one function for execution in a go routine once a slot is available.
// Returns true if successful.
func (w *workerPool) Submit(ctx context.Context, work WorkerExecutor) bool {
	return channel.NewWriter(ctx, w.inputCh).Write(work)
}
