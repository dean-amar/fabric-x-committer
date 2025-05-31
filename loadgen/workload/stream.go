/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package workload

import (
	"context"
	"math/rand"

	"github.com/cockroachdb/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoqueryservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
)

type (
	// TxStream yields transactions from the  stream.
	TxStream struct {
		stream
		gens  []*txModifierDecorator
		queue chan []*protoblocktx.Tx
	}

	// QueryStream generates stream's queries consumers.
	QueryStream struct {
		stream
		gen   []*QueryGenerator
		queue chan []*protoqueryservice.Query
	}

	stream struct {
		options *StreamOptions
		ready   *channel.Ready
		limiter *rate.Limiter
	}
)

// NewTxStream creates workers that generates transactions into a queue and apply the modifiers.
// Each worker will have a unique instance of the modifier to avoid concurrency issues.
// The modifiers will be applied in the order they are given.
// A transaction modifier can modify any of its fields to adjust the workload.
// For example, a modifier can query the database for the read-set versions to simulate a real transaction.
// The signature modifier is applied last so all previous modifications will be signed correctly.
func NewTxStream(
	profile *Profile,
	options *StreamOptions,
	modifierGenerators ...Generator[Modifier],
) *TxStream {
	signer := NewTxSignerVerifier(profile.Transaction.Policy)
	txStream := &TxStream{stream: newStream(profile, options)}
	for _, w := range makeWorkersData(profile) {
		modifiers := make([]Modifier, 0, len(modifierGenerators)+2)
		if len(profile.Conflicts.Dependencies) > 0 {
			modifiers = append(modifiers, newTxDependenciesModifier(NewRandFromSeedGenerator(w.seed), profile))
		}
		for _, mod := range modifierGenerators {
			modifiers = append(modifiers, mod.Next())
		}
		// The signer must be the last modifier.
		modifiers = append(modifiers, newSignTxModifier(NewRandFromSeedGenerator(w.seed), signer, profile))

		txGen := newIndependentTxGenerator(NewRandFromSeedGenerator(w.seed), w.keyGen, &profile.Transaction)
		modGen := newTxModifierTxDecorator(txGen, modifiers...)
		txStream.gens = append(txStream.gens, modGen)
	}
	return txStream
}

// Run starts the stream workers.
func (s *TxStream) Run(ctx context.Context) error {
	logger.Debugf("Starting %d workers to generate load", len(s.gens))

	s.queue = make(chan []*protoblocktx.Tx, max(s.options.BuffersSize, 1))
	defer func() {
		// It is safe to close the channel as we only exit this method once all the ingesters are done.
		close(s.queue)
	}()
	s.ready.SignalReady()

	g, gCtx := errgroup.WithContext(ctx)
	for _, gen := range s.gens {
		g.Go(func() error {
			ingestBatchesToQueue(gCtx, s.queue, gen, int(s.options.GenBatch))
			return nil
		})
	}
	return errors.Wrap(g.Wait(), "stream finished")
}

// MakeGenerator creates a new generator that consumes from the stream.
// Each generator must be used from a single goroutine, but different
// generators from the same Stream can be used concurrently.
func (s *TxStream) MakeGenerator() *RateLimiterGenerator[*protoblocktx.Tx] {
	return &RateLimiterGenerator[*protoblocktx.Tx]{
		Chan:    s.queue,
		Limiter: s.limiter,
	}
}

// NewQueryGenerator creates workers that generates queries into a queue.
func NewQueryGenerator(profile *Profile, options *StreamOptions) *QueryStream {
	qs := &QueryStream{stream: newStream(profile, options)}
	for _, w := range makeWorkersData(profile) {
		queryGen := newQueryGenerator(NewRandFromSeedGenerator(w.seed), w.keyGen, profile)
		qs.gen = append(qs.gen, queryGen)
	}
	return qs
}

// Run starts the workers.
func (s *QueryStream) Run(ctx context.Context) error {
	logger.Debugf("Starting %d workers to generate query load", len(s.gen))

	s.queue = make(chan []*protoqueryservice.Query, max(s.options.BuffersSize, 1))
	defer func() {
		// It is safe to close the channel as we only exit this method once all the ingesters are done.
		close(s.queue)
	}()
	s.ready.SignalReady()

	g, gCtx := errgroup.WithContext(ctx)
	for _, gen := range s.gen {
		g.Go(func() error {
			ingestBatchesToQueue(gCtx, s.queue, gen, int(s.options.GenBatch))
			return nil
		})
	}
	return errors.Wrap(g.Wait(), "stream finished")
}

// MakeGenerator creates a new generator that consumes from the stream.
// Each generator must be used from a single goroutine, but different
// generators from the same Stream can be used concurrently.
func (s *QueryStream) MakeGenerator() *RateLimiterGenerator[*protoqueryservice.Query] {
	return &RateLimiterGenerator[*protoqueryservice.Query]{
		Chan:    s.queue,
		Limiter: s.limiter,
	}
}

type workerData struct {
	seed   *rand.Rand
	keyGen *ByteArrayGenerator
}

func makeWorkersData(profile *Profile) []workerData {
	seedGen := rand.New(rand.NewSource(profile.Seed))
	workers := make([]workerData, max(profile.Workers, 1))
	for i := range workers {
		seed := NewRandFromSeedGenerator(seedGen)
		// Each worker has a unique seed to generate keys in addition the seed for the other content.
		// This allows reproducing the generated keys regardless of the other generated content.
		// It is useful when generating transactions, and later generating queries for the same keys.
		keySeed := NewRandFromSeedGenerator(seed)
		workers[i] = workerData{
			seed:   seed,
			keyGen: &ByteArrayGenerator{Size: profile.Key.Size, Rnd: keySeed},
		}
	}
	return workers
}

func ingestBatchesToQueue[T any](ctx context.Context, c chan<- []T, g Generator[T], batchSize int) {
	batchGen := &MultiGenerator[T]{
		Gen:   g,
		Count: &ConstGenerator[int]{Const: max(batchSize, 1)},
	}
	q := channel.NewWriter(ctx, c)
	for q.Write(batchGen.Next()) {
	}
}

func newStream(profile *Profile, options *StreamOptions) stream {
	// We allow bursting with a full block.
	// We also need to support bursting with the size of the generated batch
	// as we fetch the entire batch regardless of the block size.
	burst := max(int(options.GenBatch), int(profile.Block.Size)) //nolint:gosec // uint64 -> int.
	return stream{
		options: options,
		ready:   channel.NewReady(),
		limiter: NewLimiter(options.RateLimit, burst),
	}
}

// WaitForReady waits for the service resources to initialize, so it is ready to answers requests.
// If the context ended before the service is ready, returns false.
func (s *stream) WaitForReady(ctx context.Context) bool {
	return s.ready.WaitForReady(ctx)
}
