/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cockroachdb/errors"
	"github.com/jackc/puddle"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yugabyte/pgx/v4/pgxpool"
	"go.uber.org/zap"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
)

type (
	// RetryProfile can be used to define the backoff properties for retries.
	//
	// We use it as a workaround for a known issues:
	//   - Dropping a database with proximity to accessing it.
	//     See: https://support.yugabyte.com/hc/en-us/articles/10552861830541-Unable-to-Drop-Database.
	//   - Creating/dropping tables immediately after creating a database.
	//     See: https://github.com/yugabyte/yugabyte-db/issues/14519.
	RetryProfile struct {
		InitialInterval     time.Duration `mapstructure:"initial-interval" yaml:"initial-interval"`
		RandomizationFactor float64       `mapstructure:"randomization-factor" yaml:"randomization-factor"`
		Multiplier          float64       `mapstructure:"multiplier" yaml:"multiplier"`
		MaxInterval         time.Duration `mapstructure:"max-interval" yaml:"max-interval"`
		// After MaxElapsedTime the ExponentialBackOff returns RetryStopDuration.
		// It never stops if MaxElapsedTime == 0.
		MaxElapsedTime time.Duration `mapstructure:"max-elapsed-time" yaml:"max-elapsed-time"`
	}

	// SQLExecutionBundle contains required information for 'ExecuteSQL' method.
	SQLExecutionBundle struct {
		OperationName string
		Stmt          string
		Pool          *pgxpool.Pool
		RetryMetrics  *prometheus.CounterVec
	}

	operationStatus = string
)

const (
	defaultInitialInterval     = 500 * time.Millisecond
	defaultRandomizationFactor = 0.5
	defaultMultiplier          = 1.5
	defaultMaxInterval         = 10 * time.Second
	defaultMaxElapsedTime      = 15 * time.Minute

	failureStatus = operationStatus("failure")
)

// Execute executes the given operation repeatedly until it succeeds or a timeout occurs.
// It returns nil on success, or the error returned by the final attempt on timeout.
func (p *RetryProfile) Execute(
	ctx context.Context,
	operationName string,
	retryMetrics *prometheus.CounterVec,
	o backoff.Operation,
) error {
	return errors.Wrapf(
		backoff.Retry(
			func() error {
				err := o()
				if err != nil && retryMetrics != nil {
					promutil.AddToCounterVec(retryMetrics, []string{operationName, failureStatus}, 1)
				}
				return err
			}, backoff.WithContext(p.NewBackoff(), ctx)), "multiple retries failed")
}

// ExecuteSQL executes the given SQL statement until it succeeds or a timeout occurs.
func (p *RetryProfile) ExecuteSQL(ctx context.Context, execBundle *SQLExecutionBundle, args ...any) error {
	err := p.Execute(ctx, execBundle.OperationName, execBundle.RetryMetrics, func() error {
		_, err := execBundle.Pool.Exec(ctx, execBundle.Stmt, args...)
		wrappedErr := errors.Wrapf(err, "failed to execute the SQL statement [%s]", execBundle.Stmt)
		if errors.Is(err, puddle.ErrClosedPool) {
			return &backoff.PermanentError{Err: wrappedErr}
		}
		if wrappedErr != nil {
			logger.WithOptions(zap.AddCallerSkip(8)).Warn(wrappedErr)
		}
		return wrappedErr
	})
	return err
}

// NewBackoff creates a new [backoff.ExponentialBackOff] instance with this profile.
func (p *RetryProfile) NewBackoff() *backoff.ExponentialBackOff {
	b := &backoff.ExponentialBackOff{
		InitialInterval:     defaultInitialInterval,
		RandomizationFactor: defaultRandomizationFactor,
		Multiplier:          defaultMultiplier,
		MaxInterval:         defaultMaxInterval,
		MaxElapsedTime:      defaultMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
	if p != nil {
		if p.InitialInterval > 0 {
			b.InitialInterval = p.InitialInterval
		}
		if p.RandomizationFactor > 0 {
			b.RandomizationFactor = p.RandomizationFactor
		}
		if p.Multiplier > 1 {
			b.Multiplier = p.Multiplier
		}
		if p.MaxInterval > 0 {
			b.MaxInterval = p.MaxInterval
		}
		if p.MaxElapsedTime > 0 {
			b.MaxElapsedTime = p.MaxElapsedTime
		}
	}
	b.Stop = backoff.Stop // -1 to stop retries
	b.Reset()
	return b
}

// MakeGrpcRetryPolicyJSON defines the retry policy for a gRPC client connection.
// The retry policy applies to all subsequent gRPC calls made through the client connection.
// Our GRPC retry policy is applicable only for the following status codes:
//
//	(1) UNAVAILABLE	The service is currently unavailable (e.g., transient network issue, server down).
//	(2) DEADLINE_EXCEEDED	Operation took too long (deadline passed).
//	(3) RESOURCE_EXHAUSTED	Some resource (e.g., quota) has been exhausted; the operation cannot proceed.
func (p *RetryProfile) MakeGrpcRetryPolicyJSON() string {
	// We initialize a backoff object to fetch the default values.
	b := p.NewBackoff()

	// We put limits on the values to ensure correct values.
	initialInterval := max(b.InitialInterval.Seconds(), time.Nanosecond.Seconds())
	maxInterval := max(b.MaxInterval.Seconds(), initialInterval)
	multiplier := max(b.Multiplier, 1.0001)
	maxElapsedTime := max(b.MaxElapsedTime.Seconds(), maxInterval)
	ret := map[string]any{
		"loadBalancingConfig": []map[string]any{{
			"round_robin": make(map[string]any),
		}},
		"methodConfig": []map[string]any{{
			// Setting an empty name sets the default for all methods.
			"name": []any{make(map[string]any)},
			"retryPolicy": map[string]any{
				"maxAttempts":       calcMaxAttempts(initialInterval, maxInterval, multiplier, maxElapsedTime),
				"initialBackoff":    fmt.Sprintf("%.1fs", initialInterval),
				"maxBackoff":        fmt.Sprintf("%.1fs", maxInterval),
				"backoffMultiplier": multiplier,
				"retryableStatusCodes": []string{
					"UNAVAILABLE",
					"DEADLINE_EXCEEDED",
					"RESOURCE_EXHAUSTED",
				},
			},
		}},
	}
	jsonString, err := json.MarshalIndent(ret, "", "  ")
	if err != nil {
		logger.Warnf("failed to marshal retry profile to JSON: %s", err)
		return "{}"
	}
	return string(jsonString)
}

// calcMaxAttempts calculates the number of attempts given the following parameters:
// - initialInterval > 0
// - maxInterval     >= i
// - multiplier      > 1
// - maxElapsedTime > i.
func calcMaxAttempts(initialInterval, maxInterval, multiplier, maxElapsedTime float64) int {
	nextBackoffInterval := initialInterval
	var estimatedElapsedTime float64
	var attempts int
	for attempts = 0; estimatedElapsedTime <= maxElapsedTime; attempts++ {
		estimatedElapsedTime += nextBackoffInterval
		nextBackoffInterval = min(nextBackoffInterval*multiplier, maxInterval)
	}
	return attempts
}
