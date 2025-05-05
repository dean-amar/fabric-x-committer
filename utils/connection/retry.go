package connection

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yugabyte/pgx/v4/pgxpool"

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
		err = errors.Wrapf(err, "failed to execute the SQL statement [%s]", execBundle.Stmt)
		if err != nil {
			logger.Warn(err)
		}
		return err
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
		if p.InitialInterval != 0 {
			b.InitialInterval = p.InitialInterval
		}
		if p.RandomizationFactor != 0 {
			b.RandomizationFactor = p.RandomizationFactor
		}
		if p.Multiplier != 0 {
			b.Multiplier = p.Multiplier
		}
		if p.MaxInterval != 0 {
			b.MaxInterval = p.MaxInterval
		}
		if p.MaxElapsedTime != 0 {
			b.MaxElapsedTime = p.MaxElapsedTime
		}
	}
	b.Stop = backoff.Stop // -1 to stop retries
	b.Reset()
	return b
}
