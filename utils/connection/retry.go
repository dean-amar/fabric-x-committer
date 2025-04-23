package connection

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"

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

	operationStatus = string
)

const (
	defaultInitialInterval     = 500 * time.Millisecond
	defaultRandomizationFactor = 0.5
	defaultMultiplier          = 1.5
	defaultMaxInterval         = 10 * time.Second
	defaultMaxElapsedTime      = 15 * time.Minute

	successStatus = operationStatus("success")
	failureStatus = operationStatus("failure")
)

// Execute executes the given operation repeatedly until it succeeds or a timeout occurs.
// It returns nil on success, or the error returned by the final attempt on timeout.
func (p *RetryProfile) Execute(ctx context.Context,
	operationName string,
	counterVec *prometheus.CounterVec,
	o backoff.Operation,
) error {
	retryCount := 0
	status := successStatus

	return errors.Wrapf(
		backoff.Retry(
			func() error {
				var err error
				if err = o(); err != nil {
					status = failureStatus
				} else {
					status = successStatus
				}
				if counterVec != nil {
					promutil.AddToCounterVec(counterVec,
						[]string{operationName, status},
						1)
				}
				retryCount++
				return err
			}, backoff.WithContext(p.NewBackoff(), ctx),
		), "multiple retries failed")
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
