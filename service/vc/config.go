/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"time"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/dbconn"
	"github.com/hyperledger/fabric-x-committer/utils/retry"
)

// Config is the configuration for the validator-committer service.
type Config struct {
	Database       *DatabaseConfig       `mapstructure:"database" validate:"required"`
	ResourceLimits *ResourceLimitsConfig `mapstructure:"resource-limits" validate:"required"`
}

// DatabaseConfig is the configuration for the database.
type DatabaseConfig struct {
	Endpoints            []*connection.Endpoint   `mapstructure:"endpoints"`
	Username             string                   `mapstructure:"username"`
	Password             string                   `mapstructure:"password"`
	Database             string                   `mapstructure:"database" validate:"required"`
	MaxConnections       int32                    `mapstructure:"max-connections" validate:"required,gt=0"`
	MinConnections       int32                    `mapstructure:"min-connections" validate:"gte=0"`
	LoadBalance          bool                     `mapstructure:"load-balance"`
	Retry                *retry.Profile           `mapstructure:"retry"`
	TLS                  dbconn.DatabaseTLSConfig `mapstructure:"tls"`
	TablePreSplitTablets int                      `mapstructure:"table-pre-split-tablets"`
}

// DataSourceName returns the data source name of the database.
func (d *DatabaseConfig) DataSourceName() (string, error) {
	return dbconn.DataSourceName(dbconn.DataSourceNameParams{
		Username:        d.Username,
		Password:        d.Password,
		Database:        d.Database,
		EndpointsString: d.EndpointsString(),
		LoadBalance:     d.LoadBalance,
		TLS:             d.TLS,
	})
}

// EndpointsString returns the address:port as a string with comma as a separator between endpoints.
func (d *DatabaseConfig) EndpointsString() string {
	return connection.AddressString(d.Endpoints...)
}

// ResourceLimitsConfig is the configuration for the resource limits.
type ResourceLimitsConfig struct {
	// WorkersForPreparer, WorkersForValidator, and WorkersForCommitter set the exact number
	// of goroutines spawned for each pipeline stage. They are exact counts, not upper bounds.
	WorkersForPreparer                int           `mapstructure:"workers-for-preparer" validate:"required,gt=0"`
	WorkersForValidator               int           `mapstructure:"workers-for-validator" validate:"required,gt=0"`
	WorkersForCommitter               int           `mapstructure:"workers-for-committer" validate:"required,gt=0"`
	MinTransactionBatchSize           int           `mapstructure:"min-transaction-batch-size" validate:"required,gt=0"`
	TimeoutForMinTransactionBatchSize time.Duration `mapstructure:"timeout-for-min-transaction-batch-size" validate:"required,gt=0"` //nolint:lll
	// QueueMultiplier scales the buffer size of the internal pipeline channels; larger values
	// allow more transactions to be buffered between pipeline stages. Most channels are sized
	// as workers * QueueMultiplier, but the validator-to-committer channel is sized by
	// QueueMultiplier alone to bound memory usage (see NewValidatorCommitterService).
	QueueMultiplier int `mapstructure:"queue-multiplier" validate:"required,gt=0"`
	// QueueMonitorSamplingTime defines the sampling interval for monitoring queue sizes.
	QueueMonitorSamplingTime time.Duration `mapstructure:"queue-monitor-sampling-time" validate:"required,gt=0"`
}

// Default configuration values for the validator-committer service and database.
const (
	DefaultServerPort                  = 6001
	DefaultMonitoringPort              = 2116
	DefaultDatabaseName                = "yugabyte"
	DefaultDatabaseMaxConnections      = 20
	DefaultDatabaseMinConnections      = 1
	DefaultDatabaseRetryMaxElapsedTime = 10 * time.Minute
	DefaultWorkersForPreparer          = 1
	DefaultWorkersForValidator         = 1
	DefaultWorkersForCommitter         = 20
	DefaultMinTransactionBatchSize     = 1
	DefaultTimeoutForMinBatchSize      = 5 * time.Second
	DefaultQueueMultiplier             = 1
	DefaultQueueMonitorSamplingTime    = 100 * time.Millisecond
	DefaultDatabaseEndpointHost        = "localhost"
	DefaultDatabaseEndpointPort        = 5433
)
