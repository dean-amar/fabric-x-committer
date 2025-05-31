/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vc

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
)

// Config is the configuration for the validator-committer service.
type Config struct {
	Server         *connection.ServerConfig `mapstructure:"server"`
	Database       *DatabaseConfig          `mapstructure:"database"`
	ResourceLimits *ResourceLimitsConfig    `mapstructure:"resource-limits"`
	Monitoring     monitoring.Config        `mapstructure:"monitoring"`
}

// DatabaseConfig is the configuration for the database.
type DatabaseConfig struct {
	Endpoints      []*connection.Endpoint   `mapstructure:"endpoints"`
	Username       string                   `mapstructure:"username"`
	Password       string                   `mapstructure:"password"`
	Database       string                   `mapstructure:"database"`
	MaxConnections int32                    `mapstructure:"max-connections"`
	MinConnections int32                    `mapstructure:"min-connections"`
	LoadBalance    bool                     `mapstructure:"load-balance"`
	Retry          *connection.RetryProfile `mapstructure:"retry"`
	Creds          connection.DatabaseCreds `mapstructure:",squash"`
}

// DataSourceName returns the data source name of the database.
func (d *DatabaseConfig) DataSourceName() string {
	ret := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		d.Username, d.Password, d.EndpointsString(), d.Database)

	if d.Creds.UseCreds() {
		ret = strings.Replace(ret, "sslmode=disable", "sslmode=verify-ca", 1)
	}
	// The load balancing flag is only available when the server supports it (having multiple nodes).
	// Thus, we only add it when explicitly required. Otherwise, an error will occur.
	if d.LoadBalance {
		ret += "&load_balance=true"
	}
	return ret
}

func (d *DatabaseConfig) BuildDatabaseCreds() (*tls.Config, error) {
	if !d.Creds.UseCreds() {
		return nil, nil
	}
	certPool, err := connection.BuildCertPool(d.Creds.CAPaths)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
		ServerName: "database",
	}, nil
}

// EndpointsString returns the address:port as a string with comma as a separator between endpoints.
func (d *DatabaseConfig) EndpointsString() string {
	return connection.AddressString(d.Endpoints...)
}

// ResourceLimitsConfig is the configuration for the resource limits.
type ResourceLimitsConfig struct {
	MaxWorkersForPreparer             int           `mapstructure:"max-workers-for-preparer"`
	MaxWorkersForValidator            int           `mapstructure:"max-workers-for-validator"`
	MaxWorkersForCommitter            int           `mapstructure:"max-workers-for-committer"`
	MinTransactionBatchSize           int           `mapstructure:"min-transaction-batch-size"`
	TimeoutForMinTransactionBatchSize time.Duration `mapstructure:"timeout-for-min-transaction-batch-size"`
}
