/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

import (
	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// Config describes the load generator metrics.
// It adds latency tracker to the common metrics configurations.
type Config struct {
	Server  *connection.ServerConfig `mapstructure:"server" yaml:"server"`
	Retry   *connection.RetryProfile `mapstructure:"retry" yaml:"retry,omitempty"`
	Latency LatencyConfig            `mapstructure:"latency" yaml:"latency"`
}
