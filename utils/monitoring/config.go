/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitoring

import (
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

// Config represents the monitoring configuration.
type Config struct {
	Server *connection.ServerConfig `mapstructure:"server"`
}
