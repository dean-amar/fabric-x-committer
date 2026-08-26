/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"time"

	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

// Config is the configuration for the authentication and authorization service.
type Config struct {
	// Database is the state-database connection the service reads the committed channel
	// configuration from and persists token records in.
	Database *statedb.Config `mapstructure:"database" validate:"required"`
	// SigningKeyPath is the path to a PEM-encoded EC (P-256) private key used to mint and verify
	// ES256 tokens. All AuthService instances must share the same key so a token minted by one
	// instance verifies at another. When empty, an ephemeral key is generated at startup - fine for
	// a single-instance dev deployment, but tokens then do not survive a restart and separate
	// instances cannot verify each other's tokens.
	SigningKeyPath string `mapstructure:"signing-key-path"`
	// TokenTTL is the lifetime of a minted token. Clients refresh by re-authenticating before it elapses.
	TokenTTL time.Duration `mapstructure:"token-ttl" default:"5m" validate:"gt=0"`
	// EnvelopeFreshnessWindow bounds how far an authentication envelope's timestamp may deviate from
	// the server's clock, so a captured envelope cannot be replayed once it goes stale.
	EnvelopeFreshnessWindow time.Duration `mapstructure:"envelope-freshness-window" default:"5m" validate:"gt=0"`
	// ConfigRefreshInterval is how often the service reads the latest committed channel configuration
	// from the state database to refresh its evaluation bundle.
	ConfigRefreshInterval time.Duration `mapstructure:"config-refresh-interval" default:"1m" validate:"gt=0"`
	// TokenCleanupInterval is how often expired token records are swept from the store.
	TokenCleanupInterval time.Duration `mapstructure:"token-cleanup-interval" default:"1m" validate:"gt=0"`
}
