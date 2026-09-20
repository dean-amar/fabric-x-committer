/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"time"

	"github.com/cockroachdb/errors"

	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

// Config is the configuration for the authentication and authorization service.
type Config struct {
	// Database is the state-database connection the service reads the committed channel
	// configuration from and persists token records in.
	Database *statedb.Config `mapstructure:"database" validate:"required"`
	// SigningKeyPath is a PEM-encoded EC (P-256) key for ES256 tokens; every instance must share it for a
	// token minted by one to verify at another. Empty means an ephemeral key: single-instance dev only.
	SigningKeyPath string `mapstructure:"signing-key-path"`
	// TokenTTL is the lifetime of a minted token. A client mints once and does not renew, so this must
	// cover the client's whole run; past it the resource server rejects the token.
	TokenTTL time.Duration `mapstructure:"token-ttl" default:"5m" validate:"gt=0"`
	// NonceTTL is how long an issued nonce stays redeemable. It need only cover the IssueNonce ->
	// Authenticate round trip, and a shorter window means fewer unredeemed nonces in the database.
	NonceTTL time.Duration `mapstructure:"nonce-ttl" default:"1m" validate:"gt=0"`
	// EnvelopeFreshnessWindow bounds an envelope timestamp's deviation from the server clock. The nonce is
	// what prevents replay; this only bounds how long an unredeemed envelope stays presentable.
	EnvelopeFreshnessWindow time.Duration `mapstructure:"envelope-freshness-window" default:"5m" validate:"gt=0"`
	// ConfigRefreshInterval is how often the service reads the latest committed channel configuration
	// from the state database to refresh its evaluation bundle.
	ConfigRefreshInterval time.Duration `mapstructure:"config-refresh-interval" default:"1m" validate:"gt=0"`
	// TokenCleanupInterval is how often expired token records are swept from the store.
	TokenCleanupInterval time.Duration `mapstructure:"token-cleanup-interval" default:"1m" validate:"gt=0"`
	// ChallengeRequestsPerSecond caps IssueNonce and Authenticate together: the only RPCs reachable without
	// a token. Limited apart from Authorize, whose rate tracks the resource servers' whole load. 0 disables.
	ChallengeRequestsPerSecond int `mapstructure:"challenge-requests-per-second" default:"200" validate:"gte=0"`
	// ChallengeBurst is how far the challenge limiter may run ahead of its steady rate, absorbing a
	// burst of clients authenticating at once. It must not exceed the rate.
	ChallengeBurst int `mapstructure:"challenge-burst" default:"50" validate:"gte=0"`
}

// Validate rejects a challenge burst larger than the rate it bursts above, mirroring the server's own
// rate-limit validation: a burst over the rate would let a caller outrun the limit for a full second.
func (c *Config) Validate() error {
	if c.ChallengeRequestsPerSecond > 0 && c.ChallengeBurst > c.ChallengeRequestsPerSecond {
		return errors.Newf("challenge-burst (%d) must not exceed challenge-requests-per-second (%d)",
			c.ChallengeBurst, c.ChallengeRequestsPerSecond)
	}
	return nil
}
