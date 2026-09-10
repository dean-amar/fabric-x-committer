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
	// SigningKeyPath is the path to a PEM-encoded EC (P-256) private key used to mint and verify
	// ES256 tokens. All AuthService instances must share the same key so a token minted by one
	// instance verifies at another. When empty, an ephemeral key is generated at startup - fine for
	// a single-instance dev deployment, but tokens then do not survive a restart and separate
	// instances cannot verify each other's tokens.
	SigningKeyPath string `mapstructure:"signing-key-path"`
	// TokenTTL is the lifetime of a minted token. Clients refresh by re-authenticating before it elapses.
	TokenTTL time.Duration `mapstructure:"token-ttl" default:"5m" validate:"gt=0"`
	// EnvelopeFreshnessWindow bounds how far an authentication envelope's timestamp may deviate from
	// the server's clock. The single-use nonce is what actually prevents replay; this window is
	// defence in depth and bounds how long an unredeemed envelope stays presentable.
	EnvelopeFreshnessWindow time.Duration `mapstructure:"envelope-freshness-window" default:"5m" validate:"gt=0"`
	// NonceTTL is how long an issued authentication nonce remains redeemable. It only has to cover
	// the round trip between IssueNonce and Authenticate, so it is deliberately short: a shorter window
	// means fewer unredeemed nonces held in the database.
	NonceTTL time.Duration `mapstructure:"nonce-ttl" default:"1m" validate:"gt=0"`
	// ConfigRefreshInterval is how often the service reads the latest committed channel configuration
	// from the state database to refresh its evaluation bundle.
	ConfigRefreshInterval time.Duration `mapstructure:"config-refresh-interval" default:"1m" validate:"gt=0"`
	// TokenCleanupInterval is how often expired token records are swept from the store.
	TokenCleanupInterval time.Duration `mapstructure:"token-cleanup-interval" default:"1m" validate:"gt=0"`
	// ChallengeRequestsPerSecond caps the combined rate of IssueNonce and Authenticate, the two RPCs
	// reachable without a token. Both are cheap to call and expensive to serve - a nonce costs a database
	// row, an authentication costs a signature verification and an MSP resolution - so an unthrottled
	// caller can spam either one into a denial of service. They are limited separately from Authorize,
	// whose volume legitimately tracks the resource servers' whole RPC load and must not be throttled
	// alongside them. Set to 0 to disable, which is only sensible in tests.
	ChallengeRequestsPerSecond int `mapstructure:"challenge-requests-per-second" default:"200" validate:"gte=0"`
	// ChallengeBurst is how far the challenge limiter may run ahead of its steady rate, absorbing the
	// spike of many clients whose tokens expire at the same moment. It must not exceed the rate.
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
