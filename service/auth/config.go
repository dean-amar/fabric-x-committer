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
	Database       *statedb.Config `mapstructure:"database" validate:"required"`
	SigningKeyPath string          `mapstructure:"signing-key-path"`
	// TokenTTL is the lifetime of a minted token.
	TokenTTL time.Duration `mapstructure:"token-ttl" default:"5m" validate:"gt=0"`
	// NonceTTL is how long an issued nonce stays redeemable.
	NonceTTL time.Duration `mapstructure:"nonce-ttl" default:"1m" validate:"gt=0"`
	// EnvelopeFreshnessWindow bounds an envelope timestamp's deviation from the server clock.
	EnvelopeFreshnessWindow time.Duration `mapstructure:"envelope-freshness-window" default:"5m" validate:"gt=0"`
	// ConfigRefreshInterval is how often the service reads the latest committed channel configuration
	// from the state database to refresh its evaluation bundle.
	ConfigRefreshInterval time.Duration `mapstructure:"config-refresh-interval" default:"1m" validate:"gt=0"`
	// TokenAndNoncesCleanupInterval is how often expired token and nonce records are swept from the store.
	TokenAndNoncesCleanupInterval time.Duration `mapstructure:"token-and-nonces-cleanup-interval" default:"1m" validate:"gt=0"` //nolint:lll,revive // a struct tag cannot be wrapped.
	// ChallengeRequestsPerSecond caps IssueNonce and Authenticate together: the only RPCs reachable without
	// a token. Limited apart from Authorize, whose rate tracks the resource servers' whole load.
	ChallengeRequestsPerSecond int `mapstructure:"challenge-requests-per-second" default:"200" validate:"gte=0"`
	// ChallengeBurst is how far the challenge limiter may run ahead of its steady rate, absorbing a
	// burst of clients authenticating at once. It must not exceed the rate.
	ChallengeBurst int `mapstructure:"challenge-burst" default:"50" validate:"gte=0"`
}
