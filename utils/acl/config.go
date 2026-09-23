/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"time"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// Client configures a resource server's connection to the AuthService. It carries no `default` tags on
// purpose: an operator who omits the section leaves the pointer nil, which disables enforcement.
type Client struct {
	// Config is the AuthService endpoint and the TLS the resource server uses to reach it.
	Config *connection.ClientConfig `mapstructure:"client"`
	// StreamReAuthorizeInterval is how often an open stream re-authorizes its bound token against the
	// latest policy. A stream is always bounded by its token's expiry as well, so a high value here leaves
	// the token's lifetime as the only bound. Zero means Authorization on every call.
	StreamReAuthorizeInterval time.Duration `mapstructure:"stream-re-authorize-interval" default:"1m" validate:"gt=0"`
	// TransientRetryInterval is how long a stream waits before retrying a re-authorization that failed
	// transiently, so a brief outage costs one attempt per interval rather than one per message.
	TransientRetryInterval time.Duration `mapstructure:"transient-retry-interval" default:"5s" validate:"gt=0"`
}
