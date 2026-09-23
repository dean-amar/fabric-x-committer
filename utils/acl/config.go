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
	Config *connection.ClientConfig `mapstructure:"client" validate:"required"`
	// StreamReAuthorizeInterval is how often an open stream re-authorizes its bound token against the
	// latest policy. Zero uses the enforcer's default interval.
	StreamReAuthorizeInterval time.Duration `mapstructure:"stream-re-authorize-interval"`
}
