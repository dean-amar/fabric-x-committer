/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"time"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// ClientConfig configures a resource server's connection to the AuthService and its ACL enforcement.
// A resource service embeds it as an optional (pointer) field: when absent, ACL enforcement is
// disabled and the service behaves as before. It deliberately carries no `default` tags, so an
// operator who omits the section leaves the pointer nil rather than having it auto-populated.
//
// Whether the client's TLS certificate is forwarded for the token's certificate binding is not a
// separate toggle: it follows from the resource server's own TLS mode (mutual TLS makes the
// certificate present on the connection), so the interceptor simply forwards whatever is presented.
type ClientConfig struct {
	// Server is the AuthService endpoint and the TLS the resource server uses to reach it.
	Server *connection.ClientConfig `mapstructure:"server" validate:"required"`
	// StreamRevalidateInterval is how often an open stream re-authorizes its bound identity against
	// the latest policy. Zero uses the enforcer's default interval.
	StreamRevalidateInterval time.Duration `mapstructure:"stream-revalidate-interval"`
}
