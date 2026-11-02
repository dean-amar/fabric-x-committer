/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"time"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// Config configures a resource server's connection to the AuthService. Enforcement is on only when it lists
// endpoints: the embedded client's flow-control defaults make the section present even when the YAML omits it.
type Config struct {
	// MultiClientConfig lists the AuthService instances and the TLS the resource server uses to reach them.
	connection.MultiClientConfig `mapstructure:",squash"`
	// StreamReAuthorizeInterval is how often an open stream re-authorizes its bound token against the
	// latest policy. A stream is always bounded by its token's expiry as well, so a high value here leaves
	// the token's lifetime as the only bound.
	StreamReAuthorizeInterval time.Duration `mapstructure:"stream-re-authorize-interval"`
	// AuthorizeTimeout bounds each AuthorizeIdentity call. Neither a unary nor a stream context carries a deadline, so
	// without it a call to an unreachable auth service would wait for it indefinitely.
	AuthorizeTimeout time.Duration `mapstructure:"authorize-timeout"`
}
