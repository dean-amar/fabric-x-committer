/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

var logger = flogging.MustGetLogger("acl")

// Provider checks access control for read operations.
// Simplified from Fabric's ACLProvider since fabric-x-committer only has read operations.
type Provider interface {
	// CheckReadAccess verifies if the envelope's identity has read access
	// to the channel specified in the envelope.
	// The channel ID is extracted from the envelope's channel header.
	CheckReadAccess(envelope *common.Envelope) error

	// UpdateFromConfigBlock updates the channel configuration bundle from a config block.
	// This should be called whenever a new config block is received.
	UpdateFromConfigBlock(configBlock *common.Block) error

	// UpdateFromConfigEnvelope updates the channel configuration bundle from a config envelope.
	// This is useful when only the envelope bytes are available (e.g., from database queries).
	UpdateFromConfigEnvelope(envelopeBytes []byte) error
}
