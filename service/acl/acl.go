/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
)

// Provider defines the interface for ACL enforcement using gRPC metadata.
// This interface abstracts the policy evaluation logic, allowing services
// to validate client access without directly handling channel configurations.
type Provider interface {
	// GetBundle retrieves the channel configuration bundle for the specified channel.
	// Returns an error if the channel is not configured or the bundle is unavailable.
	GetBundle(channelID string) (*channelconfig.Bundle, error)

	// UpdateFromConfigBlock updates the provider's channel configuration
	// from a config block. This is called when a new config block is received.
	UpdateFromConfigBlock(block *common.Block) error
}

// Made with Bob
