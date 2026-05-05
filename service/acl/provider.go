/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/protoutil"
)

var logger = flogging.MustGetLogger("acl")

const (
	// ReadersPolicy is the default policy path for read operations.
	ReadersPolicy = "/Channel/Application/Readers"
)

// provider implements the Provider interface using Fabric's policy evaluation engine.
type provider struct {
	bundleManager *BundleManager
}

// NewProvider creates a new ACL provider with the given bundle manager.
func NewProvider(bundleManager *BundleManager) Provider {
	return &provider{
		bundleManager: bundleManager,
	}
}

// GetBundle retrieves the channel configuration bundle for the specified channel.
func (p *provider) GetBundle(channelID string) (*channelconfig.Bundle, error) {
	return p.bundleManager.GetBundle(channelID)
}

// UpdateFromConfigBlock updates the provider's channel configuration from a config block.
func (p *provider) UpdateFromConfigBlock(block *common.Block) error {
	// Extract channel ID from block
	channelID, err := protoutil.GetChannelIDFromBlock(block)
	if err != nil {
		return errors.Wrap(err, "failed to extract channel ID from block")
	}

	// Extract config envelope from block
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	if err != nil {
		return errors.Wrap(err, "failed to extract envelope from config block")
	}

	// Create bundle from config envelope
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, factory.GetDefault())
	if err != nil {
		return errors.Wrap(err, "failed to create bundle from config envelope")
	}

	// Update bundle in manager
	p.bundleManager.UpdateBundle(channelID, bundle)

	logger.Infof("Updated ACL bundle for channel %s from config block %d", channelID, block.Header.Number)
	return nil
}

// Made with Bob
