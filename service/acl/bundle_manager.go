/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
)

// BundleManager manages channel configuration bundles.
// Services don't hold channel IDs - they're extracted from envelopes.
type BundleManager struct {
	mu      sync.RWMutex
	bundles map[string]*channelconfig.Bundle
}

// NewBundleManager creates a new bundle manager.
func NewBundleManager() *BundleManager {
	return &BundleManager{
		bundles: make(map[string]*channelconfig.Bundle),
	}
}

// GetChannelConfig retrieves the channel config bundle for a channel.
func (bm *BundleManager) GetChannelConfig(channelID string) *channelconfig.Bundle {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.bundles[channelID]
}

// UpdateBundle updates the channel config bundle.
func (bm *BundleManager) UpdateBundle(channelID string, bundle *channelconfig.Bundle) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.bundles[channelID] = bundle
	logger.Infof("Updated channel config bundle for channel %s", channelID)
}

// UpdateFromConfigBlock creates a bundle from a config block and stores it.
func (bm *BundleManager) UpdateFromConfigBlock(channelID string, configBlock *common.Block) error {
	material, err := channelconfig.LoadConfigBlockMaterial(configBlock)
	if err != nil {
		return errors.Wrap(err, "failed to load config block material")
	}

	bm.UpdateBundle(channelID, material.Bundle)
	return nil
}

// RemoveChannel removes a channel's config bundle.
func (bm *BundleManager) RemoveChannel(channelID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.bundles, channelID)
	logger.Infof("Removed channel config bundle for channel %s", channelID)
}
