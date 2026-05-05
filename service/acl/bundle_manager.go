/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
)

// BundleManager provides thread-safe storage and retrieval of channel configuration bundles.
// It maintains a map of channel IDs to their corresponding configuration bundles.
type BundleManager struct {
	mu      sync.RWMutex
	bundles map[string]*channelconfig.Bundle
}

// NewBundleManager creates a new BundleManager instance.
func NewBundleManager() *BundleManager {
	return &BundleManager{
		bundles: make(map[string]*channelconfig.Bundle),
	}
}

// GetBundle retrieves the configuration bundle for the specified channel.
// Returns an error if the channel is not configured.
func (bm *BundleManager) GetBundle(channelID string) (*channelconfig.Bundle, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	bundle, ok := bm.bundles[channelID]
	if !ok {
		return nil, errors.Newf("bundle not found for channel %s", channelID)
	}
	return bundle, nil
}

// UpdateBundle stores or updates the configuration bundle for the specified channel.
func (bm *BundleManager) UpdateBundle(channelID string, bundle *channelconfig.Bundle) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.bundles[channelID] = bundle
}

// RemoveBundle removes the configuration bundle for the specified channel.
// This is useful for cleanup when a channel is no longer needed.
func (bm *BundleManager) RemoveBundle(channelID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.bundles, channelID)
}

// ChannelCount returns the number of channels currently managed.
func (bm *BundleManager) ChannelCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.bundles)
}

// Made with Bob
