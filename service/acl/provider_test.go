/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/testcrypto"
)

func TestProvider_UpdateFromConfigBlock(t *testing.T) {
	t.Parallel()

	// Success cases
	for _, tc := range []struct {
		name              string
		channelID         string
		peerOrgCount      uint32
		expectBundleCount int
	}{
		{
			name:              "single peer org config block",
			channelID:         "channel1",
			peerOrgCount:      1,
			expectBundleCount: 1,
		},
		{
			name:              "multiple peer orgs config block",
			channelID:         "channel2",
			peerOrgCount:      3,
			expectBundleCount: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create config block with crypto material
			cryptoPath := t.TempDir()
			configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
				cryptoPath,
				&testcrypto.ConfigBlock{
					ChannelID:             tc.channelID,
					PeerOrganizationCount: tc.peerOrgCount,
				},
			)
			require.NoError(t, err)
			require.NotNil(t, configBlock)

			// Create provider and update from config block
			bundleManager := NewBundleManager()
			provider := NewProvider(bundleManager)

			err = provider.UpdateFromConfigBlock(configBlock)
			require.NoError(t, err)

			// Verify bundle was created
			require.Equal(t, tc.expectBundleCount, bundleManager.ChannelCount())

			// Verify we can retrieve the bundle
			bundle, err := bundleManager.GetBundle(tc.channelID)
			require.NoError(t, err)
			require.NotNil(t, bundle)

			// Verify bundle has channel config
			channelConfig := bundle.ChannelConfig()
			require.NotNil(t, channelConfig)
		})
	}
}

func TestProvider_UpdateFromConfigBlock_Failures(t *testing.T) {
	t.Parallel()

	// Failure cases
	for _, tc := range []struct {
		name        string
		configBlock *common.Block
		expectError string
	}{
		{
			name:        "nil config block",
			configBlock: nil,
			expectError: "block is empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bundleManager := NewBundleManager()
			provider := NewProvider(bundleManager)

			err := provider.UpdateFromConfigBlock(tc.configBlock)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectError)
		})
	}
}

func TestProvider_GetBundle(t *testing.T) {
	t.Parallel()

	channelID := "channel1"

	// Create config block
	cryptoPath := t.TempDir()
	configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
		cryptoPath,
		&testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 1,
		},
	)
	require.NoError(t, err)

	// Create provider and update
	bundleManager := NewBundleManager()
	provider := NewProvider(bundleManager)
	err = provider.UpdateFromConfigBlock(configBlock)
	require.NoError(t, err)

	// Success cases
	for _, tc := range []struct {
		name      string
		channelID string
	}{
		{
			name:      "get existing bundle",
			channelID: channelID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bundle, err := provider.GetBundle(tc.channelID)
			require.NoError(t, err)
			require.NotNil(t, bundle)
		})
	}

	// Failure cases
	for _, tc := range []struct {
		name      string
		channelID string
	}{
		{
			name:      "get non-existent bundle",
			channelID: "non-existent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bundle, err := provider.GetBundle(tc.channelID)
			require.Error(t, err)
			require.Nil(t, bundle)
			require.Contains(t, err.Error(), "bundle not found")
		})
	}
}

func TestProvider_MultipleChannels(t *testing.T) {
	t.Parallel()

	bundleManager := NewBundleManager()
	provider := NewProvider(bundleManager)

	// Create and add multiple channels
	channels := []string{"channel1", "channel2", "channel3"}
	cryptoPath := t.TempDir()

	for _, channelID := range channels {
		configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
			cryptoPath,
			&testcrypto.ConfigBlock{
				ChannelID:             channelID,
				PeerOrganizationCount: 1,
			},
		)
		require.NoError(t, err)

		err = provider.UpdateFromConfigBlock(configBlock)
		require.NoError(t, err)
	}

	// Verify all channels are present
	require.Equal(t, len(channels), bundleManager.ChannelCount())

	// Verify each channel can be retrieved
	for _, channelID := range channels {
		bundle, err := provider.GetBundle(channelID)
		require.NoError(t, err)
		require.NotNil(t, bundle)
	}
}

// Made with Bob
