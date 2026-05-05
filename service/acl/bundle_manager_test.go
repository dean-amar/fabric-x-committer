/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"testing"

	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/stretchr/testify/require"
)

func TestBundleManager_GetBundle(t *testing.T) {
	t.Parallel()

	// Test getting non-existent bundle
	for _, tc := range []struct {
		name      string
		channelID string
	}{
		{
			name:      "non-existent channel returns error",
			channelID: "channel1",
		},
		{
			name:      "empty channel ID returns error",
			channelID: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bm := NewBundleManager()
			bundle, err := bm.GetBundle(tc.channelID)
			require.Error(t, err)
			require.Nil(t, bundle)
			require.Contains(t, err.Error(), "bundle not found")
		})
	}
}

func TestBundleManager_UpdateAndGetBundle(t *testing.T) {
	t.Parallel()

	// Test updating and retrieving bundle
	for _, tc := range []struct {
		name      string
		channelID string
	}{
		{
			name:      "update and retrieve bundle",
			channelID: "channel1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bm := NewBundleManager()

			// Create a mock bundle (nil is acceptable for this test)
			var mockBundle *channelconfig.Bundle

			// Update bundle
			bm.UpdateBundle(tc.channelID, mockBundle)

			// Verify bundle was stored
			retrieved, err := bm.GetBundle(tc.channelID)
			require.NoError(t, err)
			require.Equal(t, mockBundle, retrieved)
		})
	}
}

func TestBundleManager_RemoveBundle(t *testing.T) {
	t.Parallel()

	// Test removing bundle
	for _, tc := range []struct {
		name      string
		channelID string
		addFirst  bool
	}{
		{
			name:      "remove existing bundle",
			channelID: "channel1",
			addFirst:  true,
		},
		{
			name:      "remove non-existent bundle does not panic",
			channelID: "non-existent",
			addFirst:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bm := NewBundleManager()

			// Add a bundle first if needed
			if tc.addFirst {
				var mockBundle *channelconfig.Bundle
				bm.UpdateBundle(tc.channelID, mockBundle)
				_, err := bm.GetBundle(tc.channelID)
				require.NoError(t, err)
			}

			// Remove the bundle
			bm.RemoveBundle(tc.channelID)

			// Verify bundle was removed
			bundle, err := bm.GetBundle(tc.channelID)
			require.Error(t, err)
			require.Nil(t, bundle)
		})
	}
}

func TestBundleManager_ChannelCount(t *testing.T) {
	t.Parallel()

	// Test channel count
	for _, tc := range []struct {
		name          string
		channelIDs    []string
		expectedCount int
	}{
		{
			name:          "empty bundle manager has zero channels",
			channelIDs:    []string{},
			expectedCount: 0,
		},
		{
			name:          "single channel",
			channelIDs:    []string{"channel1"},
			expectedCount: 1,
		},
		{
			name:          "multiple channels",
			channelIDs:    []string{"channel1", "channel2", "channel3"},
			expectedCount: 3,
		},
		{
			name:          "duplicate channel IDs count as one",
			channelIDs:    []string{"channel1", "channel1"},
			expectedCount: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			bm := NewBundleManager()

			// Add bundles
			var mockBundle *channelconfig.Bundle
			for _, channelID := range tc.channelIDs {
				bm.UpdateBundle(channelID, mockBundle)
			}

			// Verify count
			count := bm.ChannelCount()
			require.Equal(t, tc.expectedCount, count)
		})
	}
}

func TestBundleManager_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Test concurrent reads and writes
	t.Run("concurrent operations do not panic", func(t *testing.T) {
		t.Parallel()
		bm := NewBundleManager()
		channelID := "channel1"
		var mockBundle *channelconfig.Bundle

		done := make(chan bool)

		// Writer goroutine
		go func() {
			for i := 0; i < 100; i++ {
				bm.UpdateBundle(channelID, mockBundle)
			}
			done <- true
		}()

		// Reader goroutine
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = bm.GetBundle(channelID)
			}
			done <- true
		}()

		// Counter goroutine
		go func() {
			for i := 0; i < 100; i++ {
				_ = bm.ChannelCount()
			}
			done <- true
		}()

		// Wait for all goroutines
		<-done
		<-done
		<-done
	})
}

// Made with Bob
