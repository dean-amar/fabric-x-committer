/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/testcrypto"
)

func TestExtractChannelID(t *testing.T) {
	t.Parallel()

	// Success cases
	for _, tc := range []struct {
		name      string
		channelID string
	}{
		{
			name:      "valid channel ID",
			channelID: "mychannel",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env, err := protoutil.CreateSignedEnvelope(
				common.HeaderType_ENDORSER_TRANSACTION,
				tc.channelID,
				nil,
				&common.Payload{Data: []byte("test")},
				0, 0,
			)
			require.NoError(t, err)

			extractedID, err := extractChannelID(env)
			require.NoError(t, err)
			require.Equal(t, tc.channelID, extractedID)
		})
	}

	// Failure cases
	for _, tc := range []struct {
		name     string
		envelope *common.Envelope
	}{
		{
			name:     "nil envelope",
			envelope: nil,
		},
		{
			name:     "nil payload",
			envelope: &common.Envelope{},
		},
		{
			name: "invalid payload bytes",
			envelope: &common.Envelope{
				Payload: []byte("invalid"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := extractChannelID(tc.envelope)
			require.Error(t, err)
		})
	}
}

func TestExtractSignedData(t *testing.T) {
	t.Parallel()

	cryptoPath := t.TempDir()
	_, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	identities, err := testcrypto.GetPeersIdentities(cryptoPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)

	signer := identities[0]

	// Success cases
	for _, tc := range []struct {
		name      string
		channelID string
		payload   []byte
	}{
		{
			name:      "valid signed envelope",
			channelID: "mychannel",
			payload:   []byte("test payload"),
		},
		{
			name:      "empty payload",
			channelID: "testchannel",
			payload:   []byte{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env, err := protoutil.CreateSignedEnvelope(
				common.HeaderType_ENDORSER_TRANSACTION,
				tc.channelID,
				signer,
				&common.Payload{Data: tc.payload},
				0, 0,
			)
			require.NoError(t, err)

			signedData, err := extractSignedData(env)
			require.NoError(t, err)
			require.NotEmpty(t, signedData)
			require.NotNil(t, signedData[0].Identity)
			require.NotEmpty(t, signedData[0].Data)
			require.NotEmpty(t, signedData[0].Signature)
		})
	}

	// Failure cases
	for _, tc := range []struct {
		name     string
		envelope *common.Envelope
	}{
		{
			name:     "nil envelope",
			envelope: nil,
		},
		{
			name:     "empty envelope",
			envelope: &common.Envelope{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := extractSignedData(tc.envelope)
			require.Error(t, err)
		})
	}
}

func TestBundleManager(t *testing.T) {
	t.Parallel()

	t.Run("new bundle manager is empty", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		require.NotNil(t, bm)
		require.Nil(t, bm.GetChannelConfig("mychannel"))
	})

	t.Run("update and retrieve bundle", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		channelID := "testchannel"
		cryptoPath := t.TempDir()

		// Create a config block
		configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)

		// Update bundle
		err = bm.UpdateFromConfigBlock(channelID, configBlock)
		require.NoError(t, err)

		// Retrieve bundle
		bundle := bm.GetChannelConfig(channelID)
		require.NotNil(t, bundle)
		require.Equal(t, channelID, bundle.ConfigtxValidator().ChannelID())
	})

	t.Run("update replaces existing bundle", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		channelID := "testchannel"
		cryptoPath := t.TempDir()

		// Create first config block
		configBlock1, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)

		err = bm.UpdateFromConfigBlock(channelID, configBlock1)
		require.NoError(t, err)

		bundle1 := bm.GetChannelConfig(channelID)
		require.NotNil(t, bundle1)

		// Create second config block (simulating an update)
		configBlock2, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 2,
		})
		require.NoError(t, err)

		err = bm.UpdateFromConfigBlock(channelID, configBlock2)
		require.NoError(t, err)

		bundle2 := bm.GetChannelConfig(channelID)
		require.NotNil(t, bundle2)
		// Bundles should be different instances
		require.NotSame(t, bundle1, bundle2)
	})

	t.Run("remove bundle", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		channelID := "testchannel"
		cryptoPath := t.TempDir()

		configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)

		err = bm.UpdateFromConfigBlock(channelID, configBlock)
		require.NoError(t, err)
		require.NotNil(t, bm.GetChannelConfig(channelID))

		bm.RemoveChannel(channelID)
		require.Nil(t, bm.GetChannelConfig(channelID))
	})

	t.Run("update with invalid config block fails", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()

		// Empty block
		err := bm.UpdateFromConfigBlock("testchannel", &common.Block{})
		require.Error(t, err)

		// Block with invalid data
		err = bm.UpdateFromConfigBlock("testchannel", &common.Block{
			Data: &common.BlockData{
				Data: [][]byte{[]byte("invalid")},
			},
		})
		require.Error(t, err)
	})
}

func TestProvider_CheckReadAccess(t *testing.T) {
	t.Parallel()

	cryptoPath := t.TempDir()
	channelID := "testchannel"
	configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
		ChannelID:             channelID,
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	identities, err := testcrypto.GetPeersIdentities(cryptoPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)

	t.Run("grants access with valid identity", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		err := bm.UpdateFromConfigBlock(channelID, configBlock)
		require.NoError(t, err)

		provider := NewProvider(bm)

		// Create signed envelope with valid identity
		env := CreateSignedEnvelope(t, channelID, identities[0], []byte("test"))

		err = provider.CheckReadAccess(env)
		require.NoError(t, err)
	})

	t.Run("denies access without channel config", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		env := CreateSignedEnvelope(t, channelID, identities[0], []byte("test"))

		err := provider.CheckReadAccess(env)
		require.Error(t, err)
		require.Contains(t, err.Error(), "channel config not found")
	})

	t.Run("denies access with unsigned envelope", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		err := bm.UpdateFromConfigBlock(channelID, configBlock)
		require.NoError(t, err)

		provider := NewProvider(bm)

		env := CreateUnsignedEnvelope(t, channelID)

		err = provider.CheckReadAccess(env)
		require.Error(t, err)
	})

	t.Run("fails with invalid envelope", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		err := provider.CheckReadAccess(&common.Envelope{})
		require.Error(t, err)
	})
}

func TestProvider_UpdateFromConfigBlock(t *testing.T) {
	t.Parallel()

	channelID := "testchannel"
	cryptoPath := t.TempDir()

	t.Run("updates bundle from config block", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)

		err = provider.UpdateFromConfigBlock(configBlock)
		require.NoError(t, err)

		// Verify bundle was created
		bundle := bm.GetChannelConfig(channelID)
		require.NotNil(t, bundle)
	})

	t.Run("fails with empty config block", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		err := provider.UpdateFromConfigBlock(&common.Block{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "no data")
	})

	t.Run("fails with invalid envelope in block", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		block := &common.Block{
			Data: &common.BlockData{
				Data: [][]byte{[]byte("invalid")},
			},
		}

		err := provider.UpdateFromConfigBlock(block)
		require.Error(t, err)
	})
}

func TestProvider_UpdateFromConfigEnvelope(t *testing.T) {
	t.Parallel()

	channelID := "testchannel"
	cryptoPath := t.TempDir()

	t.Run("updates bundle from config envelope", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)

		// Extract envelope bytes from config block
		envelopeBytes := configBlock.Data.Data[0]

		err = provider.UpdateFromConfigEnvelope(envelopeBytes)
		require.NoError(t, err)

		// Verify bundle was created
		bundle := bm.GetChannelConfig(channelID)
		require.NotNil(t, bundle)
	})

	t.Run("fails with invalid envelope bytes", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		err := provider.UpdateFromConfigEnvelope([]byte("invalid"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal")
	})

	t.Run("fails with empty envelope bytes", func(t *testing.T) {
		t.Parallel()

		bm := NewBundleManager()
		provider := NewProvider(bm)

		err := provider.UpdateFromConfigEnvelope([]byte{})
		require.Error(t, err)
	})
}

// Made with Bob
