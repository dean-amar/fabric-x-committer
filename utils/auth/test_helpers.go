/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// CreateTestSignerAndEnvelope creates a test signer and signed envelope for testing.
// If cryptoPath is empty, it generates new crypto material in a temp directory.
// Returns the signer and a function to create signed envelopes with any message.
func CreateTestSignerAndEnvelope(t *testing.T, channelID string, cryptoPath string) (msp.SigningIdentity, func(proto.Message) *common.Envelope) {
	t.Helper()

	signer := CreateTestSigner(t, cryptoPath)

	// Return signer and envelope creator function
	createEnvelope := func(msg proto.Message) *common.Envelope {
		env, err := protoutil.CreateSignedEnvelope(
			common.HeaderType_MESSAGE,
			channelID,
			signer,
			msg,
			0,
			0,
		)
		require.NoError(t, err)
		return env
	}

	return signer, createEnvelope
}

// CreateTestSigner creates a test signing identity for testing.
// If cryptoPath is empty, it generates new crypto material in a temp directory.
func CreateTestSigner(t *testing.T, cryptoPath string) msp.SigningIdentity {
	t.Helper()

	if cryptoPath == "" {
		cryptoPath = t.TempDir()
		_, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(cryptoPath, &testcrypto.ConfigBlock{
			ChannelID:             "testchannel",
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)
	}

	identities, err := testcrypto.GetPeersIdentities(cryptoPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)

	return identities[0]
}

// CreateSignedEnvelope creates a signed envelope with the given signer and message.
func CreateSignedEnvelope(t *testing.T, signer msp.SigningIdentity, channelID string, msg proto.Message) *common.Envelope {
	t.Helper()

	env, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_MESSAGE,
		channelID,
		signer,
		msg,
		0,
		0,
	)
	require.NoError(t, err)
	return env
}

// AuthorizeTestClient performs the Authorize RPC call for test clients.
// It creates a signed envelope using the provided signer and calls the Authorize RPC.
// This should be called once per connection before making other RPC calls.
func AuthorizeTestClient(t *testing.T, client committerpb.AuthServiceClient, signer msp.SigningIdentity, channelID string) {
	t.Helper()

	// Create a simple message for the envelope
	msg := &common.Payload{
		Header: &common.Header{
			ChannelHeader: protoutil.MarshalOrPanic(&common.ChannelHeader{
				Type:      int32(common.HeaderType_MESSAGE),
				ChannelId: channelID,
			}),
		},
	}

	// Create signed envelope
	envelope := CreateSignedEnvelope(t, signer, channelID, msg)

	// Call Authorize RPC
	resp, err := client.Authorize(t.Context(), &committerpb.AuthorizeRequest{
		SignedEnvelope: envelope,
	})
	require.NoError(t, err)
	require.True(t, resp.Success, "Authorization failed: %s", resp.Message)
}

// AuthorizeTestConnection is a convenience function that creates a signer from the crypto path
// and authorizes the connection in one call. This is useful for test environments where the
// crypto path is already known.
func AuthorizeTestConnection(t *testing.T, conn interface {
	committerpb.AuthServiceClient
}, cryptoPath, channelID string) {
	t.Helper()

	signer := CreateTestSigner(t, cryptoPath)
	authClient := conn.(committerpb.AuthServiceClient)
	AuthorizeTestClient(t, authClient, signer, channelID)
}
