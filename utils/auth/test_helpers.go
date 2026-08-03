/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// CreateTestSigner creates a test signing identity for testing.
// If cryptoPath is empty, it generates new crypto material in a temp directory.
//
//nolint:ireturn // msp.SigningIdentity is an interface by design.
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

// AuthorizeTestConn authorizes a connection using a signer loaded from cryptoPath, binding the
// client's TLS certificate hash derived from clientTLS. Use this once per connection before
// issuing business RPCs. It works for both mTLS (cert-bound) and non-mTLS (timestamp-only)
// connections.
//
//nolint:revive // argument-limit: test helper takes the connection, crypto, channel, and TLS config.
func AuthorizeTestConn(
	t *testing.T,
	conn grpc.ClientConnInterface,
	cryptoPath, channelID string,
	clientTLS connection.TLSConfig,
) {
	t.Helper()

	tlsCertHash, err := ClientTLSCertHash(clientTLS)
	require.NoError(t, err)

	require.NoError(t, AuthorizeConnection(t.Context(), conn, AuthorizeParameters{
		Signer:      CreateTestSigner(t, cryptoPath),
		ChannelID:   channelID,
		TLSCertHash: tlsCertHash,
	}))
}
