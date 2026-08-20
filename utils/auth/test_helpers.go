/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"

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

// ClientTLSCertHash returns the SHA-256 hash of the client certificate configured in the
// given TLS config, or nil when the config is not mutual TLS (no client certificate). The
// hash matches the value the server computes from the presented certificate.
func ClientTLSCertHash(tlsConfig connection.TLSConfig) ([]byte, error) {
	creds, err := connection.NewClientTLSCredentials(tlsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load client TLS credentials")
	}
	if creds.Mode != connection.MutualTLSMode || len(creds.Cert) == 0 {
		return nil, nil
	}
	hash, err := protoutil.HashTLSCertificate(creds.Cert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash client TLS certificate")
	}
	return hash, nil
}
