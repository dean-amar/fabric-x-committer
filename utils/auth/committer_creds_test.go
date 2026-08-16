/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/hyperledger/fabric-x-common/common/crypto/tlsgen"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
)

func TestNewMSPAuthInfoCapturesClientCert(t *testing.T) {
	t.Parallel()
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	clientPair, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)

	// Under mTLS the TLS layer surfaces the client's leaf certificate; newMSPAuthInfo must
	// capture it and its DER SHA-256 hash so the Authorize envelope can be cert-bound.
	tlsInfo := credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientPair.TLSCert},
	}}
	info := newMSPAuthInfo(tlsInfo)

	require.True(t, info.HasClientCertificate())
	require.Equal(t, clientPair.TLSCert, info.TLSCert)

	// The captured hash matches protoutil.HashTLSCertificate over the PEM cert, which is the value
	// the client puts into the envelope binding — so server and client agree.
	wantHash, err := protoutil.HashTLSCertificate(clientPair.Cert)
	require.NoError(t, err)
	require.Equal(t, wantHash, info.TLSCertHash)
}

func TestNewMSPAuthInfoNoClientCert(t *testing.T) {
	t.Parallel()

	// Non-mTLS: the TLS info carries no peer certificate, so the cert fields stay empty and
	// HasClientCertificate reports false (freshness is then the only replay guard).
	for _, tc := range []struct {
		name        string
		tlsAuthInfo credentials.AuthInfo
	}{
		{name: "TLS info without peer certs", tlsAuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}},
		{name: "non-TLS auth info", tlsAuthInfo: nonTLSAuthInfo{}},
		{name: "nil auth info", tlsAuthInfo: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info := newMSPAuthInfo(tc.tlsAuthInfo)
			require.False(t, info.HasClientCertificate())
			require.Nil(t, info.TLSCert)
			require.Empty(t, info.TLSCertHash)
		})
	}
}

func TestCustomCredentialsInfoAndClone(t *testing.T) {
	t.Parallel()

	creds := NewCustomCredentials(nil) // insecure underlying credentials (test-only)
	require.Equal(t, "tls+custom-auth", creds.Info().SecurityProtocol)

	cloned := creds.Clone()
	require.NotNil(t, cloned)
	require.Equal(t, "tls+custom-auth", cloned.Info().SecurityProtocol)
}

func TestHashRawCertificate(t *testing.T) {
	t.Parallel()
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	pair, err := ca.NewServerCertKeyPair("localhost")
	require.NoError(t, err)

	// hashRawCertificate hashes the DER bytes; protoutil.HashTLSCertificate hashes the DER content
	// of the PEM cert. For the same certificate the two must agree, or client/server bindings
	// would never match.
	got := hashRawCertificate(pair.TLSCert)
	want, err := protoutil.HashTLSCertificate(pair.Cert)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// nonTLSAuthInfo is a credentials.AuthInfo that is not a credentials.TLSInfo, modeling a
// connection whose transport carried no TLS handshake result.
type nonTLSAuthInfo struct{}

func (nonTLSAuthInfo) AuthType() string { return "non-tls" }
