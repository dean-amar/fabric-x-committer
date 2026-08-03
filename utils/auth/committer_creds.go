/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// CustomCredentials wraps standard TLS transport credentials and replaces the
// connection's AuthInfo with a mutable *MSPAuthInfo. This lets the Authorize RPC
// bind an MSP identity to the physical connection while still carrying the TLS
// handshake information (including the client certificate) for cert-hash binding.
type CustomCredentials struct {
	tlsCreds credentials.TransportCredentials
}

// NewCustomCredentials creates new custom credentials that wrap existing TLS credentials.
// If tlsCreds is nil, it will use insecure credentials (for testing only).
func NewCustomCredentials(tlsCreds credentials.TransportCredentials) credentials.TransportCredentials {
	if tlsCreds == nil {
		// Use insecure credentials for testing.
		tlsCreds = insecure.NewCredentials()
	}

	return &CustomCredentials{
		tlsCreds: tlsCreds,
	}
}

// ClientHandshake delegates to TLS credentials, then adds custom auth info.
//
//nolint:ireturn // credentials.AuthInfo is required by the TransportCredentials interface.
func (c *CustomCredentials) ClientHandshake(
	ctx context.Context, authority string, rawConn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	// Delegate to the underlying TLS credentials to perform the handshake.
	conn, tlsAuthInfo, err := c.tlsCreds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return nil, nil, errors.Wrap(err, "TLS handshake failed")
	}

	return conn, newMSPAuthInfo(tlsAuthInfo), nil
}

// ServerHandshake delegates to TLS credentials, then captures the client
// certificate (if any) so subsequent Authorize calls can bind the MSP identity
// to it.
//
//nolint:ireturn // credentials.AuthInfo is required by the TransportCredentials interface.
func (c *CustomCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// Delegate to the underlying TLS credentials to perform the handshake.
	conn, tlsAuthInfo, err := c.tlsCreds.ServerHandshake(rawConn)
	if err != nil {
		return nil, nil, errors.Wrap(err, "TLS handshake failed")
	}

	return conn, newMSPAuthInfo(tlsAuthInfo), nil
}

// newMSPAuthInfo builds an MSPAuthInfo from the TLS handshake result, extracting
// the client's leaf certificate and its SHA-256 hash when the connection is
// mutually authenticated. Non-mTLS connections carry no client certificate, so
// the cert fields remain empty.
func newMSPAuthInfo(tlsAuthInfo credentials.AuthInfo) *MSPAuthInfo {
	info := &MSPAuthInfo{TLSInfo: tlsAuthInfo}

	tlsInfo, ok := tlsAuthInfo.(credentials.TLSInfo)
	if !ok {
		return info
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return info
	}

	cert := tlsInfo.State.PeerCertificates[0]
	info.TLSCert = cert
	info.TLSCertHash = hashRawCertificate(cert)
	return info
}

// hashRawCertificate computes the SHA-256 hash of a certificate's DER bytes.
// This matches protoutil.HashTLSCertificate, which hashes the DER content of a
// PEM-encoded certificate, so a client that binds its cert hash via
// protoutil.CreateSignedEnvelopeWithTLSBinding produces a value equal to this.
func hashRawCertificate(cert *x509.Certificate) []byte {
	digest := sha256.Sum256(cert.Raw)
	return digest[:]
}

// Info returns protocol info, delegating to underlying TLS credentials.
func (c *CustomCredentials) Info() credentials.ProtocolInfo {
	info := c.tlsCreds.Info()
	// Modify to indicate custom auth is added on top of TLS.
	info.SecurityProtocol = "tls+custom-auth"
	return info
}

// Clone creates a copy of the credentials.
func (c *CustomCredentials) Clone() credentials.TransportCredentials {
	return &CustomCredentials{
		tlsCreds: c.tlsCreds.Clone(),
	}
}

// OverrideServerName delegates to underlying TLS credentials.
// Required by the TransportCredentials interface; deprecated by gRPC but still delegated.
//
//nolint:staticcheck // SA1019: method is part of the credentials.TransportCredentials interface.
func (c *CustomCredentials) OverrideServerName(serverNameOverride string) error {
	return c.tlsCreds.OverrideServerName(serverNameOverride)
}
