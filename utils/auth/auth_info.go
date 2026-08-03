/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"crypto/x509"
	"sync"

	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc/credentials"
)

// MSPAuthInfo implements credentials.AuthInfo and holds MSP authentication state.
// This struct is attached to the gRPC connection during the TLS handshake and
// lives for the duration of the connection.
//
// The TLS fields (TLSCert, TLSCertHash) are populated once during the handshake and
// are immutable afterwards, so they are read without holding the mutex. The MSP
// identity fields are set later by the Authorize RPC and are guarded by the mutex,
// since the binding happens on a different goroutine than subsequent RPCs.
type MSPAuthInfo struct {
	mu             sync.RWMutex
	MSPIdentity    msp.Identity
	ConfigSequence uint64

	// TLSCert and TLSCertHash capture the client certificate presented during the
	// TLS handshake (empty when the connection is not mutually authenticated).
	// They are set once at handshake time and never mutated afterwards.
	TLSCert     *x509.Certificate
	TLSCertHash []byte

	TLSInfo credentials.AuthInfo
}

// AuthType returns the authentication type.
func (*MSPAuthInfo) AuthType() string {
	return "mTLS+MSP"
}

// SetIdentity binds an MSP identity to this connection.
func (m *MSPAuthInfo) SetIdentity(identity msp.Identity, sequence uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.MSPIdentity = identity
	m.ConfigSequence = sequence
}

// GetIdentity retrieves the bound MSP identity.
//
//nolint:ireturn // msp.Identity is an interface by design.
func (m *MSPAuthInfo) GetIdentity() (msp.Identity, uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.MSPIdentity, m.ConfigSequence
}

// HasClientCertificate reports whether the connection presented a client TLS
// certificate during the handshake (i.e. it is mutually authenticated).
func (m *MSPAuthInfo) HasClientCertificate() bool {
	return len(m.TLSCertHash) > 0
}
