/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"crypto/x509"
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc/credentials"
	"sync"
)

// MSPAuthInfo implements credentials.AuthInfo and holds MSP authentication state.
// This struct is attached to the gRPC connection during the TLS handshake and
// lives for the duration of the connection.
type MSPAuthInfo struct {
	mu             sync.RWMutex
	MSPIdentity    msp.Identity
	ConfigSequence uint64
	TLSCert        *x509.Certificate
	TLSCertHash    []byte

	TLSInfo credentials.AuthInfo
}

// AuthType returns the authentication type.
func (m *MSPAuthInfo) AuthType() string {
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
func (m *MSPAuthInfo) GetIdentity() (msp.Identity, uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.MSPIdentity, m.ConfigSequence
}
