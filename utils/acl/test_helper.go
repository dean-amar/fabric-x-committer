/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCertificateAuthority represents a simple CA for testing.
type TestCertificateAuthority struct {
	cert       *x509.Certificate
	privateKey *ecdsa.PrivateKey
}

// NewTestCA creates a new test Certificate Authority.
func NewTestCA(t *testing.T) *TestCertificateAuthority {
	t.Helper()

	// Generate CA private key
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TestCA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	return &TestCertificateAuthority{
		cert:       caCert,
		privateKey: caPrivateKey,
	}
}

// CertBytes returns the CA certificate in PEM format.
func (ca *TestCertificateAuthority) CertBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

// CreateClientCertWithRole creates a client certificate with the specified organization and role.
// The role is set in the OU (Organizational Unit) field of the certificate.
func (ca *TestCertificateAuthority) CreateClientCertWithRole(t *testing.T, org, role string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate client private key
	clientPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create client certificate template
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:       []string{org},
			OrganizationalUnit: []string{role}, // Role is set in OU field
			CommonName:         "Test Client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// Add IP SANs for localhost testing
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:    []string{"localhost"},
	}

	// Sign the client certificate with CA
	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca.cert, &clientPrivateKey.PublicKey, ca.privateKey)
	require.NoError(t, err)

	clientCert, err := x509.ParseCertificate(clientCertBytes)
	require.NoError(t, err)

	return clientCert, clientPrivateKey
}

// CertToPEM converts a certificate to PEM format.
func CertToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// PrivateKeyToPEM converts a private key to PEM format.
func PrivateKeyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}
