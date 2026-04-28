/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestExtractOrganization(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		cert     *x509.Certificate
		expected string
	}{
		{
			name: "single organization",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"Org1MSP"},
				},
			},
			expected: "Org1MSP",
		},
		{
			name: "multiple organizations returns first",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"Org1MSP", "Org2MSP"},
				},
			},
			expected: "Org1MSP",
		},
		{
			name: "no organization returns empty",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{},
				},
			},
			expected: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := extractOrganization(tc.cert)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractRole(t *testing.T) {
	t.Parallel()

	// Valid roles
	for _, tc := range []struct {
		name     string
		cert     *x509.Certificate
		expected string
	}{
		{
			name: "admin role",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{RoleAdmin},
				},
			},
			expected: RoleAdmin,
		},
		{
			name: "client role",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{RoleClient},
				},
			},
			expected: RoleClient,
		},
		{
			name: "member role",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{RoleMember},
				},
			},
			expected: RoleMember,
		},
		{
			name: "no OU defaults to member",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{},
				},
			},
			expected: RoleMember,
		},
		{
			name: "invalid role defaults to member",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{"invalid-role"},
				},
			},
			expected: RoleMember,
		},
		{
			name: "multiple OUs uses first",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{RoleAdmin, RoleClient},
				},
			},
			expected: RoleAdmin,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := extractRole(tc.cert)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractIdentityFromContext(t *testing.T) {
	t.Parallel()

	// Create test CA and certificate
	ca, caCert := createTestCA(t)
	clientCert := createTestClientCert(t, ca, caCert, "Org1MSP", RoleClient, time.Now().Add(24*time.Hour))

	t.Run("valid context with certificate", func(t *testing.T) {
		t.Parallel()

		// Create context with peer and TLS info
		ctx := createContextWithCert(t, clientCert)

		identity, err := ExtractIdentityFromContext(ctx)
		require.NoError(t, err)
		require.NotNil(t, identity)
		require.Equal(t, "Org1MSP", identity.Organization)
		require.Equal(t, RoleClient, identity.Role)
		require.Equal(t, clientCert, identity.Certificate)
	})

	t.Run("context without peer info", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		identity, err := ExtractIdentityFromContext(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoPeerInfo)
		require.Nil(t, identity)
	})

	t.Run("context without TLS info", func(t *testing.T) {
		t.Parallel()

		// Create context with peer but no TLS info
		p := &peer.Peer{
			Addr: nil,
		}
		ctx := peer.NewContext(context.Background(), p)

		identity, err := ExtractIdentityFromContext(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoTLSInfo)
		require.Nil(t, identity)
	})

	t.Run("context with empty certificate chain", func(t *testing.T) {
		t.Parallel()

		// Create context with TLS info but no certificates
		p := &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{},
				},
			},
		}
		ctx := peer.NewContext(context.Background(), p)

		identity, err := ExtractIdentityFromContext(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCertificate)
		require.Nil(t, identity)
	})

	t.Run("certificate missing organization", func(t *testing.T) {
		t.Parallel()

		// Create certificate without organization
		certNoOrg := createTestClientCert(t, ca, caCert, "", RoleClient, time.Now().Add(24*time.Hour))
		ctx := createContextWithCert(t, certNoOrg)

		identity, err := ExtractIdentityFromContext(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing organization")
		require.Nil(t, identity)
	})
}

// Helper functions for testing

func createTestCA(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertBytes)
	require.NoError(t, err)

	return caKey, caCert
}

func createTestClientCert(t *testing.T, caKey *rsa.PrivateKey, caCert *x509.Certificate, org, role string, notAfter time.Time) *x509.Certificate {
	t.Helper()

	// Generate client private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create client certificate
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-client",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Add organization if provided
	if org != "" {
		clientTemplate.Subject.Organization = []string{org}
	}

	// Add role if provided
	if role != "" {
		clientTemplate.Subject.OrganizationalUnit = []string{role}
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCert, err := x509.ParseCertificate(clientCertBytes)
	require.NoError(t, err)

	return clientCert
}

func createContextWithCert(t *testing.T, cert *x509.Certificate) context.Context {
	t.Helper()

	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}

	return peer.NewContext(context.Background(), p)
}
