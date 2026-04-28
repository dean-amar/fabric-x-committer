/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
)

// TestInterceptor_WithRealCertificates tests the ACL interceptor with real certificates
// containing different roles in the OU field.
func TestInterceptor_WithRealCertificates(t *testing.T) {
	t.Parallel()

	// Create test CA
	ca := acl.NewTestCA(t)

	// Create ACL configuration
	// Note: Certificate validation is handled by TLS layer, not ACL
	aclConfig := &acl.Config{
		Enabled: true,
		Policies: map[string]string{
			"/test.Service/PublicMethod": "member",
			"/test.Service/ClientMethod": "client",
			"/test.Service/AdminMethod":  "admin",
		},
	}

	// Create ACL provider
	aclProvider, err := acl.NewProvider(aclConfig)
	require.NoError(t, err)
	require.True(t, aclProvider.IsEnabled())

	// Test cases with different client roles
	for _, tc := range []struct {
		name          string
		clientRole    string
		method        string
		expectedError bool
		expectedCode  codes.Code
	}{
		{
			name:          "member can access public method",
			clientRole:    "member",
			method:        "/test.Service/PublicMethod",
			expectedError: false,
		},
		{
			name:          "member cannot access client method",
			clientRole:    "member",
			method:        "/test.Service/ClientMethod",
			expectedError: true,
			expectedCode:  codes.PermissionDenied,
		},
		{
			name:          "client can access public method",
			clientRole:    "client",
			method:        "/test.Service/PublicMethod",
			expectedError: false,
		},
		{
			name:          "client can access client method",
			clientRole:    "client",
			method:        "/test.Service/ClientMethod",
			expectedError: false,
		},
		{
			name:          "client cannot access admin method",
			clientRole:    "client",
			method:        "/test.Service/AdminMethod",
			expectedError: true,
			expectedCode:  codes.PermissionDenied,
		},
		{
			name:          "admin can access all methods - public",
			clientRole:    "admin",
			method:        "/test.Service/PublicMethod",
			expectedError: false,
		},
		{
			name:          "admin can access all methods - client",
			clientRole:    "admin",
			method:        "/test.Service/ClientMethod",
			expectedError: false,
		},
		{
			name:          "admin can access all methods - admin",
			clientRole:    "admin",
			method:        "/test.Service/AdminMethod",
			expectedError: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create client certificate with specified role
			clientCert, clientKey := ca.CreateClientCertWithRole(t, "Org1MSP", tc.clientRole)
			clientTLSCert, err := tls.X509KeyPair(acl.CertToPEM(clientCert), mustPrivateKeyToPEM(t, clientKey))
			require.NoError(t, err)

			// Create context with peer info (simulating gRPC connection)
			ctx := createContextWithCert(t, clientTLSCert)

			// Test ACL check directly
			err = aclProvider.CheckACL(ctx, tc.method)

			if tc.expectedError {
				require.Error(t, err)
				st, ok := status.FromError(err)
				if ok {
					require.Equal(t, tc.expectedCode, st.Code())
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestInterceptor_DisabledACL tests that when ACL is disabled, all requests are allowed.
func TestInterceptor_DisabledACL(t *testing.T) {
	t.Parallel()

	// Create disabled ACL provider
	aclProvider, err := acl.NewProvider(nil)
	require.NoError(t, err)
	require.False(t, aclProvider.IsEnabled())

	// Create test CA and certificate
	ca := acl.NewTestCA(t)
	clientCert, clientKey := ca.CreateClientCertWithRole(t, "Org1MSP", "member")
	clientTLSCert, err := tls.X509KeyPair(acl.CertToPEM(clientCert), mustPrivateKeyToPEM(t, clientKey))
	require.NoError(t, err)

	// Create context with peer info
	ctx := createContextWithCert(t, clientTLSCert)

	// All methods should be allowed when ACL is disabled
	methods := []string{
		"/test.Service/PublicMethod",
		"/test.Service/ClientMethod",
		"/test.Service/AdminMethod",
	}

	for _, method := range methods {
		err := aclProvider.CheckACL(ctx, method)
		require.NoError(t, err, "method %s should be allowed when ACL is disabled", method)
	}
}

// createContextWithCert creates a context with peer info containing the given TLS certificate.
// This simulates what gRPC does when a client connects with mTLS.
func createContextWithCert(t *testing.T, tlsCert tls.Certificate) context.Context {
	t.Helper()

	// Parse the certificate
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	// Create TLS connection state
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	// Create peer with TLS info
	p := &peer.Peer{
		AuthInfo: tlsInfo,
	}

	// Add peer to context
	return peer.NewContext(context.Background(), p)
}

func mustPrivateKeyToPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	pem, err := acl.PrivateKeyToPEM(key)
	require.NoError(t, err)
	return pem
}
