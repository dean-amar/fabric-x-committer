/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-common/api/committerpb"

	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// TestQueryServiceACL_Integration tests ACL enforcement with real Query Service and multiple clients.
func TestQueryServiceACL_Integration(t *testing.T) {
	t.Parallel()

	// Create test CA and certificates with different roles
	ca := acl.NewTestCA(t)
	adminCert, adminKey := ca.CreateClientCertWithRole(t, "Org1MSP", "admin")
	clientCert, clientKey := ca.CreateClientCertWithRole(t, "Org1MSP", "client")
	memberCert, memberKey := ca.CreateClientCertWithRole(t, "Org1MSP", "member")

	// Create server certificate
	serverCert, serverKey := ca.CreateClientCertWithRole(t, "ServerOrg", "peer")

	// Write certificates to temp files for TLSConfig
	serverTLSConfig := writeCertsToTempFiles(t, ca, serverCert, serverKey, true)
	adminTLSConfig := writeCertsToTempFiles(t, ca, adminCert, adminKey, false)
	clientTLSConfig := writeCertsToTempFiles(t, ca, clientCert, clientKey, false)
	memberTLSConfig := writeCertsToTempFiles(t, ca, memberCert, memberKey, false)

	// Setup Query Service with ACL enabled
	env := newQueryServiceTestEnvWithACL(t, serverTLSConfig)
	env.insertSampleKeysValueItems(t)
	txIDs := env.insertSampleTxsStatus(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	// Test cases for different roles
	t.Run("admin can access all methods", func(t *testing.T) {
		t.Parallel()
		adminClient := createQueryClientWithTLS(t, &env.qs.config.Server.Endpoint, adminTLSConfig)

		// GetRows should succeed
		_, err := adminClient.GetRows(ctx, &committerpb.Query{
			Namespaces: []*committerpb.QueryNamespace{
				{NsId: "0", Keys: strToBytes("item1")},
			},
		})
		require.NoError(t, err, "admin should be able to call GetRows")

		// GetTransactionStatus should succeed
		_, err = adminClient.GetTransactionStatus(ctx, &committerpb.TxStatusQuery{
			TxIds: txIDs[:1],
		})
		require.NoError(t, err, "admin should be able to call GetTransactionStatus")

		// GetNamespacePolicies should succeed
		_, err = adminClient.GetNamespacePolicies(ctx, nil)
		require.NoError(t, err, "admin should be able to call GetNamespacePolicies")

		// GetConfigTransaction should succeed
		_, err = adminClient.GetConfigTransaction(ctx, nil)
		require.NoError(t, err, "admin should be able to call GetConfigTransaction")
	})

	t.Run("client can access read methods but not admin methods", func(t *testing.T) {
		t.Parallel()
		clientClient := createQueryClientWithTLS(t, &env.qs.config.Server.Endpoint, clientTLSConfig)

		// GetRows should succeed (reader policy)
		_, err := clientClient.GetRows(ctx, &committerpb.Query{
			Namespaces: []*committerpb.QueryNamespace{
				{NsId: "0", Keys: strToBytes("item1")},
			},
		})
		require.NoError(t, err, "client should be able to call GetRows")

		// GetTransactionStatus should succeed (reader policy)
		_, err = clientClient.GetTransactionStatus(ctx, &committerpb.TxStatusQuery{
			TxIds: txIDs[:1],
		})
		require.NoError(t, err, "client should be able to call GetTransactionStatus")

		// GetNamespacePolicies should be denied (admin policy)
		_, err = clientClient.GetNamespacePolicies(ctx, nil)
		require.Error(t, err, "client should be denied access to GetNamespacePolicies")
		st := status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")
		require.Contains(t, st.Message(), "access denied", "error should mention access denied")

		// GetConfigTransaction should be denied (admin policy)
		_, err = clientClient.GetConfigTransaction(ctx, nil)
		require.Error(t, err, "client should be denied access to GetConfigTransaction")
		st = status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")
		require.Contains(t, st.Message(), "access denied", "error should mention access denied")
	})

	t.Run("member is denied access to read methods", func(t *testing.T) {
		t.Parallel()
		memberClient := createQueryClientWithTLS(t, &env.qs.config.Server.Endpoint, memberTLSConfig)

		// GetRows should be denied
		_, err := memberClient.GetRows(ctx, &committerpb.Query{
			Namespaces: []*committerpb.QueryNamespace{
				{NsId: "0", Keys: strToBytes("item1")},
			},
		})
		require.Error(t, err, "member should be denied access to GetRows")
		st := status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")
		require.Contains(t, st.Message(), "access denied", "error should mention access denied")

		// GetTransactionStatus should be denied
		_, err = memberClient.GetTransactionStatus(ctx, &committerpb.TxStatusQuery{
			TxIds: txIDs[:1],
		})
		require.Error(t, err, "member should be denied access to GetTransactionStatus")
		st = status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")

		// GetNamespacePolicies should be denied
		_, err = memberClient.GetNamespacePolicies(ctx, nil)
		require.Error(t, err, "member should be denied access to GetNamespacePolicies")
		st = status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")

		// GetConfigTransaction should be denied
		_, err = memberClient.GetConfigTransaction(ctx, nil)
		require.Error(t, err, "member should be denied access to GetConfigTransaction")
		st = status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")
	})

	t.Run("view operations respect ACL", func(t *testing.T) {
		t.Parallel()

		// Client can create and use views
		clientClient := createQueryClientWithTLS(t, &env.qs.config.Server.Endpoint, clientTLSConfig)
		view, err := clientClient.BeginView(ctx, defaultViewParams(time.Minute))
		require.NoError(t, err, "client should be able to begin view")
		require.NotNil(t, view)

		_, err = clientClient.GetRows(ctx, &committerpb.Query{
			View: view,
			Namespaces: []*committerpb.QueryNamespace{
				{NsId: "0", Keys: strToBytes("item1")},
			},
		})
		require.NoError(t, err, "client should be able to query with view")

		_, err = clientClient.EndView(ctx, view)
		require.NoError(t, err, "client should be able to end view")

		// Member cannot create views
		memberClient := createQueryClientWithTLS(t, &env.qs.config.Server.Endpoint, memberTLSConfig)
		_, err = memberClient.BeginView(ctx, defaultViewParams(time.Minute))
		require.Error(t, err, "member should be denied access to BeginView")
		st := status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "should return PermissionDenied")
	})
}

// newQueryServiceTestEnvWithACL creates a test environment with ACL enabled.
func newQueryServiceTestEnvWithACL(t *testing.T, serverTLS connection.TLSConfig) *queryServiceTestEnv {
	t.Helper()

	// Generate namespaces and database
	namespacesToTest := []string{"0", "1", "2"}
	dbConf := generateNamespacesUnderTest(t, namespacesToTest)

	// Create ACL configuration
	// Use the full gRPC method paths as keys
	// GetNamespacePolicies and GetConfigTransaction require admin role
	aclConfig := &acl.Config{
		Enabled: true,
		Policies: map[string]string{
			"/committerpb.QueryService/BeginView":            "reader",
			"/committerpb.QueryService/EndView":              "reader",
			"/committerpb.QueryService/GetRows":              "reader",
			"/committerpb.QueryService/GetTransactionStatus": "reader",
			"/committerpb.QueryService/GetNamespacePolicies": "admin", // Admin only
			"/committerpb.QueryService/GetConfigTransaction": "admin", // Admin only
		},
	}

	config := &Config{
		MinBatchKeys:          5,
		MaxBatchWait:          time.Second,
		ViewAggregationWindow: time.Minute,
		MaxViewTimeout:        time.Minute,
		MaxAggregatedViews:    5,
		MaxActiveViews:        10,
		Server:                test.NewLocalHostServer(serverTLS),
		MaxRequestKeys:        0,
		Database:              dbConf,
		Monitoring:            test.NewLocalHostServer(test.InsecureTLSConfig),
		ACL:                   aclConfig,
	}

	qs := NewQueryService(config, nil)
	qs.ConfigureACLInterceptors(config.Server)
	test.RunServiceAndGrpcForTest(t.Context(), t, qs, qs.config.Server)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	pool, err := vc.NewDatabasePool(ctx, config.Database)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return &queryServiceTestEnv{
		config:     config,
		qs:         qs,
		ns:         namespacesToTest,
		clientConn: nil, // Not used in ACL tests
		pool:       pool,
	}
}

// writeCertsToTempFiles writes certificates to temporary files and returns a TLSConfig.
func writeCertsToTempFiles(
	t *testing.T,
	ca *acl.TestCertificateAuthority,
	cert interface{},
	key *ecdsa.PrivateKey,
	isServer bool,
) connection.TLSConfig {
	t.Helper()

	// Create temp directory
	tempDir := t.TempDir()

	// Write CA cert
	caCertPath := tempDir + "/ca.pem"
	require.NoError(t, os.WriteFile(caCertPath, ca.CertBytes(), 0600))

	// Write cert
	certPath := tempDir + "/cert.pem"
	require.NoError(t, os.WriteFile(certPath, acl.CertToPEM(cert.(*x509.Certificate)), 0600))

	// Write key
	keyPath := tempDir + "/key.pem"
	keyPEM, err := acl.PrivateKeyToPEM(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	mode := connection.MutualTLSMode
	if !isServer {
		mode = connection.MutualTLSMode
	}

	return connection.TLSConfig{
		Mode:        mode,
		CertPath:    certPath,
		KeyPath:     keyPath,
		CACertPaths: []string{caCertPath},
	}
}

// Made with Bob
