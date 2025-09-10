/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

type (
	// CredentialsFactory responsible for the creation of
	// TLS certificates inside a TLSConfig for testing purposes
	// by using the tls generation library of 'Hyperledger Fabric'.
	CredentialsFactory struct {
		CertificateAuthority tlsgen.CA
	}

	// testCase define a secure connection test case.
	testCase struct {
		testDescription  string
		clientSecureMode string
		shouldFail       bool
	}

	createTLSConfigParameters struct {
		connectionMode string
		keyPair        *tlsgen.CertKeyPair
		namingStyle    CertStyle
		san            string
	}

	// ServerStarter is a function that receives a TLS configuration, starts the server,
	// and returns a RPCAttempt function for initiating a client connection and attempting an RPC call.
	ServerStarter func(t *testing.T, serverTLS connection.TLSConfig) RPCAttempt

	// RPCAttempt is a function returned by ServerStarter that contains the information
	// needed to start a client connection and attempt an RPC call.
	RPCAttempt func(ctx context.Context, t *testing.T, cfg connection.TLSConfig) error

	// CertStyle sets the database certificates file formatting.
	CertStyle int
)

const (
	defaultHostName = "localhost"

	// CertStyleDefault creates certificates by the default naming convention.
	CertStyleDefault CertStyle = iota
	// CertStyleYugabyte creates YugabyteDB node's certificates by node.<IP>.key, node.<IP>.crt, ca.crt.
	CertStyleYugabyte
	// CertStylePostgres creates PostgreSQL node's certificates by server.key, server.crt, ca.crt.
	CertStylePostgres

	//nolint:revive // KeyPrivate, KeyPublic KeyCACert are convention key names for the credential map.
	KeyPrivate = "private-key"
	KeyPublic  = "public-key"
	KeyCACert  = "ca-certificate"

	keySubDirectory = "sub-dir"
	caCertFileName  = "ca.crt"
)

// ServerModes is a list of server-side TLS modes used for testing.
var ServerModes = []string{connection.MutualTLSMode, connection.OneSideTLSMode, connection.NoneTLSMode}

// NewCredentialsFactory returns a CredentialsFactory with a new CA.
func NewCredentialsFactory(t *testing.T) *CredentialsFactory {
	t.Helper()
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	return &CredentialsFactory{
		CertificateAuthority: ca,
	}
}

// CreateServerCredentials creates a server key pair given SAN (Subject Alternative Name),
// Writing it to a temp testing folder and returns a [connection.TLSConfig].
func (scm *CredentialsFactory) CreateServerCredentials(
	t *testing.T,
	tlsMode string,
	san string,
	namingStyle CertStyle,
) (connection.TLSConfig, string) {
	t.Helper()
	serverKeypair, err := scm.CertificateAuthority.NewServerCertKeyPair(san)
	require.NoError(t, err)
	return scm.createTLSConfig(t, createTLSConfigParameters{
		connectionMode: tlsMode,
		keyPair:        serverKeypair,
		namingStyle:    namingStyle,
		san:            san,
	})
}

// CreateClientCredentials creates a client key pair,
// Writing it to a temp testing folder and returns a [connection.TLSConfig].
func (scm *CredentialsFactory) CreateClientCredentials(t *testing.T, tlsMode string) (connection.TLSConfig, string) {
	t.Helper()
	clientKeypair, err := scm.CertificateAuthority.NewClientCertKeyPair()
	require.NoError(t, err)
	return scm.createTLSConfig(t, createTLSConfigParameters{
		connectionMode: tlsMode,
		keyPair:        clientKeypair,
		namingStyle:    CertStyleDefault,
	})
}

/*
RunSecureConnectionTest starts a gRPC server with mTLS enabled and
tests client connections using various TLS configurations to verify that
the server correctly accepts or rejects connections based on the client's setup.
It runs a server instance of the service and returns a function
that starts a client with the required TLS mode, attempts an RPC call,
and returns the resulting error.
Server Mode | Client with mTLS | Client with server-side TLS | Client with no TLS
------------|------------------|-----------------------------|--------------------
mTLS        |      connect     |        can't connect        |     can't connect
TLS         |      connect     |           connect           |     can't connect
None        | can't connect    |        can't connect        |       connect.
*/
func RunSecureConnectionTest(
	t *testing.T,
	starter ServerStarter,
) {
	t.Helper()
	// create server and client credentials
	tlsMgr := NewCredentialsFactory(t)
	// create a base TLS configuration for the client
	baseClientTLS, _ := tlsMgr.CreateClientCredentials(t, connection.NoneTLSMode)
	for _, tc := range []struct {
		serverMode string
		cases      []testCase
	}{
		{
			serverMode: connection.MutualTLSMode,
			cases: []testCase{
				{"client mTLS", connection.MutualTLSMode, false},
				{"client with one sided TLS", connection.OneSideTLSMode, true},
				{"client no TLS", connection.NoneTLSMode, true},
			},
		},
		{
			serverMode: connection.OneSideTLSMode,
			cases: []testCase{
				{"client mTLS", connection.MutualTLSMode, false},
				{"client with one sided TLS", connection.OneSideTLSMode, false},
				{"client no TLS", connection.NoneTLSMode, true},
			},
		},
		{
			serverMode: connection.NoneTLSMode,
			cases: []testCase{
				{"client mTLS", connection.MutualTLSMode, true},
				{"client with one sided TLS", connection.OneSideTLSMode, true},
				{"client no TLS", connection.NoneTLSMode, false},
			},
		},
	} {
		// create server's tls config and start it according to the serverSecureMode.
		serverTLS, _ := tlsMgr.CreateServerCredentials(t, tc.serverMode, defaultHostName, CertStyleDefault)
		rpcAttemptFunc := starter(t, serverTLS)
		// for each server secure mode, build the client's test cases.
		for _, clientTestCase := range tc.cases {
			clientTc := clientTestCase
			t.Run(fmt.Sprintf(
				"tls-mode:%s/%s",
				tc.serverMode,
				clientTc.testDescription,
			), func(t *testing.T) {
				t.Parallel()

				cfg := baseClientTLS
				cfg.Mode = clientTc.clientSecureMode

				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				t.Cleanup(cancel)

				err := rpcAttemptFunc(ctx, t, cfg)
				if clientTc.shouldFail {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}

// CreateClientWithTLS creates and returns a typed gRPC client using the provided TLS configuration.
// It establishes a secure connection to the given endpoint
// and returns the generated client using the provided client creation proto function.
func CreateClientWithTLS[T any](
	t *testing.T,
	endpoint *connection.Endpoint,
	tlsCfg connection.TLSConfig,
	protoClient func(grpc.ClientConnInterface) T,
) T {
	t.Helper()
	conn, err := connection.Connect(NewSecuredDialConfig(t, endpoint, tlsCfg))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})
	return protoClient(conn)
}

// createTLSConfig creates and returns a TLS configuration based on the
// given TLS mode and the credential bytes.
func (scm *CredentialsFactory) createTLSConfig(
	t *testing.T,
	params createTLSConfigParameters,
) (connection.TLSConfig, string) {
	t.Helper()
	tmpDir := t.TempDir()
	namingFunction := selectFileNames(params.namingStyle, params.san)
	//nolint:gofumpt //Note: gofumpt reports this line as improperly formatted, but no actual formatting issue exists.
	if sub := namingFunction(keySubDirectory); sub != "" {
		tmpDir = filepath.Join(tmpDir, sub)
		require.NoError(t, os.MkdirAll(tmpDir, 0700))
	}

	privateKeyPath := filepath.Join(tmpDir, namingFunction("private-key"))
	require.NoError(t, os.WriteFile(privateKeyPath, params.keyPair.Key, 0o600))

	publicKeyPath := filepath.Join(tmpDir, namingFunction("public-key"))
	require.NoError(t, os.WriteFile(publicKeyPath, params.keyPair.Cert, 0o600))

	caCertificatePath := filepath.Join(tmpDir, namingFunction("ca-certificate"))
	require.NoError(t, os.WriteFile(caCertificatePath, scm.CertificateAuthority.CertBytes(), 0o600))

	return connection.TLSConfig{
		Mode:        params.connectionMode,
		KeyPath:     privateKeyPath,
		CertPath:    publicKeyPath,
		CACertPaths: []string{caCertificatePath},
	}, tmpDir
}

func selectFileNames(style CertStyle, serverName string) func(string) string {
	switch style {
	case CertStyleYugabyte:
		return func(key string) string {
			switch key {
			case KeyPrivate:
				return fmt.Sprintf("node.%s.key", serverName)
			case KeyPublic:
				return fmt.Sprintf("node.%s.crt", serverName)
			case KeyCACert:
				return caCertFileName
			default:
				return ""
			}
		}
	case CertStylePostgres:
		return func(key string) string {
			switch key {
			case KeyPrivate:
				return "server.key"
			case KeyPublic:
				return "server.crt"
			case KeyCACert:
				return caCertFileName
			default:
				return ""
			}
		}
	default:
		return func(key string) string {
			switch key {
			case KeyPrivate:
				return "private-key.key"
			case KeyPublic:
				return "public-key.crt"
			case KeyCACert:
				return caCertFileName
			default:
				return ""
			}
		}
	}
}
