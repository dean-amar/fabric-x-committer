/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tlsgen

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric/common/crypto/tlsgen"
)

// SecureCommunicationManager responsible for the creation of
// TLS certificates for testing purposes by utilizing the tls generation library of 'Hyperledger Fabric'.
// Path map convention: private-key, public-key, ca-certificate.
type (
	SecureCommunicationManager struct {
		CertificateAuthority tlsgen.CA
	}

	// CertStyle sets the database certificates file formatting.
	CertStyle int
)

const (
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

var defaultNamingFunction = func(key string) string {
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

// NewSecureCommunicationManager returns a SecureCommunicationManager with a new CA.
func NewSecureCommunicationManager(t *testing.T) *SecureCommunicationManager {
	t.Helper()
	ca, err := tlsgen.NewCA()
	require.NoError(t, err)
	return &SecureCommunicationManager{
		CertificateAuthority: ca,
	}
}

// CreateServerCertificate creates a server key pair given SNI,
// Writing it to a temp testing folder and returns a map with the credential paths.
func (scm *SecureCommunicationManager) CreateServerCertificate(
	t *testing.T,
	serverNameIndicator string,
) map[string]string {
	t.Helper()
	_, paths := scm.CreateServerCreds(t, serverNameIndicator, CertStyleDefault)
	return paths
}

// CreateClientCertificate creates a client key pair,
// Writing it to a temp testing folder and returns a map with the credential paths.
func (scm *SecureCommunicationManager) CreateClientCertificate(t *testing.T) map[string]string {
	t.Helper()
	_, paths := scm.CreateClientCreds(t)
	return paths
}

// CreateServerCreds creates a server credentials,
// Writing it to a temp testing folder and returns the path to the credentials directory,
// and a map with the credential paths.
func (scm *SecureCommunicationManager) CreateServerCreds(t *testing.T, serverName string, style CertStyle,
) (string, map[string]string) {
	t.Helper()

	pair, err := scm.CertificateAuthority.NewServerCertKeyPair(serverName)
	require.NoError(t, err)

	namingStrategy := selectFileNames(style, serverName)

	return writeCertificateFiles(t, createDataFromKeyPair(pair, scm.CertificateAuthority.CertBytes()), namingStrategy)
}

// CreateClientCreds creates a client credentials,
// Writing it to a temp testing folder and returns the path to the credentials directory,
// and a map with the credential paths.
func (scm *SecureCommunicationManager) CreateClientCreds(t *testing.T) (string, map[string]string) {
	t.Helper()

	pair, err := scm.CertificateAuthority.NewClientCertKeyPair()
	require.NoError(t, err)

	return writeCertificateFiles(t,
		createDataFromKeyPair(pair, scm.CertificateAuthority.CertBytes()),
		defaultNamingFunction,
	)
}

func selectFileNames(style CertStyle, serverName string) func(string) string {
	switch style {
	case CertStyleYugabyte:
		suffix := fmt.Sprintf(".%s", serverName)
		return func(key string) string {
			switch key {
			case KeyPrivate:
				return "node" + suffix + ".key"
			case KeyPublic:
				return "node" + suffix + ".crt"
			case KeyCACert:
				return caCertFileName
			//case keySubDirectory:
			//	return serverName
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
		return defaultNamingFunction
	}
}

func writeCertificateFiles(
	t *testing.T,
	pair map[string][]byte,
	namingFunction func(key string) string,
) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()

	//nolint:gofumpt //Note: gofumpt reports this line as improperly formatted, but no actual formatting issue exists.
	if sub := namingFunction(keySubDirectory); sub != "" {
		dir = filepath.Join(dir, sub)
		require.NoError(t, os.MkdirAll(dir, 0700))
	}

	paths := make(map[string]string)
	for key, data := range pair {
		path, err := saveBytesToFile(dir, namingFunction(key), data)
		require.NoError(t, err)
		paths[key] = path
	}

	t.Logf("paths are: %v", paths)
	return dir, paths
}

func createDataFromKeyPair(keyPair *tlsgen.CertKeyPair, caCertificate []byte) map[string][]byte {
	data := make(map[string][]byte)
	data[KeyPrivate] = keyPair.Key
	data[KeyPublic] = keyPair.Cert
	data[KeyCACert] = caCertificate
	return data
}

func saveBytesToFile(dir, name string, data []byte) (string, error) {
	filePath := filepath.Join(dir, name)
	//nolint:gofumpt //Note: gofumpt reports this line as improperly formatted, but no actual formatting issue exists.
	err := os.WriteFile(filePath, data, 0600)
	return filePath, err
}
