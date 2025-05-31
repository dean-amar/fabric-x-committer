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
type SecureCommunicationManager struct {
	CertificateAuthority tlsgen.CA
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
	serverKeypair, err := scm.CertificateAuthority.NewServerCertKeyPair(serverNameIndicator)
	require.NoError(t, err)
	return createCertificatesPaths(t, createDataFromKeyPair(serverKeypair, scm.CertificateAuthority.CertBytes()))
}

// CreateClientCertificate creates a client key pair,
// Writing it to a temp testing folder and returns a map with the credential paths.
func (scm *SecureCommunicationManager) CreateClientCertificate(t *testing.T) map[string]string {
	t.Helper()
	clientKeypair, err := scm.CertificateAuthority.NewClientCertKeyPair()
	require.NoError(t, err)
	return createCertificatesPaths(t, createDataFromKeyPair(clientKeypair, scm.CertificateAuthority.CertBytes()))
}

func (scm *SecureCommunicationManager) CreateServerDATA(
	t *testing.T,
	serverNameIndicator string,
) map[string][]byte {
	t.Helper()
	serverKeypair, err := scm.CertificateAuthority.NewServerCertKeyPair(serverNameIndicator)
	require.NoError(t, err)
	return createDataFromKeyPair(serverKeypair, scm.CertificateAuthority.CertBytes())
}

func (scm *SecureCommunicationManager) CreateDatabaseCreds(
	t *testing.T,
	serverNameIndicator string,
) (string, map[string]string) {
	t.Helper()
	serverKeypair, err := scm.CertificateAuthority.NewServerCertKeyPair(serverNameIndicator)
	require.NoError(t, err)
	return CreateCertificatesPath(t, createDataFromKeyPair(serverKeypair, scm.CertificateAuthority.CertBytes()))
}

func CreateCertificatesPath(t *testing.T, data map[string][]byte) (string, map[string]string) {
	t.Helper()
	tmpDir := t.TempDir()
	//t.Cleanup(func() {
	//	require.NoError(t, os.RemoveAll(tmpDir))
	//})

	paths := make(map[string]string)
	var name string
	for key, value := range data {
		switch key {
		case "private-key":
			name = "server.key"
		case "public-key":
			name = "server.crt"
		case "ca-certificate":
			name = "ca.crt"
		default:
			t.Errorf("wrong key")
		}
		dataPath, err := saveBytesToFile(tmpDir, name, value)
		require.NoError(t, err)
		t.Logf("key: %v, path: %v", key, dataPath)
		paths[key] = dataPath
	}

	t.Logf("dir path: %v", tmpDir)
	listDirectoryContents(tmpDir)

	return tmpDir, paths
}

func listDirectoryContents(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", path, err)
	}

	fmt.Printf("Contents of %s:\n", path)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("error reading entry info: %w", err)
		}
		fmt.Printf("- %s (size: %d bytes)\n", entry.Name(), info.Size())
	}

	return nil
}

func createCertificatesPaths(t *testing.T, data map[string][]byte) map[string]string {
	t.Helper()
	tmpDir := t.TempDir()
	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(tmpDir))
	})

	paths := make(map[string]string)

	for key, value := range data {
		dataPath, err := saveBytesToFile(tmpDir, key, value)
		require.NoError(t, err)
		paths[key] = dataPath
	}
	return paths
}

func createDataFromKeyPair(keyPair *tlsgen.CertKeyPair, caCertificate []byte) map[string][]byte {
	data := make(map[string][]byte)
	data["private-key"] = keyPair.Key
	data["public-key"] = keyPair.Cert
	data["ca-certificate"] = caCertificate
	return data
}

func saveBytesToFile(dir, filename string, data []byte) (string, error) {
	filePath := filepath.Join(dir, filename)
	return filePath, os.WriteFile(filePath, data, 0644)
}
