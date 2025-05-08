package connection

import (
	cryptoTLS "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection/tlsgen"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"path/filepath"
	"testing"
)

type ConfigTLS struct {
	MutualTLS bool `mapstructure:"mutual-tls"`
	UseTLS    bool `mapstructure:"use-tls"`

	CertPath string `mapstructure:"cert-path"`
	KeyPath  string `mapstructure:"key-path"`
	CACert   string `mapstructure:"ca-cert-path"`
}

func (c *ConfigTLS) ServerOption() grpc.ServerOption {
	if !c.UseTLS {
		return grpc.Creds(insecure.NewCredentials())
	}

	cert, err := cryptoTLS.LoadX509KeyPair(c.CertPath, c.KeyPath)
	utils.Must(err)

	tlsCfg := &cryptoTLS.Config{
		Certificates: []cryptoTLS.Certificate{cert},
		ClientAuth:   cryptoTLS.NoClientCert,
	}

	if c.MutualTLS {
		certPool := x509.NewCertPool()
		certs, err := os.ReadFile(c.CACert)
		utils.Must(err)
		if !certPool.AppendCertsFromPEM(certs) {
			panic("failed to add server CA's certificate")
		}
		tlsCfg.ClientAuth = cryptoTLS.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = certPool
	}

	return grpc.Creds(credentials.NewTLS(tlsCfg))
}

func (c *ConfigTLS) ClientOption() (credentials.TransportCredentials, error) {
	fmt.Printf("TLS config is: %v\n", *c)
	if !c.UseTLS {
		fmt.Println("no credentials provided for client connections")
		return insecure.NewCredentials(), nil
	}

	certPool := x509.NewCertPool()
	cert, err := os.ReadFile(c.CACert)
	if err != nil {
		return nil, err
	}
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	tlsCfg := &cryptoTLS.Config{RootCAs: certPool}
	if c.MutualTLS {
		clientCert, err := cryptoTLS.LoadX509KeyPair(c.CertPath, c.KeyPath)
		if err != nil {
			return nil, errors.Join(err, errors.New("failed to load credential keys"))
		}
		tlsCfg.Certificates = []cryptoTLS.Certificate{clientCert}
	}

	return tls.ConfigToCredentials(tlsCfg), nil
}

func (c *ConfigTLS) ClientOptionWithConfig() (*cryptoTLS.Config, credentials.TransportCredentials, error) {
	if !c.UseTLS {
		fmt.Println("no credentials provided for client connections")
		return nil, insecure.NewCredentials(), nil
	}

	certPool := x509.NewCertPool()
	cert, err := os.ReadFile(c.CACert)
	if err != nil {
		return nil, nil, err
	}
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		return nil, nil, fmt.Errorf("failed to add server CA's certificate")
	}

	tlsCfg := &cryptoTLS.Config{RootCAs: certPool}
	if c.MutualTLS {
		clientCert, err := cryptoTLS.LoadX509KeyPair(c.CertPath, c.KeyPath)
		if err != nil {
			return tlsCfg, nil, errors.Join(err, errors.New("failed to load credential keys"))
		}
		tlsCfg.Certificates = []cryptoTLS.Certificate{clientCert}
	}

	return tlsCfg, tls.ConfigToCredentials(tlsCfg), nil
}

func saveBytesToFile(dir, filename string, data []byte) (string, error) {
	filePath := filepath.Join(dir, filename)
	return filePath, os.WriteFile(filePath, data, 0644)
}

func CreateAndGetCerificatesPath(t *testing.T, data map[string][]byte) map[string]string {
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

func CreateAndSaveServerCertificateForTestEnv(t *testing.T, CA tlsgen.CA, host string) map[string]string {
	serverKeypair, err := CA.NewServerCertKeyPair(host)
	require.NoError(t, err)
	return CreateAndGetCerificatesPath(t, CreateDataFromKeyPair(serverKeypair, CA.CertBytes()))
}

func CreateAndSaveClientCertificateForTestEnv(t *testing.T, CA tlsgen.CA) map[string]string {
	clientKeypair, err := CA.NewClientCertKeyPair()
	require.NoError(t, err)
	return CreateAndGetCerificatesPath(t, CreateDataFromKeyPair(clientKeypair, CA.CertBytes()))
}

func CreateDataFromKeyPair(keyPair *tlsgen.CertKeyPair, CACertificate []byte) map[string][]byte {
	data := make(map[string][]byte)
	data["PrivateKey"] = keyPair.Key
	data["PublicKey"] = keyPair.Cert
	data["CACertificate"] = CACertificate
	return data
}

func EncodeToString(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}
