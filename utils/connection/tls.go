package connection

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
)

type ConfigTLS struct {
	UseTLS      bool         `mapstructure:"use-tls"`
	MutualTLS   bool         `mapstructure:"mutual-tls"`
	Credentials TLSCertPaths `mapstructure:",squash"`
}

type TLSCertPaths struct {
	CertPath   string `mapstructure:"cert-path"`
	KeyPath    string `mapstructure:"key-path"`
	CACertPath string `mapstructure:"ca-cert-path"`
}

func (c *ConfigTLS) ServerOption() grpc.ServerOption {
	if c == nil || !c.UseTLS {
		return grpc.Creds(insecure.NewCredentials())
	}

	cert, err := tls.LoadX509KeyPair(c.Credentials.CertPath, c.Credentials.KeyPath)
	utils.Must(err)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	if c.MutualTLS {
		certPool := x509.NewCertPool()
		certs, err := os.ReadFile(c.Credentials.CACertPath)
		utils.Must(err)
		if !certPool.AppendCertsFromPEM(certs) {
			panic("failed to add server CA's certificate")
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = certPool
	}

	return grpc.Creds(credentials.NewTLS(tlsCfg))
}

func (c *ConfigTLS) ClientOption() (credentials.TransportCredentials, error) {
	_, creds, err := c.ClientOptionWithConfig()
	return creds, err
}

func (c *ConfigTLS) ClientOptionWithConfig() (*tls.Config, credentials.TransportCredentials, error) {
	if c == nil || !c.UseTLS {
		return nil, insecure.NewCredentials(), nil
	}

	tlsCfg, err := LoadTLSCredentials([]string{c.Credentials.CACertPath})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to add server CA's certificate")
	}

	if c.MutualTLS {
		clientCert, err := tls.LoadX509KeyPair(c.Credentials.CertPath, c.Credentials.KeyPath)
		if err != nil {
			return tlsCfg, nil, errors.Join(err, errors.New("failed to load credential keys"))
		}
		tlsCfg.Certificates = []tls.Certificate{clientCert}
	}

	return tlsCfg, credentials.NewTLS(tlsCfg), nil
}

func LoadTLSCredentials(certPaths []string) (*tls.Config, error) {
	certs := make([][]byte, len(certPaths))
	var err error
	for i, p := range certPaths {
		// Load certificate of the CA who signed server's certificate
		certs[i], err = os.ReadFile(p)
		if err != nil {
			return nil, err
		}
	}
	return LoadTLSCredentialsRaw(certs)
}

func LoadTLSCredentialsRaw(certs [][]byte) (*tls.Config, error) {
	if len(certs) < 1 {
		return nil, fmt.Errorf("no ROOT CAS")
	}

	certPool := x509.NewCertPool()
	for _, cert := range certs {
		if !certPool.AppendCertsFromPEM(cert) {
			return nil, fmt.Errorf("failed to add server CA's certificate")
		}
	}

	// Create the credentials and return it
	return &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}
