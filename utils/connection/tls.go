package connection

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// ConfigTLS contains the options and certificate paths
// for TLS connections between the servers and clients.
type ConfigTLS struct {
	UseTLS      bool     `mapstructure:"use-tls"`
	MutualTLS   bool     `mapstructure:"mutual-tls"`
	ServerName  string   `mapstructure:"server-name"`
	CertPath    string   `mapstructure:"cert-path"`
	KeyPath     string   `mapstructure:"key-path"`
	CACertPaths []string `mapstructure:"ca-cert-paths"`
}

// ServerOption returns the options for a grpc server.
//
//nolint:ireturn //this is intentional interface return for abstraction
func (c *ConfigTLS) ServerOption() (grpc.ServerOption, error) {
	if c == nil || !c.UseTLS {
		return grpc.Creds(insecure.NewCredentials()), nil
	}

	cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed loading the server certificate and private key")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	if c.MutualTLS {
		tmpConfig, err := loadTLSCredentials(c.CACertPaths)
		if err != nil {
			return nil, errors.Wrapf(err, "failed loading CAs.")
		}
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = tmpConfig.RootCAs
	}

	return grpc.Creds(credentials.NewTLS(tlsCfg)), nil
}

// ClientOption returns the options for a grpc client.
//
//nolint:ireturn //this is intentional interface return for abstraction
func (c *ConfigTLS) ClientOption() (credentials.TransportCredentials, error) {
	_, creds, err := c.ClientOptionWithConfig()
	return creds, err
}

// ClientOptionWithConfig returns the options for a grpc client and the tls configuration.
//
//nolint:ireturn //this is intentional interface return for abstraction
func (c *ConfigTLS) ClientOptionWithConfig() (*tls.Config, credentials.TransportCredentials, error) {
	if c == nil || !c.UseTLS {
		return nil, insecure.NewCredentials(), nil
	}

	tlsCfg, err := loadTLSCredentials(c.CACertPaths)
	if err != nil {
		return nil, nil, err
	}

	if c.MutualTLS {
		clientCert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to load credential keys")
		}
		tlsCfg.Certificates = []tls.Certificate{clientCert}
	}

	if c.ServerName != "" {
		tlsCfg.ServerName = c.ServerName
	}

	return tlsCfg, credentials.NewTLS(tlsCfg), nil
}

func loadTLSCredentials(certPaths []string) (*tls.Config, error) {
	certs := make([][]byte, len(certPaths))
	var err error
	for i, p := range certPaths {
		// Load certificate of the CA who signed server's certificate
		certs[i], err = os.ReadFile(p)
		if err != nil {
			return nil, errors.Wrapf(err, "failed reading the certificate path")
		}
	}
	return loadTLSCredentialsRaw(certs)
}

func loadTLSCredentialsRaw(certs [][]byte) (*tls.Config, error) {
	if len(certs) < 1 {
		return nil, errors.New("no ROOT CAS")
	}

	certPool := x509.NewCertPool()
	for _, cert := range certs {
		if ok := certPool.AppendCertsFromPEM(cert); !ok {
			return nil, errors.New("failed to add server CA's certificate")
		}
	}

	// Create the credentials and return it
	return &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}
