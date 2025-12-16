/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package connection

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type (
	// MultiClientConfig contains the endpoints, TLS config, and retry profile.
	// This config allows the support of number of different endpoints to multiple service instances.
	MultiClientConfig struct {
		Endpoints []*Endpoint   `mapstructure:"endpoints" yaml:"endpoints"`
		TLS       TLSConfig     `mapstructure:"tls"       yaml:"tls"`
		Retry     *RetryProfile `mapstructure:"reconnect" yaml:"reconnect"`
	}

	// ClientConfig contains a single endpoint, TLS config, and retry profile.
	ClientConfig struct {
		Endpoint *Endpoint     `mapstructure:"endpoint"  yaml:"endpoint"`
		TLS      TLSConfig     `mapstructure:"tls"       yaml:"tls"`
		Retry    *RetryProfile `mapstructure:"reconnect" yaml:"reconnect"`
	}

	// ServerConfig describes the connection parameter for a server.
	ServerConfig struct {
		Endpoint  Endpoint               `mapstructure:"endpoint"`
		TLS       TLSConfig              `mapstructure:"tls"`
		KeepAlive *ServerKeepAliveConfig `mapstructure:"keep-alive"`

		preAllocatedListener net.Listener
	}

	// ServerKeepAliveConfig describes the keep alive parameters.
	ServerKeepAliveConfig struct {
		Params            *ServerKeepAliveParamsConfig            `mapstructure:"params"`
		EnforcementPolicy *ServerKeepAliveEnforcementPolicyConfig `mapstructure:"enforcement-policy"`
	}

	// ServerKeepAliveParamsConfig describes the keep alive policy.
	ServerKeepAliveParamsConfig struct {
		MaxConnectionIdle     time.Duration `mapstructure:"max-connection-idle"`
		MaxConnectionAge      time.Duration `mapstructure:"max-connection-age"`
		MaxConnectionAgeGrace time.Duration `mapstructure:"max-connection-age-grace"`
		Time                  time.Duration `mapstructure:"time"`
		Timeout               time.Duration `mapstructure:"timeout"`
	}

	// ServerKeepAliveEnforcementPolicyConfig describes the keep alive enforcement policy.
	ServerKeepAliveEnforcementPolicyConfig struct {
		MinTime             time.Duration `mapstructure:"min-time"`
		PermitWithoutStream bool          `mapstructure:"permit-without-stream"`
	}

	// BaseTLSConfig contains the essential fields for any TLS identity (Mode, Public Key, Private Key).
	// It is embedded into specific configs that need this foundation.
	BaseTLSConfig struct {
		Mode     string `mapstructure:"mode"`
		CertPath string `mapstructure:"cert-path"`
		KeyPath  string `mapstructure:"key-path"`
	}

	// TLSConfig holds the TLS options and certificate paths
	// used for secure communication between servers and clients.
	// Credentials are built based on the configuration mode.
	// For example, If only server-side TLS is required, the certificate pool (certPool) is not built (for a server),
	// since the relevant certificates paths are defined in the YAML according to the selected mode.
	TLSConfig struct {
		BaseTLSConfig `mapstructure:",squash"`
		CACertPaths   []string `mapstructure:"ca-cert-paths"`
	}

	// OrdererTLSConfig is a restricted config (identity only) for orderer clients.
	// It reuses the base fields but strictly excludes CA paths.
	OrdererTLSConfig struct {
		BaseTLSConfig `mapstructure:",squash"`
	}

	// TLSParameters holds the loaded runtime bytes.
	TLSParameters struct {
		Mode    string
		Cert    []byte
		Key     []byte
		CACerts [][]byte
	}
)

const (
	//nolint:revive // usage: TLS configuration modes.
	UnmentionedTLSMode = ""
	NoneTLSMode        = "none"
	OneSideTLSMode     = "tls"
	MutualTLSMode      = "mtls"

	// DefaultTLSMinVersion is the minimum version required to achieve secure connections.
	DefaultTLSMinVersion = tls.VersionTLS12
)

// ConvertToTLSConfig promotes the restricted Orderer config to a full TLSConfig.
// Note: The resulting config will have empty CA paths.
func (c OrdererTLSConfig) ConvertToTLSConfig() *TLSConfig {
	bc := c.BaseTLSConfig
	return &TLSConfig{
		BaseTLSConfig: bc,
	}
}

// ToOrdererTLSConfig narrows a full TLSConfig down to an OrdererTLSConfig.
// It effectively strips out the CA certificates, keeping only the Identity.
func (c TLSConfig) ToOrdererTLSConfig() OrdererTLSConfig {
	bc := c.BaseTLSConfig
	return OrdererTLSConfig{
		BaseTLSConfig: bc,
	}
}

func (c TLSConfig) ConvertToTLSParams() (*TLSParameters, error) {
	if c.Mode == NoneTLSMode {
		return &TLSParameters{
			Mode: c.Mode,
		}, nil
	}

	var (
		certBytes, keyBytes []byte
		err                 error
	)
	if c.CertPath != UnmentionedTLSMode {
		certBytes, err = os.ReadFile(c.CertPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load certificate from %s", c.CertPath)
		}
	}

	if c.KeyPath != UnmentionedTLSMode {
		keyBytes, err = os.ReadFile(c.KeyPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load private key from %s", c.KeyPath)
		}
	}

	caCertBytes := make([][]byte, 0, len(c.CACertPaths))
	for _, caCertPath := range c.CACertPaths {
		caBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load root CA cert from %s", caCertPath)
		}
		caCertBytes = append(caCertBytes, caBytes)
	}

	return &TLSParameters{
		Mode:    c.Mode,
		Cert:    certBytes,
		Key:     keyBytes,
		CACerts: caCertBytes,
	}, nil
}

// ServerCredentials returns the gRPC transport credentials to be used by a server,
// based on the provided TLS configuration after converting it to bytes.
func (c TLSConfig) ServerCredentials() (credentials.TransportCredentials, error) {
	tlsConfigParams, err := c.ConvertToTLSParams()
	if err != nil {
		return nil, err
	}
	return tlsConfigParams.ServerCredentials()
}

// ClientCredentials returns the gRPC transport credentials to be used by a client,
// based on the provided TLS configuration after converting it to bytes.
func (c TLSConfig) ClientCredentials() (credentials.TransportCredentials, error) {
	tlsConfigParams, err := c.ConvertToTLSParams()
	if err != nil {
		return nil, err
	}
	return tlsConfigParams.ClientCredentials()
}

// ServerCredentials returns the gRPC transport credentials to be used by a server,
// based on the provided TLS configuration.
func (c TLSParameters) ServerCredentials() (credentials.TransportCredentials, error) {
	switch c.Mode {
	case NoneTLSMode, UnmentionedTLSMode:
		return insecure.NewCredentials(), nil
	case OneSideTLSMode, MutualTLSMode:
		tlsCfg := &tls.Config{
			MinVersion: DefaultTLSMinVersion,
			ClientAuth: tls.NoClientCert,
		}

		// Load server certificate and key pair (required for both modes)
		cert, err := tls.X509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load server certificates")
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)

		// Load CA certificate pool (only for mutual TLS)
		if c.Mode == MutualTLSMode {
			tlsCfg.ClientCAs, err = buildCertPool(c.CACerts)
			if err != nil {
				return nil, err
			}
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}

		return credentials.NewTLS(tlsCfg), nil
	default:
		return nil, errors.Newf("unknown TLS mode: %s (valid modes: %s, %s, %s)",
			c.Mode, NoneTLSMode, OneSideTLSMode, MutualTLSMode)
	}
}

// ClientCredentials returns the gRPC transport credentials to be used by a client,
// based on the provided TLS configuration.
func (c TLSParameters) ClientCredentials() (credentials.TransportCredentials, error) {
	switch c.Mode {
	case NoneTLSMode, UnmentionedTLSMode:
		return insecure.NewCredentials(), nil
	case OneSideTLSMode, MutualTLSMode:
		tlsCfg := &tls.Config{
			MinVersion: DefaultTLSMinVersion,
		}

		// Load client certificate and key pair (only for mutual TLS)
		if c.Mode == MutualTLSMode {
			cert, err := tls.X509KeyPair(c.Cert, c.Key)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to load client certificates")
			}
			tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
		}

		// Load CA certificate pool (required for both modes)
		var err error
		tlsCfg.RootCAs, err = buildCertPool(c.CACerts)
		if err != nil {
			return nil, err
		}

		return credentials.NewTLS(tlsCfg), nil
	default:
		return nil, errors.Newf("unknown TLS mode: %s (valid modes: %s, %s, %s)",
			c.Mode, NoneTLSMode, OneSideTLSMode, MutualTLSMode)
	}
}

func buildCertPool(rootCAs [][]byte) (*x509.CertPool, error) {
	if len(rootCAs) == 0 {
		return nil, errors.New("no CA certificates provided")
	}
	certPool := x509.NewCertPool()
	for _, rootCA := range rootCAs {
		if ok := certPool.AppendCertsFromPEM(rootCA); !ok {
			return nil, errors.Errorf("unable to parse CA cert")
		}
	}
	return certPool, nil
}
