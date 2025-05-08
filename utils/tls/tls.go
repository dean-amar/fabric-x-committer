package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"google.golang.org/grpc/credentials"
	"os"
)

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
	return &tls.Config{RootCAs: certPool}, nil
}

func ConfigToCredentials(config *tls.Config) credentials.TransportCredentials {
	return credentials.NewTLS(config)
}

//func GetClientCredentials(config *connection.ServerConfig) (credentials.TransportCredentials, error) {
//	if config == nil {
//		return nil, errors.New("client to server connection configuration is nil.")
//	}
//
//	if config.ServerCreds == nil {
//		return insecure.NewCredentials(), nil
//	}
//
//	tlsCfg, err := LoadTLSCredentialsRaw([][]byte{connection.EncodeString(config.ServerCreds.RawCACert)})
//	if err != nil {
//		return nil, errors.Wrapf(err, "failed to load TLS credentials.")
//	}
//
//	if config.ServerCreds.MutualTLS {
//		clientCert, err := tls.X509KeyPair(connection.EncodeString(config.ServerCreds.RawCert), connection.EncodeString(config.ServerCreds.RawKey))
//		if err != nil {
//			return nil, errors.Wrapf(err, "failed to load credential keys.")
//		}
//		tlsCfg.Certificates = []tls.Certificate{clientCert}
//	}
//
//	return ConfigToCredentials(tlsCfg), nil
//}
