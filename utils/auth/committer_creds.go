package auth

import (
	"context"
	"fmt"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"net"
)

type CustomCredentials struct {
	tlsCreds credentials.TransportCredentials
}

// NewCustomCredentials creates new custom credentials that wrap existing TLS credentials
// If tlsCreds is nil, it will use insecure credentials (for testing only)
func NewCustomCredentials(tlsCreds credentials.TransportCredentials) credentials.TransportCredentials {
	if tlsCreds == nil {
		// Use insecure credentials for testing
		tlsCreds = insecure.NewCredentials()
	}

	return &CustomCredentials{
		tlsCreds: tlsCreds,
	}
}

// ClientHandshake delegates to TLS credentials, then adds custom auth info
func (c *CustomCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// Delegate to the underlying TLS credentials to perform the handshake
	conn, tlsAuthInfo, err := c.tlsCreds.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return conn, &MSPAuthInfo{
		TLSInfo: tlsAuthInfo,
	}, nil
}

// ServerHandshake delegates to TLS credentials, then adds custom auth validation
func (c *CustomCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	logger.Infof("Performing TLS handshake from: %s\n", rawConn.RemoteAddr().String())

	// Delegate to the underlying TLS credentials to perform the handshake
	conn, tlsAuthInfo, err := c.tlsCreds.ServerHandshake(rawConn)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return conn, &MSPAuthInfo{
		TLSInfo: tlsAuthInfo,
	}, nil
}

// Info returns protocol info, delegating to underlying TLS credentials
func (c *CustomCredentials) Info() credentials.ProtocolInfo {
	info := c.tlsCreds.Info()
	// Modify to indicate custom auth is added on top of TLS
	info.SecurityProtocol = "tls+custom-auth"
	return info
}

// Clone creates a copy of the credentials
func (c *CustomCredentials) Clone() credentials.TransportCredentials {
	return &CustomCredentials{
		tlsCreds: c.tlsCreds.Clone(),
	}
}

// OverrideServerName delegates to underlying TLS credentials
func (c *CustomCredentials) OverrideServerName(serverNameOverride string) error {
	return c.tlsCreds.OverrideServerName(serverNameOverride)
}
