/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"crypto/x509"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var logger = flogging.MustGetLogger("acl")

// Role constants define the valid roles that can be extracted from certificates.
const (
	RoleAdmin  = "admin"
	RoleClient = "client"
	RoleMember = "member"
)

// Identity represents a validated client identity extracted from an X.509 certificate.
// It contains the essential information needed for access control decisions.
type Identity struct {
	// Certificate is the client's X.509 certificate
	Certificate *x509.Certificate

	// Organization is extracted from the certificate's Organization (O) field.
	// This typically represents the MSP ID (e.g., "Org1MSP").
	Organization string

	// Role is extracted from the certificate's Organizational Unit (OU) field.
	// Valid values are: "admin", "client", or "member".
	// If the OU field is missing or invalid, defaults to "member" (least privilege).
	Role string
}

var (
	// ErrNoPeerInfo is returned when the gRPC context does not contain peer information.
	ErrNoPeerInfo = errors.New("no peer info in gRPC context")

	// ErrNoTLSInfo is returned when the peer info does not contain TLS information.
	ErrNoTLSInfo = errors.New("no TLS info in peer context")

	// ErrNoCertificate is returned when no client certificate is provided in the TLS connection.
	// This typically means mTLS is not enabled on the server.
	ErrNoCertificate = errors.New("no client certificate provided - mTLS must be enabled")
)

// ExtractIdentityFromContext extracts the client identity from a gRPC context.
// It performs the following steps:
//  1. Extracts the peer certificate from the TLS connection
//  2. Extracts organization and role from certificate fields
//
// Note: Certificate validation (expiration, chain verification) is performed by the
// TLS layer when mTLS is enabled. By the time this function is called, the certificate
// has already been validated by the server's TLS configuration.
//
// Returns an error if:
//   - The context does not contain peer/TLS information
//   - No client certificate is provided (mTLS not enabled)
//   - Required certificate fields are missing
func ExtractIdentityFromContext(ctx context.Context) (*Identity, error) {
	// Extract peer information from context
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.WithStack(ErrNoPeerInfo)
	}

	// Extract TLS information from peer
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.WithStack(ErrNoTLSInfo)
	}

	// Verify that a client certificate was provided
	// This will be empty if mTLS is not enabled
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, errors.WithStack(ErrNoCertificate)
	}

	// The first certificate in the chain is the client's certificate
	// The TLS layer has already validated this certificate against trusted CAs
	cert := tlsInfo.State.PeerCertificates[0]

	// Extract organization from certificate
	org := extractOrganization(cert)
	if org == "" {
		return nil, errors.New("certificate missing organization (O) field")
	}

	// Extract role from certificate (defaults to member if invalid)
	role := extractRole(cert)

	identity := &Identity{
		Certificate:  cert,
		Organization: org,
		Role:         role,
	}

	logger.Debugf("Extracted identity: org=%s role=%s subject=%s",
		identity.Organization, identity.Role, cert.Subject.String())

	return identity, nil
}

// extractOrganization extracts the organization from the certificate's Organization (O) field.
// Returns the first organization if multiple are present, or empty string if none.
func extractOrganization(cert *x509.Certificate) string {
	if len(cert.Subject.Organization) == 0 {
		return ""
	}
	return cert.Subject.Organization[0]
}

// extractRole extracts the role from the certificate's Organizational Unit (OU) field.
// It validates the role against a whitelist of valid roles.
// If the OU field is missing or contains an invalid role, defaults to "member" (least privilege).
//
// Valid roles: admin, client, member
func extractRole(cert *x509.Certificate) string {
	// If no OU field, default to member (least privilege)
	if len(cert.Subject.OrganizationalUnit) == 0 {
		logger.Debugf("Certificate has no OU field, defaulting to role: %s", RoleMember)
		return RoleMember
	}

	// Extract and validate the first OU value
	role := cert.Subject.OrganizationalUnit[0]
	switch role {
	case RoleAdmin, RoleClient, RoleMember:
		return role
	default:
		logger.Warnf("Certificate has invalid role '%s', defaulting to: %s", role, RoleMember)
		return RoleMember
	}
}
