/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

// tokenIssuer identifies the AuthService as the JWT issuer (the "iss" claim).
//
//nolint:gosec // G101: this is the issuer name embedded in tokens, not a credential.
const tokenIssuer = "committer-x-auth"

// ErrInvalidToken is returned when a token's signature, algorithm, structure, or expiry is invalid.
var ErrInvalidToken = errors.New("invalid token")

type (
	// tokenClaims are the JWT claims carried by a minted token. The persisted TokenRecord - not these
	// claims - is the authority for authorization; the claims exist to prove issuance (the signature),
	// to carry the token id ("jti") that keys the record, and to expose the certificate binding and
	// scope for observability.
	tokenClaims struct {
		jwt.RegisteredClaims
		// Cnf carries the RFC 8705 certificate confirmation: base64url(sha256(client TLS cert)).
		Cnf confirmation `json:"cnf"`
		// Scope is the optional least-privilege scope granted at issuance.
		Scope []string `json:"scope,omitempty"`
		// Seq is the channel-configuration sequence the identity was resolved against at issuance.
		Seq uint64 `json:"seq"`
	}

	// confirmation is the JWT "cnf" claim holding the certificate thumbprint per RFC 8705.
	confirmation struct {
		X5tS256 string `json:"x5t#S256"`
	}

	// tokenSigner mints and verifies ES256 JWTs. Only the AuthService holds the key; resource servers
	// never see it and never verify tokens themselves.
	tokenSigner struct {
		privateKey *ecdsa.PrivateKey
	}
)

// newTokenSigner loads a PEM-encoded EC (P-256) private key from keyPath, or generates an ephemeral
// key when keyPath is empty. An ephemeral key does not survive a restart and is not shared across
// instances, so it suits only single-instance dev deployments.
func newTokenSigner(keyPath string) (*tokenSigner, error) {
	if keyPath == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate ephemeral signing key")
		}
		logger.Warn("No signing-key-path configured: generated an ephemeral ES256 key. Tokens will " +
			"not survive a restart and cannot be verified by other AuthService instances.")
		return &tokenSigner{privateKey: key}, nil
	}

	key, err := loadECPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &tokenSigner{privateKey: key}, nil
}

// mint builds and signs a JWT for the given token record. issuedAt is the "iat" claim; the record's
// ExpiresAt is the "exp" claim.
func (s *tokenSigner) mint(rec *servicepb.TokenRecord, issuedAt time.Time) (string, error) {
	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, &tokenClaims{
		Issuer:    tokenIssuer,
		Subject:   rec.GetMspId(),
		ID:        rec.GetJti(),
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(time.Unix(rec.GetExpiresAt(), 0)),
		Cnf:       confirmation{X5tS256: base64.RawURLEncoding.EncodeToString(rec.GetCertHashSha256())},
		Scope:     rec.GetScope(),
		Seq:       rec.GetIssuedSequence(),
	}).SignedString(s.privateKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign token")
	}
	return signed, nil
}

// verify parses and validates a token, returning its claims. It verifies the ES256 signature, the
// algorithm, the issuer, and the (required) expiry, wrapping any failure in ErrInvalidToken. Every
// authorization goes through it, an established stream's renewals included, so an expired or revoked
// token is rejected wherever it is presented.
func (s *tokenSigner) verify(tokenString string) (*tokenClaims, error) {
	claims := &tokenClaims{}
	// The token's algorithm is already constrained to ES256 below, so the key function only has to
	// hand back the verification key.
	_, err := jwt.ParseWithClaims(
		tokenString, claims, func(*jwt.Token) (any, error) { return &s.privateKey.PublicKey, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidToken, err)
	}
	return claims, nil
}

// loadECPrivateKey reads a PEM-encoded EC (P-256) private key, accepting both the SEC1
// ("EC PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") encodings.
func loadECPrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read signing key from %s", keyPath)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.Newf("no PEM block found in signing key %s", keyPath)
	}

	// SEC1 first, then PKCS#8: both encodings are written by common tooling under indistinguishable
	// PEM headers, so which one a given file holds can only be discovered by trying.
	if sec1Key, sec1Err := x509.ParseECPrivateKey(block.Bytes); sec1Err == nil {
		return sec1Key, nil
	}
	pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "signing key %s is neither a valid SEC1 nor PKCS#8 EC private key", keyPath)
	}
	key, ok := pkcs8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Newf("signing key %s is not an EC private key (got %T)", keyPath, pkcs8)
	}
	return key, nil
}
