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

// tokenClaims are the JWT claims carried by a minted token. The persisted TokenRecord - not these
// claims - is the authority for authorization; the claims exist to prove issuance (the signature),
// to carry the token id ("jti") that keys the record, and to expose the certificate binding and
// scope for observability.
type tokenClaims struct {
	jwt.RegisteredClaims
	// Cnf carries the RFC 8705 certificate confirmation: base64url(sha256(client TLS cert)).
	Cnf confirmation `json:"cnf"`
	// Scope is the optional least-privilege scope granted at issuance.
	Scope []string `json:"scope,omitempty"`
	// Seq is the channel-configuration sequence the identity was resolved against at issuance.
	Seq uint64 `json:"seq"`
}

// confirmation is the JWT "cnf" claim holding the certificate thumbprint per RFC 8705.
type confirmation struct {
	X5tS256 string `json:"x5t#S256"`
}

// tokenSigner mints and verifies ES256 JWTs. Only the AuthService holds the key; resource servers
// never see it and never verify tokens themselves.
type tokenSigner struct {
	privateKey *ecdsa.PrivateKey
}

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
	claims := &tokenClaims{
		Issuer:    tokenIssuer,
		Subject:   rec.GetMspId(),
		ID:        rec.GetJti(),
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(time.Unix(rec.GetExpiresAt(), 0)),
		Cnf:       confirmation{X5tS256: base64.RawURLEncoding.EncodeToString(rec.GetCertHashSha256())},
		Scope:     rec.GetScope(),
		Seq:       rec.GetIssuedSequence(),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(s.privateKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign token")
	}
	return signed, nil
}

// verify parses and validates a token, returning its claims. It verifies the ES256 signature, the
// algorithm, the issuer, and the (required) expiry, wrapping any failure in ErrInvalidToken. Only
// Authenticate/Authorize verify tokens; long-lived stream re-authorization does not re-present the
// token (it re-evaluates the bound identity), so token verification is always strict.
func (s *tokenSigner) verify(tokenString string) (*tokenClaims, error) {
	claims := &tokenClaims{}
	_, err := jwt.ParseWithClaims(
		tokenString, claims, s.keyForToken,
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, errors.Join(ErrInvalidToken, err)
	}
	return claims, nil
}

// keyForToken returns the public key used to verify a token. The token's algorithm is already
// constrained to ES256 by jwt.WithValidMethods, so this only hands back the verification key.
func (s *tokenSigner) keyForToken(_ *jwt.Token) (any, error) {
	return &s.privateKey.PublicKey, nil
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

	key, err := parseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse EC private key from %s", keyPath)
	}
	return key, nil
}

// parseECPrivateKey parses DER key bytes as either a SEC1 or a PKCS#8 EC private key.
func parseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	pkcs8, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.Wrap(err, "key is neither a valid SEC1 nor PKCS#8 EC private key")
	}
	ecKey, ok := pkcs8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.Newf("signing key is not an EC private key (got %T)", pkcs8)
	}
	return ecKey, nil
}
