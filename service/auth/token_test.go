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
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

const (
	testMSPID = "Org1MSP"
	testJTI   = "jti"
)

func TestTokenMintVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	signer := newEphemeralSigner(t)
	issuedAt := time.Now()

	for _, tc := range []struct {
		name string
		rec  *servicepb.TokenRecord
	}{
		{
			name: "full record with scope",
			rec: &servicepb.TokenRecord{
				Jti:            "jti-1",
				MspId:          testMSPID,
				CertHashSha256: []byte{0x01, 0x02, 0x03, 0x04},
				Scope:          []string{"ns2", "/committerpb.QueryService/GetRows"},
				IssuedSequence: 7,
				ExpiresAt:      issuedAt.Add(5 * time.Minute).Unix(),
			},
		},
		{
			name: "no scope",
			rec: &servicepb.TokenRecord{
				Jti:            "jti-2",
				MspId:          "Org2MSP",
				CertHashSha256: []byte{0xAA, 0xBB},
				IssuedSequence: 0,
				ExpiresAt:      issuedAt.Add(time.Hour).Unix(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			token, err := signer.mint(tc.rec, issuedAt)
			require.NoError(t, err)
			require.NotEmpty(t, token)

			claims, err := signer.verify(token)
			require.NoError(t, err)
			require.Equal(t, tokenIssuer, claims.Issuer)
			require.Equal(t, tc.rec.GetMspId(), claims.Subject)
			require.Equal(t, tc.rec.GetJti(), claims.ID)
			require.Equal(t, tc.rec.GetIssuedSequence(), claims.Seq)
			require.Equal(t, tc.rec.GetScope(), claims.Scope)
			require.Equal(t, tc.rec.GetExpiresAt(), claims.ExpiresAt.Unix())
			require.Equal(t, issuedAt.Unix(), claims.IssuedAt.Unix())
			// The cnf claim is the base64url (no padding) SHA-256 thumbprint of the TLS certificate.
			require.Equal(
				t,
				base64.RawURLEncoding.EncodeToString(tc.rec.GetCertHashSha256()),
				claims.Cnf.X5tS256,
			)
		})
	}
}

func TestTokenVerifyRejects(t *testing.T) {
	t.Parallel()
	signer := newEphemeralSigner(t)
	otherSigner := newEphemeralSigner(t)
	validRec := &servicepb.TokenRecord{
		Jti: testJTI, MspId: testMSPID, CertHashSha256: []byte{0x01}, ExpiresAt: futureUnix(),
	}
	expiredRec := &servicepb.TokenRecord{
		Jti: "expired", MspId: testMSPID, CertHashSha256: []byte{0x01},
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	}
	validClaims := jwt.RegisteredClaims{
		Issuer: tokenIssuer, ID: testJTI, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	// Flip a character of the signature segment, leaving a structurally valid token.
	tampered := mustMint(t, signer, validRec, time.Now())
	tampered = tampered[:len(tampered)-2] +
		flipChar(tampered[len(tampered)-2:len(tampered)-1]) + tampered[len(tampered)-1:]

	for _, tc := range []struct {
		name string
		// encoded is the serialized JWT to verify.
		encoded string
	}{
		{name: "expired token", encoded: mustMint(t, signer, expiredRec, time.Now().Add(-time.Hour))},
		{name: "signed by a different key", encoded: mustMint(t, otherSigner, validRec, time.Now())},
		{name: "tampered payload", encoded: tampered},
		{name: "malformed token", encoded: "not.a.valid.jwt"},
		{
			name: "wrong signing algorithm (HS256)",
			encoded: mustSignClaims(t, jwt.SigningMethodHS256, []byte("shared-secret"),
				&tokenClaims{RegisteredClaims: validClaims}),
		},
		{
			name: "wrong issuer",
			encoded: mustSignClaims(t, jwt.SigningMethodES256, signer.privateKey, &tokenClaims{
				Issuer: "someone-else", ID: testJTI, ExpiresAt: validClaims.ExpiresAt,
			}),
		},
		{
			name: "missing expiry",
			encoded: mustSignClaims(t, jwt.SigningMethodES256, signer.privateKey, &tokenClaims{
				Issuer: tokenIssuer, ID: testJTI,
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := signer.verify(tc.encoded)
			require.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

func TestNewTokenSignerFromFile(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Success cases: both PEM encodings load and produce a working signer.
	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "SEC1 EC PRIVATE KEY", path: writeSEC1Key(t, key)},
		{name: "PKCS#8 PRIVATE KEY", path: writePKCS8Key(t, key)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signer, signerErr := newTokenSigner(tc.path)
			require.NoError(t, signerErr)
			require.True(t, key.Equal(signer.privateKey))

			token, mintErr := signer.mint(&servicepb.TokenRecord{Jti: "j", ExpiresAt: futureUnix()}, time.Now())
			require.NoError(t, mintErr)
			_, err = signer.verify(token)
			require.NoError(t, err)
		})
	}

	// Failure cases.
	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "nonexistent file", path: filepath.Join(t.TempDir(), "absent.pem")},
		{name: "not a PEM file", path: writeFile(t, "signing.pem", []byte("this is not pem"))},
		{
			name: "PEM but not an EC key",
			path: writeFile(t, "signing.pem", pem.EncodeToMemory(
				&pem.Block{Type: pemPrivateKeyType, Bytes: []byte("garbage")},
			)),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, signerErr := newTokenSigner(tc.path)
			require.Error(t, signerErr)
		})
	}
}

const pemPrivateKeyType = "PRIVATE KEY"

func newEphemeralSigner(t *testing.T) *tokenSigner {
	t.Helper()
	signer, err := newTokenSigner("")
	require.NoError(t, err)
	return signer
}

// mustMint mints a token from rec as though it were issued at issuedAt.
func mustMint(t *testing.T, signer *tokenSigner, rec *servicepb.TokenRecord, issuedAt time.Time) string {
	t.Helper()
	token, err := signer.mint(rec, issuedAt)
	require.NoError(t, err)
	return token
}

// mustSignClaims signs claims directly, for the cases a mint cannot produce: a foreign algorithm,
// a foreign issuer, or absent registered claims.
func mustSignClaims(t *testing.T, method jwt.SigningMethod, key any, claims *tokenClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return token
}

func futureUnix() int64 {
	return time.Now().Add(time.Hour).Unix()
}

func flipChar(s string) string {
	if s == "A" {
		return "B"
	}
	return "A"
}

func writeSEC1Key(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return writeFile(t, "sec1.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func writePKCS8Key(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return writeFile(t, "pkcs8.pem", pem.EncodeToMemory(&pem.Block{Type: pemPrivateKeyType, Bytes: der}))
}

func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}
