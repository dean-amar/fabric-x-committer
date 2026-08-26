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

	for _, tc := range []struct {
		name  string
		token func(t *testing.T) string
	}{
		{
			name: "expired token",
			token: func(t *testing.T) string {
				t.Helper()
				expired := &servicepb.TokenRecord{
					Jti: "expired", MspId: testMSPID, CertHashSha256: []byte{0x01},
					ExpiresAt: time.Now().Add(-time.Minute).Unix(),
				}
				token, err := signer.mint(expired, time.Now().Add(-time.Hour))
				require.NoError(t, err)
				return token
			},
		},
		{
			name: "signed by a different key",
			token: func(t *testing.T) string {
				t.Helper()
				token, err := otherSigner.mint(validRec, time.Now())
				require.NoError(t, err)
				return token
			},
		},
		{
			name: "tampered payload",
			token: func(t *testing.T) string {
				t.Helper()
				token, err := signer.mint(validRec, time.Now())
				require.NoError(t, err)
				// Flip the last byte of the signature segment.
				return token[:len(token)-2] + flipChar(token[len(token)-2:len(token)-1]) + token[len(token)-1:]
			},
		},
		{
			name: "wrong signing algorithm (HS256)",
			token: func(t *testing.T) string {
				t.Helper()
				claims := &tokenClaims{RegisteredClaims: jwt.RegisteredClaims{
					Issuer: tokenIssuer, ID: testJTI, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}}
				token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("shared-secret"))
				require.NoError(t, err)
				return token
			},
		},
		{
			name: "wrong issuer",
			token: func(t *testing.T) string {
				t.Helper()
				claims := &tokenClaims{RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "someone-else", ID: testJTI, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}}
				token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(signer.privateKey)
				require.NoError(t, err)
				return token
			},
		},
		{
			name:  "malformed token",
			token: func(*testing.T) string { return "not.a.valid.jwt" },
		},
		{
			name: "missing expiry",
			token: func(t *testing.T) string {
				t.Helper()
				claims := &tokenClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: tokenIssuer, ID: testJTI}}
				token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(signer.privateKey)
				require.NoError(t, err)
				return token
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := signer.verify(tc.token(t))
			require.ErrorIs(t, err, ErrInvalidToken)
		})
	}
}

func TestNewTokenSignerFromFile(t *testing.T) {
	t.Parallel()
	// Success cases: both PEM encodings load and produce a working signer.
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, key *ecdsa.PrivateKey) string
	}{
		{name: "SEC1 EC PRIVATE KEY", write: writeSEC1Key},
		{name: "PKCS#8 PRIVATE KEY", write: writePKCS8Key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			signer, err := newTokenSigner(tc.write(t, key))
			require.NoError(t, err)
			require.True(t, key.Equal(signer.privateKey))

			// The loaded key mints tokens that verify.
			token, err := signer.mint(&servicepb.TokenRecord{Jti: "j", ExpiresAt: futureUnix()}, time.Now())
			require.NoError(t, err)
			_, err = signer.verify(token)
			require.NoError(t, err)
		})
	}

	// Failure cases.
	for _, tc := range []struct {
		name    string
		keyPath func(t *testing.T) string
	}{
		{
			name:    "nonexistent file",
			keyPath: func(t *testing.T) string { t.Helper(); return filepath.Join(t.TempDir(), "absent.pem") },
		},
		{
			name: "not a PEM file",
			keyPath: func(t *testing.T) string {
				t.Helper()
				return writeFile(t, "signing.pem", []byte("this is not pem"))
			},
		},
		{
			name: "PEM but not an EC key",
			keyPath: func(t *testing.T) string {
				t.Helper()
				block := &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}
				return writeFile(t, "signing.pem", pem.EncodeToMemory(block))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := newTokenSigner(tc.keyPath(t))
			require.Error(t, err)
		})
	}
}

func TestNewTokenSignerEphemeral(t *testing.T) {
	t.Parallel()
	signer, err := newTokenSigner("")
	require.NoError(t, err)
	require.NotNil(t, signer.privateKey)

	token, err := signer.mint(&servicepb.TokenRecord{Jti: "j", ExpiresAt: futureUnix()}, time.Now())
	require.NoError(t, err)
	_, err = signer.verify(token)
	require.NoError(t, err)
}

func newEphemeralSigner(t *testing.T) *tokenSigner {
	t.Helper()
	signer, err := newTokenSigner("")
	require.NoError(t, err)
	return signer
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
	return writeFile(t, "pkcs8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}
