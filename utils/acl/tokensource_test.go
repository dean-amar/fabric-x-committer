/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

const testChannel = "test-channel"

func TestTokenSourceAuthenticatesAndCaches(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthenticator{token: "tok-1", expiresAt: time.Now().Add(time.Hour).Unix()}
	source := NewTokenSource(TokenSourceConfig{
		Client:                   auth,
		Signer:                   fakeSigner{},
		ChannelID:                testChannel,
		RequireTransportSecurity: true,
	})

	md, err := source.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", md[TokenMetadataKey])
	require.Equal(t, 1, auth.calls)

	// A second call reuses the cached, still-valid token without re-authenticating.
	md, err = source.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	require.Equal(t, "tok-1", md[TokenMetadataKey])
	require.Equal(t, 1, auth.calls)

	require.True(t, source.RequireTransportSecurity())
}

func TestTokenSourceRefreshesExpiredToken(t *testing.T) {
	t.Parallel()
	// A token already past expiry forces re-authentication on the next call.
	auth := &fakeAuthenticator{token: "tok", expiresAt: time.Now().Add(-time.Second).Unix()}
	source := NewTokenSource(TokenSourceConfig{Client: auth, Signer: fakeSigner{}, ChannelID: testChannel})

	_, err := source.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, auth.calls)

	_, err = source.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, auth.calls)
}

func TestTokenSourceFallsBackToValidCachedToken(t *testing.T) {
	t.Parallel()
	// Every re-authentication attempt fails.
	auth := &fakeAuthenticator{err: status.Error(codes.Unavailable, "auth service down")}
	source := NewTokenSource(TokenSourceConfig{Client: auth, Signer: fakeSigner{}, ChannelID: testChannel})

	// Simulate a previously issued token that is now inside its refresh window but not yet expired,
	// so the next call attempts a refresh.
	source.token = "cached"
	source.issuedAt = time.Now().Add(-time.Minute)
	source.expiresAt = time.Now().Add(2 * time.Second)

	// The refresh attempt fails, but the still-valid cached token is served instead of an error.
	md, err := source.GetRequestMetadata(context.Background())
	require.NoError(t, err)
	require.Equal(t, "cached", md[TokenMetadataKey])
	require.Equal(t, 1, auth.calls)
}

func TestTokenSourceAuthenticateError(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthenticator{err: status.Error(codes.Unauthenticated, "bad envelope")}
	source := NewTokenSource(TokenSourceConfig{Client: auth, Signer: fakeSigner{}, ChannelID: testChannel})

	_, err := source.GetRequestMetadata(context.Background())
	require.Error(t, err)
}

// fakeAuthenticator is a test double for servicepb.AuthServiceClient's Authenticate. It returns its
// token/expiry, or err on every call.
type fakeAuthenticator struct {
	token     string
	expiresAt int64
	err       error
	calls     int
}

func (f *fakeAuthenticator) Authenticate(
	context.Context, *servicepb.AuthenticateRequest, ...grpc.CallOption,
) (*servicepb.AuthenticateResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &servicepb.AuthenticateResponse{Token: f.token, ExpiresAt: f.expiresAt}, nil
}

func (*fakeAuthenticator) Authorize(
	context.Context, *servicepb.AuthorizeRequest, ...grpc.CallOption,
) (*servicepb.AuthorizeResponse, error) {
	return nil, errors.New("not implemented")
}

func (*fakeAuthenticator) ReAuthorize(
	context.Context, *servicepb.ReAuthorizeRequest, ...grpc.CallOption,
) (*servicepb.AuthorizeResponse, error) {
	return nil, errors.New("not implemented")
}

// fakeSigner is a minimal identity.SignerSerializer: the envelope it produces is well-formed but not
// cryptographically meaningful, which is all the token-source tests need.
type fakeSigner struct{}

func (fakeSigner) Sign([]byte) ([]byte, error) { return []byte("signature"), nil }
func (fakeSigner) Serialize() ([]byte, error)  { return []byte("creator"), nil }
