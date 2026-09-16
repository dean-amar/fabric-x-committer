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
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

const testChannel = "test-channel"

func TestMintTokenAttachesTokenToEveryRPC(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthenticator{token: testToken, expiresAt: time.Now().Add(time.Hour).Unix()}

	creds, err := MintToken(t.Context(), &MintParams{
		Client:              auth,
		Signer:              fakeSigner{},
		ChannelID:           testChannel,
		SecureTransportOnly: true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, auth.calls)
	require.True(t, creds.RequireTransportSecurity())

	// The token is fixed: repeated use attaches the same value and never calls the auth service again.
	for range 3 {
		md, mdErr := creds.GetRequestMetadata(t.Context())
		require.NoError(t, mdErr)
		require.Equal(t, map[string]string{TokenMetadataKey: testToken}, md)
	}
	require.Equal(t, 1, auth.calls)
	require.Equal(t, 1, auth.nonceCalls)
}

func TestMintTokenEmbedsServerNonce(t *testing.T) {
	t.Parallel()
	auth := &fakeAuthenticator{token: testToken, expiresAt: time.Now().Add(time.Hour).Unix()}

	_, err := MintToken(t.Context(), &MintParams{
		Client:    auth,
		Signer:    fakeSigner{},
		ChannelID: testChannel,
	})
	require.NoError(t, err)
	require.Equal(t, 1, auth.nonceCalls)

	// The nonce the server issued must travel in the signed payload, or the challenge proves nothing.
	require.NotNil(t, auth.lastEnvelope)
	payload, err := protoutil.UnmarshalPayload(auth.lastEnvelope.GetPayload())
	require.NoError(t, err)
	sigHeader, err := protoutil.UnmarshalSignatureHeader(payload.GetHeader().GetSignatureHeader())
	require.NoError(t, err)
	require.Equal(t, []byte("nonce"), sigHeader.GetNonce())

	channelHeader, err := protoutil.UnmarshalChannelHeader(payload.GetHeader().GetChannelHeader())
	require.NoError(t, err)
	require.Equal(t, testChannel, channelHeader.GetChannelId())
	// An authentication envelope carries no application data.
	require.Empty(t, payload.GetData())
}

func TestMintTokenFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		auth        *fakeAuthenticator
		expectedErr string
	}{
		{
			name:        "nonce is unavailable",
			auth:        &fakeAuthenticator{nonceErr: errors.New("auth service unreachable")},
			expectedErr: "failed to obtain an authentication nonce",
		},
		{
			name:        "envelope is rejected",
			auth:        &fakeAuthenticator{err: status.Error(codes.Unauthenticated, "bad envelope")},
			expectedErr: "failed to authenticate with the auth service",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creds, err := MintToken(t.Context(), &MintParams{
				Client:    tc.auth,
				Signer:    fakeSigner{},
				ChannelID: testChannel,
			})
			require.ErrorContains(t, err, tc.expectedErr)
			require.Nil(t, creds)
		})
	}
}

// fakeAuthenticator is a test double for servicepb.AuthServiceClient's Authenticate. It returns its
// token/expiry, or err on every call.
type fakeAuthenticator struct {
	token        string
	expiresAt    int64
	err          error
	calls        int
	lastEnvelope *common.Envelope
	nonceErr     error
	nonceCalls   int
}

func (f *fakeAuthenticator) Authenticate(
	_ context.Context, req *servicepb.AuthenticateRequest, _ ...grpc.CallOption,
) (*servicepb.AuthenticateResponse, error) {
	f.calls++
	f.lastEnvelope = req.GetSignedEnvelope()
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

// IssueNonce hands out a fixed nonce and counts the call, so a test can assert that every
// authentication attempt fetches a fresh challenge rather than reusing a spent one.
func (f *fakeAuthenticator) IssueNonce(
	context.Context, *servicepb.IssueNonceRequest, ...grpc.CallOption,
) (*servicepb.IssueNonceResponse, error) {
	f.nonceCalls++
	if f.nonceErr != nil {
		return nil, f.nonceErr
	}
	return &servicepb.IssueNonceResponse{Nonce: []byte("nonce")}, nil
}

// fakeSigner is a minimal identity.SignerSerializer: the envelope it produces is well-formed but not
// cryptographically meaningful, which is all these tests need.
type fakeSigner struct{}

func (fakeSigner) Sign([]byte) ([]byte, error) { return []byte("signature"), nil }
func (fakeSigner) Serialize() ([]byte, error)  { return []byte("creator"), nil }
