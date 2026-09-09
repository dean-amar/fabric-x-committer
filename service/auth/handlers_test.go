/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

const resourceGetTxStatus = "/committerpb.QueryService/GetTransactionStatus"

func TestAuthenticateAndAuthorizeNoMTLS(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx := context.Background()

	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
	})
	require.NoError(t, err)
	require.NotEmpty(t, authResp.GetToken())
	require.Greater(t, authResp.GetExpiresAt(), time.Now().Unix())

	azResp, err := svc.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token:    authResp.GetToken(),
		Resource: resourceGetRows,
	})
	require.NoError(t, err)
	require.True(t, azResp.GetAuthorized())
}

func TestAuthenticateAndAuthorizeMTLS(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx, certHash := peerContextWithCert(t)

	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), certHash),
	})
	require.NoError(t, err)

	// The resource server presents the same certificate, so the binding holds.
	azResp, err := svc.Authorize(context.Background(), &servicepb.AuthorizeRequest{
		Token:       authResp.GetToken(),
		Resource:    resourceGetRows,
		TlsCertHash: certHash,
	})
	require.NoError(t, err)
	require.True(t, azResp.GetAuthorized())
}

func TestAuthenticateScopedTokenLimitsAuthorization(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx := context.Background()

	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
		RequestedScope: []string{resourceGetRows},
	})
	require.NoError(t, err)

	// In-scope resource is allowed.
	_, err = svc.Authorize(ctx, &servicepb.AuthorizeRequest{Token: authResp.GetToken(), Resource: resourceGetRows})
	require.NoError(t, err)

	// Out-of-scope resource is denied, even though the identity's policy would otherwise allow it.
	_, err = svc.Authorize(ctx, &servicepb.AuthorizeRequest{Token: authResp.GetToken(), Resource: resourceGetTxStatus})
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
}

// TestAuthorizeIsRepeatableForStreamRecheck covers how an established stream renews its decision: it
// re-presents the same token, so the service resolves the token to its record every time. That is what
// makes revocation observable to a stream, which an identity-only re-check could never see.
func TestAuthorizeIsRepeatableForStreamRecheck(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx := context.Background()

	// Step 1: Establish a stream's authorization; the response carries what the resource server caches.
	t.Log("Step 1: authenticate and authorize to establish the stream")
	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
	})
	require.NoError(t, err)
	azResp, err := svc.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token: authResp.GetToken(), Resource: resourceGetRows,
	})
	require.NoError(t, err)
	require.Equal(t, authResp.GetExpiresAt(), azResp.GetTokenExpiresAt(),
		"the resource server bounds its cached decision by the token's own expiry")

	// Step 2: A re-check with the same token succeeds while nothing has changed.
	t.Log("Step 2: re-check the same token, as a stream does when its cached decision lapses")
	_, err = svc.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token: authResp.GetToken(), Resource: resourceGetRows,
	})
	require.NoError(t, err)

	// Step 3: Revoke by deleting the record. The token itself is still a validly signed, unexpired JWT,
	// so only resolving it against the store can catch this - the point of re-presenting the token.
	t.Log("Step 3: revoke the token record and re-check")
	claims, err := svc.authorizer.signer.verify(authResp.GetToken())
	require.NoError(t, err)
	require.NoError(t, svc.store.delete(ctx, claims.ID))

	_, err = svc.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token: authResp.GetToken(), Resource: resourceGetRows,
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err),
		"a revoked token must fail the re-check even though the JWT is still valid")
}

// TestAuthorizeEnforcesNamespaceScope verifies the AuthService itself decides whether a token may
// touch the namespaces a request names. The resource server only reports what the request asked for.
func TestAuthorizeEnforcesNamespaceScope(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx := context.Background()

	// The requested scope is normalized on the way in: trimmed and de-duplicated.
	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope:      env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
		RequestedNamespaces: []string{testNS2, testNS2, " ns3 "},
	})
	require.NoError(t, err)
	scopedToken := authResp.GetToken()

	// An unscoped token may touch anything, including every namespace at once.
	unscoped, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
	})
	require.NoError(t, err)

	// Permitted cases.
	for _, tc := range []struct {
		name    string
		token   string
		request *servicepb.AuthorizeRequest
	}{
		{
			name:    "a namespace inside the token's scope",
			token:   scopedToken,
			request: &servicepb.AuthorizeRequest{Resource: resourceGetRows, Namespaces: []string{testNS2}},
		},
		{
			name:  "every namespace in the token's scope at once",
			token: scopedToken,
			request: &servicepb.AuthorizeRequest{
				Resource: resourceGetRows, Namespaces: []string{testNS2, testNS3},
			},
		},
		{
			name:    "an unscoped token asking for every namespace",
			token:   unscoped.GetToken(),
			request: &servicepb.AuthorizeRequest{Resource: resourceGetRows, AllNamespaces: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.request.Token = tc.token
			_, err := svc.Authorize(context.Background(), tc.request)
			require.NoError(t, err)
		})
	}

	// Denied cases - the gap this closes: a token bound to ns2 must not read ns1.
	for _, tc := range []struct {
		name    string
		request *servicepb.AuthorizeRequest
	}{
		{
			name:    "a namespace outside the token's scope",
			request: &servicepb.AuthorizeRequest{Resource: resourceGetRows, Namespaces: []string{testNS1}},
		},
		{
			name: "a permitted namespace mixed with an unpermitted one",
			request: &servicepb.AuthorizeRequest{
				Resource: resourceGetRows, Namespaces: []string{testNS2, testNS1},
			},
		},
		{
			// An unfiltered subscription cannot be satisfied by a scoped token, so it is refused rather
			// than silently narrowed.
			name:    "a request for every namespace",
			request: &servicepb.AuthorizeRequest{Resource: resourceGetRows, AllNamespaces: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.request.Token = scopedToken
			_, err := svc.Authorize(context.Background(), tc.request)
			require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
		})
	}
}

// TestAuthenticateRejectsReplayedNonce verifies the challenge is single-use: replaying a byte-identical
// envelope fails even inside the freshness window, which is what the nonce adds over a time bound.
func TestAuthenticateRejectsReplayedNonce(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx := context.Background()

	envelope := env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil)
	_, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{SignedEnvelope: envelope})
	require.NoError(t, err)

	// The very same envelope, captured and resent.
	_, err = svc.Authenticate(ctx, &servicepb.AuthenticateRequest{SignedEnvelope: envelope})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "already used")
}

// TestAuthenticateRejectsUnissuedNonce verifies an envelope carrying a nonce the server never issued
// is refused, so a client cannot invent its own challenge.
func TestAuthenticateRejectsUnissuedNonce(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)

	for _, tc := range []struct {
		name  string
		nonce []byte
	}{
		{name: "nonce the server never issued", nonce: []byte("home-made-nonce")},
		{name: "no nonce at all", nonce: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Authenticate(context.Background(), &servicepb.AuthenticateRequest{
				SignedEnvelope: env.signedEnvelopeWithNonce(t, tc.nonce, nil),
			})
			require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
		})
	}
}

func TestAuthenticateRejects(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	for _, tc := range []struct {
		name     string
		envelope *common.Envelope
		wantCode codes.Code
	}{
		{name: "absent envelope", envelope: nil, wantCode: codes.InvalidArgument},
		{
			name:     "envelope whose payload is not a marshaled Payload",
			envelope: &common.Envelope{Payload: []byte("garbage")},
			wantCode: codes.Unauthenticated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, _ := newAuthServiceForTest(t, env)
			_, err := svc.Authenticate(context.Background(), &servicepb.AuthenticateRequest{
				SignedEnvelope: tc.envelope,
			})
			require.Equal(t, tc.wantCode, grpcerror.GetCode(err))
		})
	}
}

func TestAuthRPCsUnavailableBeforeBundle(t *testing.T) {
	t.Parallel()
	metrics := newAuthServiceMetrics()
	svc := &Service{config: &Config{}, metrics: metrics, provider: newConfigProvider(nil, metrics)}

	_, err := svc.Authenticate(context.Background(), &servicepb.AuthenticateRequest{
		SignedEnvelope: &common.Envelope{Payload: []byte("x")},
	})
	require.Equal(t, codes.Unavailable, grpcerror.GetCode(err))

	_, err = svc.Authorize(context.Background(), &servicepb.AuthorizeRequest{Token: "t", Resource: resourceGetRows})
	require.Equal(t, codes.Unavailable, grpcerror.GetCode(err))
}

func TestAuthorizeRejects(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	for _, tc := range []struct {
		name     string
		request  func(t *testing.T, svc *Service, signer *tokenSigner) *servicepb.AuthorizeRequest
		wantCode codes.Code
	}{
		{
			name: "invalid token",
			request: func(*testing.T, *Service, *tokenSigner) *servicepb.AuthorizeRequest {
				return &servicepb.AuthorizeRequest{Token: "not.a.jwt", Resource: resourceGetRows}
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "unknown token (verified but not stored)",
			request: func(t *testing.T, _ *Service, signer *tokenSigner) *servicepb.AuthorizeRequest {
				t.Helper()
				token, err := signer.mint(testRecord("ghost", time.Now().Add(time.Hour)), time.Now())
				require.NoError(t, err)
				return &servicepb.AuthorizeRequest{Token: token, Resource: resourceGetRows}
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "expired token",
			request: func(t *testing.T, _ *Service, signer *tokenSigner) *servicepb.AuthorizeRequest {
				t.Helper()
				expired := testRecord("old", time.Now().Add(-time.Hour))
				token, err := signer.mint(expired, time.Now().Add(-2*time.Hour))
				require.NoError(t, err)
				return &servicepb.AuthorizeRequest{Token: token, Resource: resourceGetRows}
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "certificate mismatch",
			request: func(t *testing.T, svc *Service, _ *tokenSigner) *servicepb.AuthorizeRequest {
				t.Helper()
				ctx, certHash := peerContextWithCert(t)
				resp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
					SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), certHash),
				})
				require.NoError(t, err)
				return &servicepb.AuthorizeRequest{
					Token: resp.GetToken(), Resource: resourceGetRows, TlsCertHash: []byte{0xFF},
				}
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "no policy for resource",
			request: func(t *testing.T, svc *Service, _ *tokenSigner) *servicepb.AuthorizeRequest {
				t.Helper()
				resp, err := svc.Authenticate(context.Background(), &servicepb.AuthenticateRequest{
					SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
				})
				require.NoError(t, err)
				return &servicepb.AuthorizeRequest{Token: resp.GetToken(), Resource: "/unknown.Service/Method"}
			},
			wantCode: codes.PermissionDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, signer := newAuthServiceForTest(t, env)
			_, err := svc.Authorize(context.Background(), tc.request(t, svc, signer))
			require.Equal(t, tc.wantCode, grpcerror.GetCode(err))
		})
	}
}
