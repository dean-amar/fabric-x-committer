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
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
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
// makes token expiry observable to a stream, which an identity-only re-check could never see.
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

	// Step 3: A token whose record is gone - swept after expiry, or minted against a store that has
	// since been reset - must fail even though the JWT itself is still validly signed and unexpired.
	// Only resolving the token against the store catches that, which is why a stream re-presents it.
	t.Log("Step 3: drop the token record and re-check")
	claims, err := svc.authorizer.signer.verify(authResp.GetToken())
	require.NoError(t, err)
	_, err = svc.tokens.pool.Exec(ctx,
		"DELETE FROM "+statedb.AuthTokensTableName+" WHERE jti = $1", claims.ID)
	require.NoError(t, err)
	svc.tokens.cache.Delete(claims.ID)

	_, err = svc.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token: authResp.GetToken(), Resource: resourceGetRows,
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err),
		"a token whose record is absent must fail even though the JWT is still valid")
}

// TestChallengeRateLimitRejectsSpam verifies the limit on the two RPCs reachable without a token. It is
// what stops a caller who holds no credential from spamming IssueNonce - a database row per call - or
// Authenticate - a signature verification per call - into a denial of service.
func TestChallengeRateLimitRejectsSpam(t *testing.T) {
	t.Parallel()
	svc := NewAuthService(&Config{ChallengeRequestsPerSecond: 1, ChallengeBurst: 1})

	require.NoError(t, svc.allowChallenge(t.Context(), "IssueNonce"),
		"the first call is within the burst")
	err := svc.allowChallenge(t.Context(), "IssueNonce")
	require.Equal(t, codes.ResourceExhausted, grpcerror.GetCode(err),
		"the second call in the same second exhausts a 1/s limit")

	// The limit is shared, so Authenticate cannot be used to sidestep a budget IssueNonce has spent.
	err = svc.allowChallenge(t.Context(), "Authenticate")
	require.Equal(t, codes.ResourceExhausted, grpcerror.GetCode(err))
}

// TestChallengeRateLimitDisabled verifies a zero limit disables throttling rather than rejecting
// everything, so a test or single-user deployment can opt out.
func TestChallengeRateLimitDisabled(t *testing.T) {
	t.Parallel()
	svc := NewAuthService(&Config{ChallengeRequestsPerSecond: 0})

	for range 5 {
		require.NoError(t, svc.allowChallenge(t.Context(), "IssueNonce"))
	}
}

// TestConfigRejectsBurstAboveRate verifies the cross-field rule the config loader enforces: a burst
// larger than the rate would let a caller outrun the limit for a full second.
func TestConfigRejectsBurstAboveRate(t *testing.T) {
	t.Parallel()
	require.Error(t, (&Config{ChallengeRequestsPerSecond: 10, ChallengeBurst: 11}).Validate())
	require.NoError(t, (&Config{ChallengeRequestsPerSecond: 10, ChallengeBurst: 10}).Validate())
	require.NoError(t, (&Config{ChallengeRequestsPerSecond: 0, ChallengeBurst: 0}).Validate())
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
	svc := &Service{
		config:        &Config{},
		metrics:       metrics,
		channelConfig: &configProvider{metrics: metrics},
	}

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

// TestAuthorizeReportsStoreFailureAsUnavailable pins the classification a resource server depends on:
// a store that cannot answer is Unavailable, never a denial. Answering Unauthenticated here would make
// a database blip tear down every established stream at once, since a resource server treats that code
// as definitive - the very outcome the stream enforcer's transient tolerance exists to prevent.
func TestAuthorizeReportsStoreFailureAsUnavailable(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, signer := newAuthServiceForTest(t, env)

	token, err := signer.mint(testRecord("never-stored", time.Now().Add(time.Hour)), time.Now())
	require.NoError(t, err)

	// The token itself verifies, so authorization reaches the store - which can no longer answer, and
	// so cannot report the record as merely absent.
	svc.tokens.pool.Close()

	_, err = svc.Authorize(t.Context(), &servicepb.AuthorizeRequest{Token: token, Resource: resourceGetRows})
	require.Equal(t, codes.Unavailable, grpcerror.GetCode(err))
}
