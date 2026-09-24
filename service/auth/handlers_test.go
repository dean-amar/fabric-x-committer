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

// TestAuthenticateAndAuthorize walks the whole mechanism: nonce -> signed envelope -> token -> a decision
// on a resource. Under mutual TLS the token is additionally bound to the certificate that minted it.
func TestAuthenticateAndAuthorize(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		mutualTLS bool
	}{
		{name: "without mutual TLS the token carries no certificate binding"},
		{name: "under mutual TLS the same certificate authorizes", mutualTLS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := newAuthTestEnv(t)
			svc, _ := newAuthServiceForTest(t, env)

			ctx := context.Background()
			var certHash []byte
			if tc.mutualTLS {
				ctx, certHash = peerContextWithCert(t)
			}
			authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
				SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), certHash),
			})
			require.NoError(t, err)
			require.NotEmpty(t, authResp.GetToken())
			require.Greater(t, authResp.GetExpiresAt(), time.Now().Unix())

			azResp, err := svc.Authorize(context.Background(), &servicepb.AuthorizeRequest{
				Token: authResp.GetToken(), Resource: resourceGetRows, TlsCertHash: certHash,
			})
			require.NoError(t, err)
			require.True(t, azResp.GetAuthorized())
		})
	}
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

// TestAuthorizeIsRepeatableForStreamRecheck covers a stream renewing its decision by re-presenting the
// same token, which is what makes expiry observable - an identity-only re-check could never see it.
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

	// Step 3: a token whose record is gone must fail even though the JWT is still validly signed. Only
	// resolving against the store catches that, which is why a stream re-presents the token.
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

// TestChallengeRateLimit verifies the budget on the two RPCs reachable without a token, which is what
// stops an uncredentialed caller spamming a database row or a signature check per call. It is shared, so
// Authenticate cannot sidestep what IssueNonce has spent; zero disables it rather than rejecting all.
func TestChallengeRateLimit(t *testing.T) {
	t.Parallel()
	limited := NewAuthService(&Config{ChallengeRequestsPerSecond: 1, ChallengeBurst: 1})
	require.NoError(t, limited.allowChallenge(), "the first call is within the burst")
	require.Error(t, limited.allowChallenge(), "the second call in the same second exhausts a 1/s limit")
	require.Error(t, limited.allowChallenge())

	unlimited := NewAuthService(&Config{ChallengeRequestsPerSecond: 0})
	for range 5 {
		require.NoError(t, unlimited.allowChallenge())
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

func TestAuthenticateRejects(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)

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
		{
			// A client cannot invent its own challenge: only a nonce the server issued is redeemable.
			name:     "nonce the server never issued",
			envelope: env.signedEnvelopeWithNonce(t, []byte("home-made-nonce"), nil),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "no nonce at all",
			envelope: env.signedEnvelopeWithNonce(t, nil, nil),
			wantCode: codes.Unauthenticated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
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
		config:              &Config{},
		metrics:             metrics,
		configBlockProvider: &configProvider{metrics: metrics},
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
	svc, signer := newAuthServiceForTest(t, env)
	ctx := context.Background()

	// Verifiable but never stored, so authorization resolves it against the store and finds nothing.
	ghostToken, err := signer.mint(testRecord("ghost", time.Now().Add(time.Hour)), time.Now())
	require.NoError(t, err)
	expiredToken, err := signer.mint(testRecord("old", time.Now().Add(-time.Hour)), time.Now().Add(-2*time.Hour))
	require.NoError(t, err)

	certCtx, certHash := peerContextWithCert(t)
	boundResp, err := svc.Authenticate(certCtx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), certHash),
	})
	require.NoError(t, err)
	plainResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelopeWithNonce(t, issueNonce(t, svc), nil),
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		request  *servicepb.AuthorizeRequest
		wantCode codes.Code
	}{
		{
			name:     "invalid token",
			request:  &servicepb.AuthorizeRequest{Token: "not.a.jwt", Resource: resourceGetRows},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "unknown token (verified but not stored)",
			request:  &servicepb.AuthorizeRequest{Token: ghostToken, Resource: resourceGetRows},
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "expired token",
			request:  &servicepb.AuthorizeRequest{Token: expiredToken, Resource: resourceGetRows},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "certificate mismatch",
			request: &servicepb.AuthorizeRequest{
				Token: boundResp.GetToken(), Resource: resourceGetRows, TlsCertHash: []byte{0xFF},
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "no policy for resource",
			request: &servicepb.AuthorizeRequest{
				Token: plainResp.GetToken(), Resource: "/unknown.Service/Method",
			},
			wantCode: codes.PermissionDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Authorize(context.Background(), tc.request)
			require.Equal(t, tc.wantCode, grpcerror.GetCode(err))
		})
	}
}

// TestAuthorizeReportsStoreFailureAsUnavailable pins the classification resource servers depend on: a
// store that cannot answer is Unavailable, never a denial, or a database blip tears down every stream.
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
