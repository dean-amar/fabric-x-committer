/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"
	"time"

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
		SignedEnvelope: env.signedEnvelope(t, nil),
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
	require.NotEmpty(t, azResp.GetIdentity()) // returned so a stream session can bind it
}

func TestAuthenticateAndAuthorizeMTLS(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx, certHash := peerContextWithCert(t)

	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: env.signedEnvelope(t, certHash),
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
		SignedEnvelope: env.signedEnvelope(t, nil),
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

func TestReAuthorizeStreamIdentity(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	svc, _ := newAuthServiceForTest(t, env)
	ctx := context.Background()

	// Establish: Authorize returns the identity bound to the token.
	authResp, err := svc.Authenticate(ctx, &servicepb.AuthenticateRequest{SignedEnvelope: env.signedEnvelope(t, nil)})
	require.NoError(t, err)
	azResp, err := svc.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token: authResp.GetToken(), Resource: resourceGetRows,
	})
	require.NoError(t, err)
	identity := azResp.GetIdentity()
	require.NotEmpty(t, identity)

	// Re-authorizing the bound identity against the same resource succeeds, without a token.
	reResp, err := svc.ReAuthorize(ctx, &servicepb.ReAuthorizeRequest{Identity: identity, Resource: resourceGetRows})
	require.NoError(t, err)
	require.True(t, reResp.GetAuthorized())

	// Re-authorizing against a resource with no policy is denied.
	_, err = svc.ReAuthorize(ctx, &servicepb.ReAuthorizeRequest{
		Identity: identity, Resource: "/unknown.Service/Method",
	})
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))

	// A foreign identity (not in this bundle's MSP) is denied.
	foreign := newAuthTestEnv(t)
	foreignID, err := foreign.signer.Serialize()
	require.NoError(t, err)
	_, err = svc.ReAuthorize(ctx, &servicepb.ReAuthorizeRequest{Identity: foreignID, Resource: resourceGetRows})
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
}

func TestAuthenticateRejects(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	for _, tc := range []struct {
		name     string
		envelope []byte
		wantCode codes.Code
	}{
		{name: "empty envelope", envelope: nil, wantCode: codes.InvalidArgument},
		{name: "malformed envelope", envelope: []byte("garbage"), wantCode: codes.Unauthenticated},
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

	_, err := svc.Authenticate(context.Background(), &servicepb.AuthenticateRequest{SignedEnvelope: []byte("x")})
	require.Equal(t, codes.Unavailable, grpcerror.GetCode(err))

	_, err = svc.Authorize(context.Background(), &servicepb.AuthorizeRequest{Token: "t", Resource: resourceGetRows})
	require.Equal(t, codes.Unavailable, grpcerror.GetCode(err))

	_, err = svc.ReAuthorize(context.Background(), &servicepb.ReAuthorizeRequest{
		Identity: []byte("i"), Resource: resourceGetRows,
	})
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
					SignedEnvelope: env.signedEnvelope(t, certHash),
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
					SignedEnvelope: env.signedEnvelope(t, nil),
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
