/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Chaguar/common/api/committerpb"
	"github.com/Chaguar/common/common/channelconfig"
	"github.com/Chaguar/common/msp"
	"github.com/Chaguar/common/protoutil"
	"github.com/Chaguar/common/utils/testcrypto"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Chaguar/committer/utils/acl"
	"github.com/Chaguar/committer/utils/connection"
	"github.com/Chaguar/committer/utils/grpcerror"
	"github.com/Chaguar/committer/utils/serve"
	"github.com/Chaguar/committer/utils/test"
)

// TestAuthSecureConnection verifies the auth service gRPC server's behavior
// under various client TLS configurations.
func TestAuthSecureConnection(t *testing.T) {
	t.Parallel()
	test.RunSecureConnectionTest(
		t,
		func(t *testing.T, serverTLS, clientTLS connection.TLSConfig) test.RPCAttempt {
			t.Helper()
			env := NewAuthTestEnv(t, &TestEnvParams{ServerTLS: serverTLS, ClientTLS: clientTLS})
			return func(ctx context.Context, t *testing.T, cfg connection.TLSConfig) error {
				t.Helper()
				client := test.CreateClientWithTLS(
					t, env.Config.Endpoints[0], cfg, committerpb.NewAuthServiceClient,
				)
				_, err := client.IssueNonce(ctx, nil)
				return err
			}
		},
	)
}

// TestAuthAuthorizeIdentityCases verifies the auth service's AuthorizeIdentity method under various token and
// resource conditions.
func TestAuthAuthorizeIdentityCases(t *testing.T) {
	t.Parallel()

	artifactsPath := t.TempDir()
	env := newAuthTestEnvWithMutualTLS(t, TestEnvParams{ArtifactsPath: artifactsPath})

	token := env.IssueToken(t)

	issueToken := func(p *acl.IssueParams) string {
		t.Helper()
		resp, err := acl.IssueToken(t.Context(), p)
		require.NoError(t, err)
		return resp.GetToken()
	}

	scopedParams := *env.IssueParams
	scopedParams.Scope = []string{committerpb.QueryService_GetRows_FullMethodName}
	scopedToken := issueToken(&scopedParams)

	// A consenter belongs to the orderer organization: a channel member, so it authenticates, yet outside
	// the application organizations that the Readers policy admits.
	consenters, err := testcrypto.GetConsenterIdentities(artifactsPath)
	require.NoError(t, err)
	require.NotEmpty(t, consenters)
	consenterParams := scopedParams
	consenterParams.Signer = consenters[0]
	consenterToken := issueToken(&consenterParams)

	// Success cases.
	for _, tc := range []struct {
		name     string
		token    string
		resource string
	}{
		{
			name:     "token scoped to every RPC",
			token:    token,
			resource: committerpb.QueryService_GetRows_FullMethodName,
		},
		{
			name:     "scoped token within its scope",
			token:    scopedToken,
			resource: committerpb.QueryService_GetRows_FullMethodName,
		},
		{
			// A resource the channel configuration's ACLs do not name falls back to the Readers policy.
			name:     "resource with no ACL falls back to the Readers policy",
			token:    token,
			resource: committerpb.SidecarService_DeleteDBCloneForSnapshot_FullMethodName,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, err := env.Client.AuthorizeIdentity(t.Context(), &committerpb.AuthorizeIdentityRequest{
				Token:       tc.token,
				Resource:    tc.resource,
				TlsCertHash: env.TLSCertHash,
			})
			require.NoError(t, err)
			// The resource server bounds its cached decision for a stream by the token's own expiry.
			require.True(t, resp.GetTokenExpireTime().AsTime().After(time.Now()))
		})
	}

	// Failure cases.
	for _, tc := range []struct {
		name     string
		request  *committerpb.AuthorizeIdentityRequest
		wantCode codes.Code
	}{
		{
			name: "unknown token",
			request: &committerpb.AuthorizeIdentityRequest{
				Token:       "never-issued",
				Resource:    committerpb.QueryService_GetRows_FullMethodName,
				TlsCertHash: env.TLSCertHash,
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "empty token",
			request: &committerpb.AuthorizeIdentityRequest{
				Resource:    committerpb.QueryService_GetRows_FullMethodName,
				TlsCertHash: env.TLSCertHash,
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "certificate mismatch",
			request: &committerpb.AuthorizeIdentityRequest{
				Token:       token,
				Resource:    committerpb.QueryService_GetRows_FullMethodName,
				TlsCertHash: []byte{0xFF},
			},
			wantCode: codes.Unauthenticated,
		},
		{
			name: "identity outside the resource policy",
			request: &committerpb.AuthorizeIdentityRequest{
				Token:       consenterToken,
				Resource:    committerpb.QueryService_GetRows_FullMethodName,
				TlsCertHash: env.TLSCertHash,
			},
			wantCode: codes.PermissionDenied,
		},
		{
			// Denied although the identity's policy would otherwise allow it.
			name: "scoped token outside its scope",
			request: &committerpb.AuthorizeIdentityRequest{
				Token:       scopedToken,
				Resource:    committerpb.QueryService_GetTransactionStatus_FullMethodName,
				TlsCertHash: env.TLSCertHash,
			},
			wantCode: codes.PermissionDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := env.Client.AuthorizeIdentity(t.Context(), tc.request)
			require.Equal(t, tc.wantCode, grpcerror.GetCode(err))
		})
	}
}

// TestAuthorizeIdentityRejectsExpiredToken verifies that the auth service accepts a token until it expires and
// rejects it afterward, and that the record keeps the expiry's full precision rather than whole seconds.
func TestAuthorizeIdentityRejectsExpiredToken(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnvWithMutualTLS(t, TestEnvParams{TokenTTL: 2 * time.Second})
	issuedAfter := time.Now()
	req := &committerpb.AuthorizeIdentityRequest{
		Token:       env.IssueToken(t),
		Resource:    committerpb.QueryService_GetRows_FullMethodName,
		TlsCertHash: env.TLSCertHash,
	}

	resp, err := env.Client.AuthorizeIdentity(t.Context(), req)
	require.NoError(t, err)
	// Rounded down to whole seconds, the expiry would usually land before issuance plus the TTL.
	require.False(t, resp.GetTokenExpireTime().AsTime().Before(issuedAfter.Add(2*time.Second)))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := env.Client.AuthorizeIdentity(t.Context(), req)
		require.Equal(ct, codes.Unauthenticated, grpcerror.GetCode(err))
		require.ErrorContains(ct, err, "token has expired")
	}, 10*time.Second, 200*time.Millisecond)
}

// TestAuthorizeIdentityFollowsConfigUpdate verifies a token is re-resolved against each newly committed
// configuration: once the client's organization rotates to a new CA, its existing token is denied.
func TestAuthorizeIdentityFollowsConfigUpdate(t *testing.T) {
	t.Parallel()

	// Step 1: A token authorizes under the initial configuration.
	t.Log("Step 1: authorize under configuration version 0")
	env := NewAuthTestEnv(t, nil)
	req := &committerpb.AuthorizeIdentityRequest{
		Token:       env.IssueToken(t),
		Resource:    committerpb.QueryService_GetRows_FullMethodName,
		TlsCertHash: env.TLSCertHash,
	}
	_, err := env.Client.AuthorizeIdentity(t.Context(), req)
	require.NoError(t, err)

	// Step 2: Commit version 1, whose crypto is generated afresh, so the client's certificate chains to a CA
	// the new configuration no longer trusts.
	t.Log("Step 2: commit configuration version 1 with a rotated CA")
	newConfigBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(t.TempDir(), &testcrypto.ConfigBlock{
		ChannelID:             env.ChannelID,
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)
	seedConfigTransaction(t, env.dbConf, newConfigBlock, 1)

	// Step 3: The same token is denied once the service refreshes, without being reissued.
	t.Log("Step 3: the token is denied under the new configuration")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := env.Client.AuthorizeIdentity(t.Context(), req)
		require.Equal(ct, codes.PermissionDenied, grpcerror.GetCode(err))
	}, 10*time.Second, 100*time.Millisecond)
}

// TestAuthAuthenticateIdentityCases verifies the auth service's AuthenticateIdentity method under various envelope
// conditions.
func TestAuthAuthenticateIdentityCases(t *testing.T) {
	t.Parallel()

	env := newAuthTestEnvWithMutualTLS(t, TestEnvParams{})

	// Success case: a genuine envelope yields a token scoped to the requested methods.
	nonce, err := env.Client.IssueNonce(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)
	resp, err := env.Client.AuthenticateIdentity(t.Context(), &committerpb.AuthenticateIdentityRequest{
		SignedEnvelope: buildEnvelope(t, &env.EnvelopeParams, nonce.GetNonce()),
		RequestedScope: []string{committerpb.QueryService_GetRows_FullMethodName},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetToken())
	require.True(t, resp.GetExpireTime().AsTime().After(time.Now()))

	// Failure cases.
	// The nonce is single-use: once redeemed, the very same envelope is worthless to whoever captured it,
	// even inside the freshness window.
	nonce, err = env.Client.IssueNonce(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)
	replayed := buildEnvelope(t, &env.EnvelopeParams, nonce.GetNonce())
	_, err = env.Client.AuthenticateIdentity(
		t.Context(), &committerpb.AuthenticateIdentityRequest{SignedEnvelope: replayed, RequestedScope: env.Scope},
	)
	require.NoError(t, err)

	// withCertHash signs a fresh nonce with a certificate hash by desire.
	withCertHash := func(certHash []byte) *common.Envelope {
		resp, err := env.Client.IssueNonce(t.Context(), &emptypb.Empty{})
		require.NoError(t, err)
		params := env.EnvelopeParams
		params.TLSCertHash = certHash
		return buildEnvelope(t, &params, resp.GetNonce())
	}

	for _, tc := range []struct {
		name     string
		envelope *common.Envelope
		scope    []string
		wantCode codes.Code
		wantErr  string
	}{
		{
			name:     "absent envelope",
			scope:    env.Scope,
			wantCode: codes.InvalidArgument,
			wantErr:  errNoEnvelope.Error(),
		},
		{
			name:     "payload has no header",
			envelope: &common.Envelope{},
			scope:    env.Scope,
			wantCode: codes.Unauthenticated,
			wantErr:  "envelope payload has no header",
		},
		{
			// A client cannot invent its own challenge: only a nonce the server issued is redeemable.
			name:     "nonce the server never issued",
			envelope: buildEnvelope(t, &env.EnvelopeParams, bytes.Repeat([]byte{0x01}, randomLength)),
			scope:    env.Scope,
			wantCode: codes.Unauthenticated,
			wantErr:  errNonceNotFound.Error(),
		},
		{
			name:     "no nonce at all",
			envelope: buildEnvelope(t, &env.EnvelopeParams, nil),
			scope:    env.Scope,
			wantCode: codes.Unauthenticated,
			wantErr:  "envelope carries no nonce",
		},
		{
			name:     "replayed envelope",
			envelope: replayed,
			scope:    env.Scope,
			wantCode: codes.Unauthenticated,
			wantErr:  errNonceNotFound.Error(),
		},
		{
			name:     "certificate hash of another connection",
			envelope: withCertHash([]byte{0xFF}),
			scope:    env.Scope,
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "no certificate hash on a mutual TLS connection",
			envelope: withCertHash(nil),
			scope:    env.Scope,
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "scope naming an unknown RPC",
			envelope: withCertHash(env.TLSCertHash),
			scope:    []string{"/committerpb.QueryService/NoSuchMethod"},
			wantCode: codes.InvalidArgument,
			wantErr:  errUnknownScope.Error(),
		},
		{
			name:     "unscoped request",
			envelope: withCertHash(env.TLSCertHash),
			wantCode: codes.InvalidArgument,
			wantErr:  errEmptyScope.Error(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, authErr := env.Client.AuthenticateIdentity(t.Context(), &committerpb.AuthenticateIdentityRequest{
				SignedEnvelope: tc.envelope,
				RequestedScope: tc.scope,
			})
			require.Equal(t, tc.wantCode, grpcerror.GetCode(authErr))
			require.ErrorContains(t, authErr, tc.wantErr)
		})
	}
}

// TestVerifyEnvelope verifies each check verifyEnvelope applies. It calls verifyEnvelope directly, since over
// gRPC every failure surfaces as the same "authentication failed".
func TestVerifyEnvelope(t *testing.T) {
	t.Parallel()
	channelArtifactsPath := t.TempDir()
	channelConfigBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
		channelArtifactsPath,
		&testcrypto.ConfigBlock{ChannelID: defaultTestChannelID, PeerOrganizationCount: 1},
	)
	require.NoError(t, err)
	channelConfigEnvelope, err := protoutil.ExtractEnvelope(channelConfigBlock, 0)
	require.NoError(t, err)
	channelBundle, err := channelconfig.NewBundleFromEnvelope(channelConfigEnvelope, factory.GetDefault())
	require.NoError(t, err)
	channelMembers, err := testcrypto.GetPeersIdentities(channelArtifactsPath)
	require.NoError(t, err)

	// cryptogen names the foreign organization peer-org-0 as well, but under a CA the channel does not trust.
	foreignArtifactsPath := t.TempDir()
	_, err = testcrypto.CreateOrExtendConfigBlockWithCrypto(
		foreignArtifactsPath,
		&testcrypto.ConfigBlock{ChannelID: defaultTestChannelID, PeerOrganizationCount: 1},
	)
	require.NoError(t, err)
	foreignMembers, err := testcrypto.GetPeersIdentities(foreignArtifactsPath)
	require.NoError(t, err)

	authService := &Service{config: &Config{EnvelopeFreshnessWindow: 5 * time.Minute}}
	// verifyEnvelope reads only the parsed fields, so changing one after parsing is equivalent to signing an
	// envelope that carries the changed value.
	parseEnvelopeSignedBy := func(signer msp.SigningIdentity) *parsedEnvelope {
		parsed, err := parseSignedEnvelope(buildEnvelope(t, &acl.EnvelopeParams{
			Signer: signer, ChannelID: defaultTestChannelID,
		}, nil))
		require.NoError(t, err)
		return parsed
	}

	// Each case is a genuine envelope with exactly one property broken.
	signingTime := time.Now()
	transactionTypeEnvelope := parseEnvelopeSignedBy(channelMembers[0])
	transactionTypeEnvelope.chdr.Type = int32(common.HeaderType_ENDORSER_TRANSACTION)
	otherChannelEnvelope := parseEnvelopeSignedBy(channelMembers[0])
	otherChannelEnvelope.chdr.ChannelId = "other-channel"
	nonEmptyPayloadEnvelope := parseEnvelopeSignedBy(channelMembers[0])
	nonEmptyPayloadEnvelope.payloadData = []byte("transaction")
	staleTimestampEnvelope := parseEnvelopeSignedBy(channelMembers[0])
	staleTimestampEnvelope.chdr.Timestamp = timestamppb.New(signingTime.Add(-time.Hour))
	foreignSignerEnvelope := parseEnvelopeSignedBy(foreignMembers[0])
	tamperedSignatureEnvelope := parseEnvelopeSignedBy(channelMembers[0])
	signature := tamperedSignatureEnvelope.signedData.Signature
	signature[len(signature)-1] ^= 0xFF
	// cryptogen certificates last ten years. The timestamp moves along with the verification time, so only the
	// certificate's expiry fails.
	afterCertificateExpiry := signingTime.AddDate(11, 0, 0)
	expiredCertificateEnvelope := parseEnvelopeSignedBy(channelMembers[0])
	expiredCertificateEnvelope.chdr.Timestamp = timestamppb.New(afterCertificateExpiry)

	for _, tc := range []struct {
		name             string
		envelope         *parsedEnvelope
		verificationTime time.Time
		wantErr          string
	}{
		{
			name:             "header type of a transaction",
			envelope:         transactionTypeEnvelope,
			verificationTime: signingTime,
			wantErr:          errEnvelopeScope.Error(),
		},
		{
			name:             "another channel",
			envelope:         otherChannelEnvelope,
			verificationTime: signingTime,
			wantErr:          errEnvelopeScope.Error(),
		},
		{
			name:             "non-empty payload",
			envelope:         nonEmptyPayloadEnvelope,
			verificationTime: signingTime,
			wantErr:          errEnvelopeScope.Error(),
		},
		{
			name:             "timestamp outside the freshness window",
			envelope:         staleTimestampEnvelope,
			verificationTime: signingTime,
			wantErr:          errStaleEnvelope.Error(),
		},
		{
			name:             "signer outside the channel configuration",
			envelope:         foreignSignerEnvelope,
			verificationTime: signingTime,
			wantErr:          "failed to deserialize identity",
		},
		{
			name:             "expired certificate",
			envelope:         expiredCertificateEnvelope,
			verificationTime: afterCertificateExpiry,
			wantErr:          "identity expired",
		},
		{
			name:             "tampered signature",
			envelope:         tamperedSignatureEnvelope,
			verificationTime: signingTime,
			wantErr:          "signature verification failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := authService.verifyEnvelope(tc.envelope, channelBundle, nil, tc.verificationTime)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestValidateTimestamp verifies a timestamp that is missing or unrepresentable is refused as stale.
func TestValidateTimestamp(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ts   *timestamppb.Timestamp
	}{
		{name: "missing", ts: nil},
		{name: "unrepresentable", ts: &timestamppb.Timestamp{Nanos: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, validateTimestamp(tc.ts, time.Minute, time.Now()), errStaleEnvelope)
		})
	}
}

// TestAuthAcrossInstances verifies the instances share their state through the database: a nonce one instance
// issues is redeemed at another, and the token that yields authorizes at the first.
func TestAuthAcrossInstances(t *testing.T) {
	t.Parallel()
	env := NewAuthTestEnv(t, &TestEnvParams{Instances: 2})
	first := test.CreateClientWithTLS(t, env.Config.Endpoints[0], env.Config.TLS, committerpb.NewAuthServiceClient)
	second := test.CreateClientWithTLS(t, env.Config.Endpoints[1], env.Config.TLS, committerpb.NewAuthServiceClient)

	nonce, err := first.IssueNonce(t.Context(), &emptypb.Empty{})
	require.NoError(t, err)
	resp, err := second.AuthenticateIdentity(t.Context(), &committerpb.AuthenticateIdentityRequest{
		SignedEnvelope: buildEnvelope(t, &env.EnvelopeParams, nonce.GetNonce()),
		RequestedScope: env.Scope,
	})
	require.NoError(t, err)
	_, err = first.AuthorizeIdentity(t.Context(), &committerpb.AuthorizeIdentityRequest{
		Token:       resp.GetToken(),
		Resource:    committerpb.QueryService_GetRows_FullMethodName,
		TlsCertHash: env.TLSCertHash,
	})
	require.NoError(t, err)
}

// TestAuthChallengeRateLimit verifies the RPCs reachable without a token are refused once their limit is spent.
func TestAuthChallengeRateLimit(t *testing.T) {
	t.Parallel()
	// The env authenticates once before returning, which takes two challenges, so the burst must allow two.
	limit := serve.RateLimitConfig{RequestsPerSecond: 2, Burst: 2}
	env := NewAuthTestEnv(t, &TestEnvParams{ChallengeRateLimit: limit})

	// The env's client retries ResourceExhausted until the bucket refills, so the refusal is observed on a
	// connection without a retry policy.
	creds, err := env.Config.TLS.ClientCredentials()
	require.NoError(t, err)
	conn, err := grpc.NewClient(env.Config.Endpoints[0].Address(), grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := committerpb.NewAuthServiceClient(conn)

	// Back to back, one call more than the burst.
	for range limit.Burst + 1 {
		_, err = client.IssueNonce(t.Context(), &emptypb.Empty{})
	}
	require.Equal(t, codes.ResourceExhausted, grpcerror.GetCode(err))
}

// newAuthTestEnvWithMutualTLS starts an AuthService whose tokens are bound to the client's certificate.
func newAuthTestEnvWithMutualTLS(t *testing.T, params TestEnvParams) *TestEnv {
	t.Helper()
	credentials := test.NewCredentialsFactory(t)
	params.ServerTLS, _ = credentials.CreateServerCredentials(t, connection.MutualTLSMode, "127.0.0.1")
	params.ClientTLS, _ = credentials.CreateClientCredentials(t, connection.MutualTLSMode)
	return NewAuthTestEnv(t, &params)
}

// buildEnvelope builds a genuine authentication envelope, exactly as a client does.
func buildEnvelope(t *testing.T, params *acl.EnvelopeParams, nonce []byte) *common.Envelope {
	t.Helper()
	envelope, err := acl.BuildAuthEnvelope(params, nonce)
	require.NoError(t, err)
	return envelope
}
