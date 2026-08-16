/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	queryGetRows   = "/committerpb.QueryService/GetRows"
	notifierStream = "/committerpb.Notifier/OpenNotificationStream"
)

// --- AuthorizeInterceptor -------------------------------------------------------------------

func TestAuthorizeInterceptorPassthrough(t *testing.T) {
	t.Parallel()
	// A non-Authorize method is passed straight to the handler, untouched by this interceptor.
	handlerCalled := false
	interceptor := AuthorizeInterceptor(enforcingProvider(newBundleFixture(t).bundleAt(t, 0)))
	_, err := interceptor(authContext(&MSPAuthInfo{}), nil, unaryInfo(queryGetRows),
		func(context.Context, any) (any, error) {
			handlerCalled = true
			return "ok", nil
		})
	require.NoError(t, err)
	require.True(t, handlerCalled)
}

func TestAuthorizeInterceptorSuccessBindsIdentity(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 3)
	authInfo := &MSPAuthInfo{}
	interceptor := AuthorizeInterceptor(enforcingProvider(bundle))

	resp, err := interceptor(
		authContext(authInfo),
		&committerpb.AuthorizeRequest{SignedEnvelope: f.signedEnvelope(t, nil)},
		unaryInfo(AuthenticationResource),
		failHandler(t),
	)
	require.NoError(t, err)

	authResp, ok := resp.(*committerpb.AuthorizeResponse)
	require.True(t, ok)
	require.True(t, authResp.GetSuccess())
	require.Equal(t, f.mspID, authResp.GetMspId())
	require.Equal(t, uint64(3), authResp.GetConfigSequence())

	// The identity is now bound to the connection at the bundle's sequence.
	identity, seq := authInfo.GetIdentity()
	require.NotNil(t, identity)
	require.Equal(t, uint64(3), seq)
}

func TestAuthorizeInterceptorDeniesInBand(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	interceptor := AuthorizeInterceptor(enforcingProvider(f.bundleAt(t, 0)))

	// A tampered envelope fails signature verification. The interceptor reports the denial as a
	// structured AuthorizeResponse{Success:false} with a NIL gRPC error, so the client treats it
	// as a permanent denial rather than a retryable transport failure.
	resp, err := interceptor(
		authContext(&MSPAuthInfo{}),
		&committerpb.AuthorizeRequest{SignedEnvelope: envelopeWithTamperedSignature(t, f)},
		unaryInfo(AuthenticationResource),
		failHandler(t),
	)
	require.NoError(t, err)
	authResp, ok := resp.(*committerpb.AuthorizeResponse)
	require.True(t, ok)
	require.False(t, authResp.GetSuccess())
	require.Contains(t, authResp.GetMessage(), "failed to authorize")
}

func TestAuthorizeInterceptorErrors(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	goodEnvelope := f.signedEnvelope(t, nil)

	for _, tc := range []struct {
		name     string
		provider *stubProvider
		ctx      context.Context //nolint:containedctx // test table carries the context under test.
		req      any
		wantCode codes.Code // codes.OK means: expect a nil-error AuthorizeResponse{Success:false}
	}{
		{
			name:     "no peer in context",
			provider: enforcingProvider(f.bundleAt(t, 0)),
			ctx:      context.Background(),
			req:      &committerpb.AuthorizeRequest{SignedEnvelope: goodEnvelope},
			wantCode: codes.Internal,
		},
		{
			name:     "bundle still bootstrapping",
			provider: &stubProvider{err: ErrNoBundle, requiresACL: true},
			ctx:      authContext(&MSPAuthInfo{}),
			req:      &committerpb.AuthorizeRequest{SignedEnvelope: goodEnvelope},
			wantCode: codes.Unavailable,
		},
		{
			name:     "internal service cannot authorize",
			provider: &stubProvider{err: ErrNoUpdater},
			ctx:      authContext(&MSPAuthInfo{}),
			req:      &committerpb.AuthorizeRequest{SignedEnvelope: goodEnvelope},
			wantCode: codes.OK, // in-band Success:false
		},
		{
			name:     "wrong request type",
			provider: enforcingProvider(f.bundleAt(t, 0)),
			ctx:      authContext(&MSPAuthInfo{}),
			req:      "not-an-authorize-request",
			wantCode: codes.OK, // in-band Success:false
		},
		{
			name:     "nil signed envelope",
			provider: enforcingProvider(f.bundleAt(t, 0)),
			ctx:      authContext(&MSPAuthInfo{}),
			req:      &committerpb.AuthorizeRequest{},
			wantCode: codes.OK, // in-band Success:false
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			interceptor := AuthorizeInterceptor(tc.provider)
			resp, err := interceptor(tc.ctx, tc.req, unaryInfo(AuthenticationResource), failHandler(t))
			if tc.wantCode == codes.OK {
				require.NoError(t, err)
				authResp, ok := resp.(*committerpb.AuthorizeResponse)
				require.True(t, ok)
				require.False(t, authResp.GetSuccess())
				return
			}
			require.Equal(t, tc.wantCode, status.Code(err))
		})
	}
}

// --- MSPUnaryServerInterceptor --------------------------------------------------------------

func TestUnaryInterceptorExemptAndBypass(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)

	for _, tc := range []struct {
		name     string
		provider *stubProvider
		method   string
		ctx      context.Context //nolint:containedctx // test table carries the context under test.
	}{
		{
			name:     "exempt method passes without identity",
			provider: enforcingProvider(f.bundleAt(t, 0)),
			method:   AuthenticationResource,
			ctx:      authContext(&MSPAuthInfo{}),
		},
		{
			name:     "internal service (no updater) bypasses",
			provider: &stubProvider{err: ErrNoUpdater},
			method:   queryGetRows,
			ctx:      authContext(&MSPAuthInfo{}),
		},
		{
			name:     "service not requiring ACL bypasses on missing bundle",
			provider: &stubProvider{err: ErrNoBundle, requiresACL: false},
			method:   queryGetRows,
			ctx:      authContext(&MSPAuthInfo{}),
		},
		{
			// Regression for the fail-strict landmine: a service registered with requiresACL=false
			// must bypass enforcement even when a bundle IS loaded (e.g. it loaded one only for
			// dynamic TLS CA refresh), rather than silently enforcing ACL against it.
			name:     "loaded bundle on non-ACL service still bypasses",
			provider: &stubProvider{bundle: f.bundleAt(t, 1), requiresACL: false},
			method:   queryGetRows,
			ctx:      authContext(&MSPAuthInfo{}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			called := false
			_, err := MSPUnaryServerInterceptor(tc.provider)(tc.ctx, nil, unaryInfo(tc.method),
				func(context.Context, any) (any, error) { called = true; return nil, nil })
			require.NoError(t, err)
			require.True(t, called)
		})
	}
}

func TestUnaryInterceptorEnforcement(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 1)

	t.Run("authorized identity is allowed", func(t *testing.T) {
		t.Parallel()
		ctx := authContext(boundAuthInfo(f.identity()))
		called := false
		_, err := MSPUnaryServerInterceptor(enforcingProvider(bundle))(ctx, nil, unaryInfo(queryGetRows),
			func(context.Context, any) (any, error) { called = true; return nil, nil })
		require.NoError(t, err)
		require.True(t, called)
	})

	t.Run("connection without bound identity is rejected", func(t *testing.T) {
		t.Parallel()
		ctx := authContext(&MSPAuthInfo{}) // authorized TLS, but Authorize never called
		interceptor := MSPUnaryServerInterceptor(enforcingProvider(bundle))
		_, err := interceptor(ctx, nil, unaryInfo(queryGetRows), failHandler(t))
		require.Equal(t, codes.Unauthenticated, status.Code(err))
		require.ErrorContains(t, err, "call Authorize first")
	})

	t.Run("missing peer info is rejected", func(t *testing.T) {
		t.Parallel()
		interceptor := MSPUnaryServerInterceptor(enforcingProvider(bundle))
		_, err := interceptor(context.Background(), nil, unaryInfo(queryGetRows), failHandler(t))
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("bundle error other than bootstrap fails closed", func(t *testing.T) {
		t.Parallel()
		provider := &stubProvider{err: errors.New("db exploded"), requiresACL: true}
		ctx := authContext(boundAuthInfo(f.identity()))
		_, err := MSPUnaryServerInterceptor(provider)(ctx, nil, unaryInfo(queryGetRows), failHandler(t))
		require.Equal(t, codes.Internal, status.Code(err))
	})
}

// --- evaluatePolicy fail-closed -------------------------------------------------------------

func TestEvaluatePolicyFailClosed(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 0)

	t.Run("method with no policy anywhere is denied", func(t *testing.T) {
		t.Parallel()
		// A method absent from both the channel ACLs and DefaultACL must be denied, not allowed.
		err := evaluatePolicy(bundle, f.identity(), "/some.Unmapped/Method")
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		require.ErrorContains(t, err, "no ACL policy defined")
	})

	t.Run("default-mapped method is allowed for a member", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, evaluatePolicy(bundle, f.identity(), queryGetRows))
	})
}

// --- helpers -------------------------------------------------------------------------------

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func failHandler(t *testing.T) grpc.UnaryHandler {
	t.Helper()
	return func(context.Context, any) (any, error) {
		require.FailNow(t, "handler should not be invoked when the interceptor rejects the call")
		return nil, nil
	}
}
