/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

const (
	testResource = "/committerpb.QueryService/GetRows"
	testToken    = "token"
)

func TestUnaryInterceptorAllows(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{identity: []byte("id")}
	enforcer := NewEnforcer(fake, EnforcerConfig{})

	handlerRan := false
	handler := func(context.Context, any) (any, error) {
		handlerRan = true
		return "ok", nil
	}
	resp, err := enforcer.UnaryInterceptor()(
		ctxWithToken(testToken), nil, &grpc.UnaryServerInfo{FullMethod: testResource}, handler,
	)

	require.NoError(t, err)
	require.Equal(t, "ok", resp)
	require.True(t, handlerRan)
	require.Equal(t, 1, fake.authorizeCallCount())
	require.Equal(t, testToken, fake.lastAuthorizeRequest().GetToken())
	require.Equal(t, testResource, fake.lastAuthorizeRequest().GetResource())
}

func TestUnaryInterceptorRejects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		token     string // empty means no token is attached
		authErr   error
		wantCode  codes.Code
		wantCalls int
	}{
		{
			name:      "missing token short-circuits before AuthService",
			wantCode:  codes.Unauthenticated,
			wantCalls: 0,
		},
		{
			name:      "policy denial is propagated",
			token:     testToken,
			authErr:   status.Error(codes.PermissionDenied, "not a reader"),
			wantCode:  codes.PermissionDenied,
			wantCalls: 1,
		},
		{
			name:      "unreachable AuthService fails closed",
			token:     testToken,
			authErr:   status.Error(codes.Unavailable, "connection refused"),
			wantCode:  codes.Unavailable,
			wantCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeAuthClient{authorizeErr: tc.authErr}
			enforcer := NewEnforcer(fake, EnforcerConfig{})

			ctx := context.Background()
			if tc.token != "" {
				ctx = ctxWithToken(tc.token)
			}
			handlerRan := false
			handler := func(context.Context, any) (any, error) {
				handlerRan = true
				return nil, nil
			}
			_, err := enforcer.UnaryInterceptor()(
				ctx, nil, &grpc.UnaryServerInfo{FullMethod: testResource}, handler,
			)

			require.Equal(t, tc.wantCode, grpcerror.GetCode(err))
			require.False(t, handlerRan)
			require.Equal(t, tc.wantCalls, fake.authorizeCallCount())
		})
	}
}

func TestInterceptorsExemptHealthChecks(t *testing.T) {
	t.Parallel()
	const healthCheck = "/grpc.health.v1.Health/Check"
	const healthWatch = "/grpc.health.v1.Health/Watch"

	// A health check with no token must pass through without contacting the AuthService, so that
	// liveness/readiness probes keep working once ACL is enabled.
	fake := &fakeAuthClient{}
	enforcer := NewEnforcer(fake, EnforcerConfig{})

	unaryRan := false
	_, err := enforcer.UnaryInterceptor()(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: healthCheck},
		func(context.Context, any) (any, error) { unaryRan = true; return nil, nil })
	require.NoError(t, err)
	require.True(t, unaryRan)

	streamRan := false
	err = enforcer.StreamInterceptor()(nil, &fakeServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: healthWatch},
		func(any, grpc.ServerStream) error { streamRan = true; return nil })
	require.NoError(t, err)
	require.True(t, streamRan)

	require.Equal(t, 0, fake.authorizeCallCount())
}

func TestStreamInterceptorAllowsAndDenies(t *testing.T) {
	t.Parallel()

	// Authorized at establishment: the handler runs and receives the wrapped stream.
	fake := &fakeAuthClient{identity: []byte("id")}
	enforcer := NewEnforcer(fake, EnforcerConfig{})
	handlerRan := false
	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(any, grpc.ServerStream) error { handlerRan = true; return nil },
	)
	require.NoError(t, err)
	require.True(t, handlerRan)

	// Denied at establishment: the handler never runs.
	denyFake := &fakeAuthClient{authorizeErr: status.Error(codes.PermissionDenied, "denied")}
	denyEnforcer := NewEnforcer(denyFake, EnforcerConfig{})
	deniedHandlerRan := false
	err = denyEnforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(any, grpc.ServerStream) error { deniedHandlerRan = true; return nil },
	)
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
	require.False(t, deniedHandlerRan)
}

func TestStreamReauthorizesOnInterval(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{identity: []byte("bound-identity")}
	enforcer := NewEnforcer(fake, EnforcerConfig{RevalidateInterval: 10 * time.Millisecond})

	// The handler stays open until released, so the background revalidation loop keeps running.
	release := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- enforcer.StreamInterceptor()(
			nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
			&grpc.StreamServerInfo{FullMethod: testResource},
			func(any, grpc.ServerStream) error { <-release; return nil },
		)
	}()

	// The bound identity is re-authorized on the timer, driven by the interval, not message flow.
	require.Eventually(t, func() bool { return fake.reAuthorizeCallCount() >= 1 },
		2*time.Second, 5*time.Millisecond)
	require.Equal(t, []byte("bound-identity"), fake.lastReAuthorizeRequest().GetIdentity())

	close(release)
	require.NoError(t, <-errCh)
}

func TestStreamTolerantOfTransientReauthErrors(t *testing.T) {
	t.Parallel()
	// The AuthService is briefly unreachable; an established, already-authorized stream must survive.
	fake := &fakeAuthClient{
		identity:       []byte("id"),
		reAuthorizeErr: status.Error(codes.Unavailable, "auth service restarting"),
	}
	enforcer := NewEnforcer(fake, EnforcerConfig{RevalidateInterval: 10 * time.Millisecond})

	release := make(chan struct{})
	errCh := make(chan error, 1)
	streamCh := make(chan grpc.ServerStream, 1)
	go func() {
		errCh <- enforcer.StreamInterceptor()(
			nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
			&grpc.StreamServerInfo{FullMethod: testResource},
			func(_ any, ss grpc.ServerStream) error { streamCh <- ss; <-release; return nil },
		)
	}()
	wrapped := <-streamCh // synchronized handoff of the wrapped stream

	// After several failed re-checks the stream is still open and messages still flow.
	require.Eventually(t, func() bool { return fake.reAuthorizeCallCount() >= 3 },
		2*time.Second, 5*time.Millisecond)
	require.NoError(t, wrapped.RecvMsg(nil))

	close(release)
	require.NoError(t, <-errCh)
}

func TestStreamTerminatesWhenReauthorizationDenied(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{
		identity:       []byte("id"),
		reAuthorizeErr: status.Error(codes.PermissionDenied, "organization removed from channel"),
	}
	enforcer := NewEnforcer(fake, EnforcerConfig{RevalidateInterval: 10 * time.Millisecond})

	// The handler blocks on its context; a definitive denial cancels it, then a receive returns the
	// recorded denial - terminating even a stream that was not actively transferring messages.
	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(_ any, ss grpc.ServerStream) error {
			<-ss.Context().Done()
			return ss.RecvMsg(nil)
		},
	)
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
}

// --- test doubles ---

func ctxWithToken(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(TokenMetadataKey, token))
}

// fakeAuthClient is a test double for servicepb.AuthServiceClient. Authorize returns its configured
// identity or error; ReAuthorize returns its configured error; both record their calls.
type fakeAuthClient struct {
	mu             sync.Mutex
	identity       []byte
	authorizeErr   error
	reAuthorizeErr error
	authorizeCalls int
	reAuthCalls    int
	lastAuthorize  *servicepb.AuthorizeRequest
	lastReAuth     *servicepb.ReAuthorizeRequest
}

func (f *fakeAuthClient) Authorize(
	_ context.Context, req *servicepb.AuthorizeRequest, _ ...grpc.CallOption,
) (*servicepb.AuthorizeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorizeCalls++
	f.lastAuthorize = req
	if f.authorizeErr != nil {
		return nil, f.authorizeErr
	}
	return &servicepb.AuthorizeResponse{Authorized: true, Identity: f.identity}, nil
}

func (f *fakeAuthClient) ReAuthorize(
	_ context.Context, req *servicepb.ReAuthorizeRequest, _ ...grpc.CallOption,
) (*servicepb.AuthorizeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reAuthCalls++
	f.lastReAuth = req
	if f.reAuthorizeErr != nil {
		return nil, f.reAuthorizeErr
	}
	return &servicepb.AuthorizeResponse{Authorized: true, Identity: req.GetIdentity()}, nil
}

func (*fakeAuthClient) Authenticate(
	context.Context, *servicepb.AuthenticateRequest, ...grpc.CallOption,
) (*servicepb.AuthenticateResponse, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeAuthClient) authorizeCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authorizeCalls
}

func (f *fakeAuthClient) reAuthorizeCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reAuthCalls
}

func (f *fakeAuthClient) lastAuthorizeRequest() *servicepb.AuthorizeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuthorize
}

func (f *fakeAuthClient) lastReAuthorizeRequest() *servicepb.ReAuthorizeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReAuth
}

// fakeServerStream is a minimal grpc.ServerStream whose RecvMsg/SendMsg succeed, carrying a context.
type fakeServerStream struct {
	//nolint:containedctx // a grpc.ServerStream test double must return a context from Context().
	ctx context.Context
}

func (s *fakeServerStream) Context() context.Context   { return s.ctx }
func (*fakeServerStream) RecvMsg(any) error            { return nil }
func (*fakeServerStream) SendMsg(any) error            { return nil }
func (*fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (*fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (*fakeServerStream) SetTrailer(metadata.MD)       {}
