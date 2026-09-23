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
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

const (
	testResource = "/committerpb.QueryService/GetRows"
	testToken    = "token"
)

func TestUnaryInterceptorAllows(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{}
	enforcer := &Enforcer{Client: fake}

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
			enforcer := &Enforcer{Client: fake}

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
	enforcer := &Enforcer{Client: fake}

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

// TestStreamInterceptorDeniesAtEstablishment verifies a denial before the stream exists keeps the handler
// from running at all, so no message is ever exchanged over an unauthorized stream.
func TestStreamInterceptorDeniesAtEstablishment(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{authorizeErr: status.Error(codes.PermissionDenied, "denied")}
	enforcer := &Enforcer{Client: fake}
	handlerRan := false
	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(any, grpc.ServerStream) error { handlerRan = true; return nil },
	)

	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
	require.False(t, handlerRan)
}

// TestStreamEnforcement covers what an established stream does over its life: it reuses its decision inside
// the re-authorization interval and renews it past that, while honouring both bounds - the bound token's
// expiry, checked locally on every message, and a definitive denial - and riding out a brief outage.
func TestStreamEnforcement(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		// tokenTTL is the bound token's remaining life, as the AuthService reports it.
		tokenTTL        time.Duration
		reAuthorize     time.Duration
		laterErr        error
		messages        int
		wantCode        codes.Code
		wantErrContains string
		// wantCalls is the exact number of Authorize calls; zero instead asserts the re-check happened.
		wantCalls int
	}{
		{
			name:     "a decision is reused within the interval, so messages cost no round trips",
			tokenTTL: time.Hour, reAuthorize: time.Hour, messages: 5, wantCalls: 1,
		},
		{
			// Establishment, then the receive and the send each renew past the lapsed interval.
			name:     "a lapsed decision is renewed, which is what makes a policy change observable",
			tokenTTL: time.Hour, reAuthorize: time.Nanosecond, messages: 1, wantCalls: 3,
		},
		{
			name:     "an expired bound token is denied locally, so an outage cannot extend a stream",
			tokenTTL: -time.Second, reAuthorize: time.Hour, messages: 1,
			wantCode: codes.Unauthenticated, wantErrContains: "has expired", wantCalls: 1,
		},
		{
			name:     "a transient re-check failure leaves an established stream serving",
			tokenTTL: time.Hour, reAuthorize: time.Nanosecond, messages: 3,
			laterErr: status.Error(codes.Unavailable, "auth service restarting"),
		},
		{
			name:     "a definitive denial terminates the stream",
			tokenTTL: time.Hour, reAuthorize: time.Nanosecond, messages: 1,
			laterErr: status.Error(codes.PermissionDenied, "organization removed from channel"),
			wantCode: codes.PermissionDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeAuthClient{
				tokenExpiresAt: time.Now().Add(tc.tokenTTL).Unix(),
				laterErr:       tc.laterErr,
			}
			enforcer := &Enforcer{Client: fake, ReAuthorizeInterval: tc.reAuthorize}

			err := enforcer.StreamInterceptor()(
				nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
				&grpc.StreamServerInfo{FullMethod: testResource},
				exchangeMessages(tc.messages),
			)

			require.Equal(t, tc.wantCode, grpcerror.GetCode(err))
			if tc.wantErrContains != "" {
				require.ErrorContains(t, err, tc.wantErrContains)
			}
			if tc.wantCalls > 0 {
				require.Equal(t, tc.wantCalls, fake.authorizeCallCount())
				return
			}
			require.GreaterOrEqual(t, fake.authorizeCallCount(), 2, "the re-check must have run")
		})
	}
}

// TestStreamDeniesMessageWhenTokenExpiresDuringReceive verifies the post-receive bound: a receive can
// block past the token's expiry, so its message must not reach the handler on the earlier check.
func TestStreamDeniesMessageWhenTokenExpiresDuringReceive(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Valid when the receive starts, expired by the time it returns.
	stream := &authorizedStream{
		ServerStream:    &fakeServerStream{ctx: ctx, recvDelay: 60 * time.Millisecond},
		ctx:             ctx,
		cancel:          cancel,
		enforcer:        &Enforcer{Client: fake, ReAuthorizeInterval: time.Hour},
		resource:        testResource,
		token:           testToken,
		tokenExpiresAt:  time.Now().Add(20 * time.Millisecond),
		nextAuthorizeAt: time.Now().Add(time.Hour),
	}

	err := stream.RecvMsg(nil)

	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "has expired")
	require.Zero(t, fake.authorizeCallCount(), "the expiry bound is local, so it costs no round trip")
}

// TestStreamTolerantOfTransientReauthErrors verifies an established stream survives a brief
// AuthService outage, since the token-expiry bound still limits how long that can continue.
func TestStreamTolerantOfTransientReauthErrors(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{
		tokenExpiresAt: time.Now().Add(time.Hour).Unix(),
		laterErr:       status.Error(codes.Unavailable, "auth service restarting"),
	}
	enforcer := &Enforcer{Client: fake, ReAuthorizeInterval: time.Nanosecond}

	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(_ any, ss grpc.ServerStream) error {
			for range 3 {
				if recvErr := ss.RecvMsg(nil); recvErr != nil {
					return recvErr
				}
			}
			return nil
		},
	)

	require.NoError(t, err, "a transient re-check failure must not tear down an established stream")
	require.GreaterOrEqual(t, fake.authorizeCallCount(), 2)
}

// TestStreamTerminatesWhenReauthorizationDenied verifies a definitive denial terminates the stream: the
// receive returns it and the stream context is cancelled, so a parked handler also wakes.
func TestStreamTerminatesWhenReauthorizationDenied(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{
		tokenExpiresAt: time.Now().Add(time.Hour).Unix(),
		laterErr:       status.Error(codes.PermissionDenied, "organization removed from channel"),
	}
	enforcer := &Enforcer{Client: fake, ReAuthorizeInterval: time.Nanosecond}

	ctxDone := false
	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(_ any, ss grpc.ServerStream) error {
			recvErr := ss.RecvMsg(nil)
			<-ss.Context().Done()
			ctxDone = true
			return recvErr
		},
	)

	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
	require.True(t, ctxDone, "a definitive denial must cancel the stream context")
}

// --- test doubles ---

func ctxWithToken(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(TokenMetadataKey, token))
}

// fakeAuthClient records every Authorize call. authorizeErr fails all of them; laterErr fails only those
// after the first, simulating a change that only a re-check sees.
type fakeAuthClient struct {
	mu             sync.Mutex
	tokenExpiresAt int64
	authorizeErr   error
	laterErr       error
	authorizeCalls int
	lastAuthorize  *servicepb.AuthorizeRequest
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
	if f.authorizeCalls > 1 && f.laterErr != nil {
		return nil, f.laterErr
	}
	return &servicepb.AuthorizeResponse{
		Authorized:     true,
		TokenExpiresAt: f.tokenExpiresAt,
	}, nil
}

func (*fakeAuthClient) Authenticate(
	context.Context, *servicepb.AuthenticateRequest, ...grpc.CallOption,
) (*servicepb.AuthenticateResponse, error) {
	return nil, errors.New("not implemented")
}

func (*fakeAuthClient) IssueNonce(
	context.Context, *servicepb.IssueNonceRequest, ...grpc.CallOption,
) (*servicepb.IssueNonceResponse, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeAuthClient) authorizeCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authorizeCalls
}

func (f *fakeAuthClient) lastAuthorizeRequest() *servicepb.AuthorizeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuthorize
}

// exchangeMessages returns a handler that receives and sends count messages, stopping at the first error.
// A terminal error arrives with the stream context already cancelled, so waiting on it here asserts that a
// real handler parked on that context wakes rather than holding the stream open.
func exchangeMessages(count int) grpc.StreamHandler {
	return func(_ any, ss grpc.ServerStream) error {
		for range count {
			if err := ss.RecvMsg(nil); err != nil {
				<-ss.Context().Done()
				return err
			}
			if err := ss.SendMsg(nil); err != nil {
				return err
			}
		}
		return nil
	}
}

// fakeServerStream is a minimal grpc.ServerStream whose RecvMsg/SendMsg succeed, carrying a context.
// When recv is set, RecvMsg delivers it, so a test can hand the wrapper a subscription request.
type fakeServerStream struct {
	//nolint:containedctx // a grpc.ServerStream test double must return a context from Context().
	ctx  context.Context
	recv proto.Message
	// recvDelay blocks RecvMsg, standing in for an idle stream waiting on a client that says nothing.
	recvDelay time.Duration
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func (s *fakeServerStream) RecvMsg(m any) error {
	time.Sleep(s.recvDelay)
	dst, ok := m.(proto.Message)
	if !ok || s.recv == nil {
		return nil
	}
	proto.Merge(dst, s.recv)
	return nil
}

func (*fakeServerStream) SendMsg(any) error            { return nil }
func (*fakeServerStream) SetHeader(metadata.MD) error  { return nil }
func (*fakeServerStream) SendHeader(metadata.MD) error { return nil }
func (*fakeServerStream) SetTrailer(metadata.MD)       {}
