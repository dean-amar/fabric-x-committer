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

func TestStreamInterceptorAllowsAndDenies(t *testing.T) {
	t.Parallel()

	// Authorized at establishment: the handler runs and receives the wrapped stream.
	fake := &fakeAuthClient{}
	enforcer := &Enforcer{Client: fake}
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
	denyEnforcer := &Enforcer{Client: denyFake}
	deniedHandlerRan := false
	err = denyEnforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(any, grpc.ServerStream) error { deniedHandlerRan = true; return nil },
	)
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
	require.False(t, deniedHandlerRan)
}

// TestStreamReusesDecisionWithinInterval verifies the decision cache: while a decision is still
// valid, messages flow without consulting the AuthService, so its latency stays off the data path.
func TestStreamReusesDecisionWithinInterval(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{tokenExpiresAt: time.Now().Add(time.Hour).Unix()}
	enforcer := &Enforcer{Client: fake, RevalidateInterval: time.Hour}

	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(_ any, ss grpc.ServerStream) error {
			for range 5 {
				if recvErr := ss.RecvMsg(nil); recvErr != nil {
					return recvErr
				}
				if sendErr := ss.SendMsg(nil); sendErr != nil {
					return sendErr
				}
			}
			return nil
		},
	)

	require.NoError(t, err)
	// Only the establishment call: ten messages added no round trips.
	require.Equal(t, 1, fake.authorizeCallCount())
}

// TestStreamReauthorizesWhenDecisionLapses verifies that once the cached decision lapses, the next
// message re-authorizes with the bound token - which is what lets the AuthService re-resolve the
// token to its record and catch expiry and a policy change.
func TestStreamReauthorizesWhenDecisionLapses(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{tokenExpiresAt: time.Now().Add(time.Hour).Unix()}
	enforcer := &Enforcer{Client: fake, RevalidateInterval: time.Nanosecond}

	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(_ any, ss grpc.ServerStream) error { return ss.RecvMsg(nil) },
	)

	require.NoError(t, err)
	require.Equal(t, 2, fake.authorizeCallCount())
	require.Equal(t, testToken, fake.lastAuthorizeRequest().GetToken(), "the re-check must carry the token")
}

// TestStreamDeniesOnceBoundTokenExpires verifies the local hard bound: past the bound token's expiry
// the stream is denied without consulting the AuthService, so an outage cannot extend a stream beyond
// the lifetime of the token that established it.
func TestStreamDeniesOnceBoundTokenExpires(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{tokenExpiresAt: time.Now().Add(-time.Second).Unix()}
	enforcer := &Enforcer{Client: fake, RevalidateInterval: time.Hour}

	err := enforcer.StreamInterceptor()(
		nil, &fakeServerStream{ctx: ctxWithToken(testToken)},
		&grpc.StreamServerInfo{FullMethod: testResource},
		func(_ any, ss grpc.ServerStream) error { return ss.RecvMsg(nil) },
	)

	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "has expired")
	// Establishment only: the expiry is enforced locally, with no further round trip.
	require.Equal(t, 1, fake.authorizeCallCount())
}

// TestStreamDeniesMessageWhenTokenExpiresDuringReceive verifies the post-receive bound. A receive on an
// idle stream can block past the bound token's expiry, so the message it eventually returns must not
// reach the handler on the strength of the check that admitted the receive.
func TestStreamDeniesMessageWhenTokenExpiresDuringReceive(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Valid when the receive starts, expired by the time it returns.
	stream := &authorizedStream{
		ServerStream:   &fakeServerStream{ctx: ctx, recvDelay: 60 * time.Millisecond},
		ctx:            ctx,
		cancel:         cancel,
		enforcer:       &Enforcer{Client: fake, RevalidateInterval: time.Hour},
		resource:       testResource,
		token:          testToken,
		tokenExpiresAt: time.Now().Add(20 * time.Millisecond),
		validUntil:     time.Now().Add(time.Hour),
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
	enforcer := &Enforcer{Client: fake, RevalidateInterval: time.Nanosecond}

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

// TestStreamTerminatesWhenReauthorizationDenied verifies a definitive denial on a re-check terminates
// the stream: the receive returns the denial and the stream context is cancelled, so a handler parked
// on its context also wakes.
func TestStreamTerminatesWhenReauthorizationDenied(t *testing.T) {
	t.Parallel()
	fake := &fakeAuthClient{
		tokenExpiresAt: time.Now().Add(time.Hour).Unix(),
		laterErr:       status.Error(codes.PermissionDenied, "organization removed from channel"),
	}
	enforcer := &Enforcer{Client: fake, RevalidateInterval: time.Nanosecond}

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

// fakeAuthClient is a test double for servicepb.AuthServiceClient, recording every Authorize call.
// authorizeErr fails all of them; laterErr fails only those after the first, which is how a test
// simulates a change - a policy denial or a brief outage - that only a re-check sees.
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
