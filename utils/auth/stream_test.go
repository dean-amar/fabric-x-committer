/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"sync"
	"testing"

	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeServerStream is a controllable grpc.ServerStream for exercising the stream interceptor and
// the wrapped authServerStream. It records Recv/Send calls and returns a fixed context.
type fakeServerStream struct {
	grpc.ServerStream
	ctx       context.Context //nolint:containedctx // a ServerStream owns its context by design.
	recvCalls int
	sendCalls int
	mu        sync.Mutex
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func (s *fakeServerStream) RecvMsg(any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recvCalls++
	return nil
}

func (s *fakeServerStream) SendMsg(any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendCalls++
	return nil
}

func streamInfo(method string) *grpc.StreamServerInfo {
	return &grpc.StreamServerInfo{FullMethod: method, IsServerStream: true}
}

// advancingProvider returns a bundle whose config sequence increases on every GetBundle call, so
// callers always take the "sequence advanced" re-evaluation branch. It pre-builds a fixed set of
// bundles once (bundle construction is not itself goroutine-safe) and hands them out under its own
// lock, isolating the test to the stream's synchronization rather than the provider's.
type advancingProvider struct {
	mu    sync.Mutex
	seq   int
	built []*channelconfig.Bundle
}

// newAdvancingProvider pre-builds count bundles at sequences 1..count, all of which authorize the
// fixture's member identity.
func newAdvancingProvider(t *testing.T, f *bundleFixture, count int) *advancingProvider {
	t.Helper()
	built := make([]*channelconfig.Bundle, count)
	for i := range count {
		built[i] = f.bundleAt(t, uint64(i+1))
	}
	return &advancingProvider{built: built}
}

func (p *advancingProvider) GetBundle() (*channelconfig.Bundle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seq >= len(p.built) {
		return p.built[len(p.built)-1], nil
	}
	b := p.built[p.seq]
	p.seq++
	return b, nil
}

func (*advancingProvider) RequiresACL() bool { return true }

func TestStreamInterceptorExemptAndBypass(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)

	for _, tc := range []struct {
		name     string
		provider *stubProvider
		method   string
	}{
		{name: "exempt method passes", provider: enforcingProvider(f.bundleAt(t, 0)), method: AuthenticationResource},
		{name: "internal service bypasses", provider: &stubProvider{err: ErrNoUpdater}, method: notifierStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			called := false
			ss := &fakeServerStream{ctx: authContext(&MSPAuthInfo{})}
			err := MSPStreamServerInterceptor(tc.provider)(nil, ss, streamInfo(tc.method),
				func(any, grpc.ServerStream) error { called = true; return nil })
			require.NoError(t, err)
			require.True(t, called)
		})
	}
}

func TestStreamInterceptorEnforcement(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 1)

	t.Run("authorized identity establishes the stream", func(t *testing.T) {
		t.Parallel()
		ss := &fakeServerStream{ctx: authContext(boundAuthInfo(f.identity()))}
		var wrapped grpc.ServerStream
		err := MSPStreamServerInterceptor(enforcingProvider(bundle))(nil, ss, streamInfo(notifierStream),
			func(_ any, s grpc.ServerStream) error { wrapped = s; return nil })
		require.NoError(t, err)
		// The handler receives the wrapping stream, not the raw one.
		_, isWrapped := wrapped.(*authServerStream)
		require.True(t, isWrapped)
	})

	t.Run("connection without bound identity is rejected at establishment", func(t *testing.T) {
		t.Parallel()
		ss := &fakeServerStream{ctx: authContext(&MSPAuthInfo{})}
		err := MSPStreamServerInterceptor(enforcingProvider(bundle))(nil, ss, streamInfo(notifierStream),
			func(any, grpc.ServerStream) error {
				require.FailNow(t, "handler must not run for an unauthorized stream")
				return nil
			})
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

// TestStreamConcurrentRecvSend exercises the wrapped stream the way OpenNotificationStream does:
// a receive loop and a send loop run on separate goroutines against the same authServerStream while
// the config sequence advances underneath them. Both directions call checkConfigAndRevalidate,
// which reads and updates the cached bundle; this test fails under -race unless that access is
// synchronized. It is a regression guard for the data race on the cached bundle.
func TestStreamConcurrentRecvSend(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	authInfo := boundAuthInfo(f.identity())
	// A provider whose bundle sequence keeps advancing (all still authorize the member), so both
	// goroutines take the "sequence changed → update cache" branch and contend on the cached bundle.
	provider := newAdvancingProvider(t, f, 100)
	ss := &fakeServerStream{ctx: authContext(authInfo)}
	stream := &authServerStream{
		ServerStream:  ss,
		authInfo:      authInfo,
		provider:      provider,
		fullMethod:    notifierStream,
		currentBundle: f.bundleAt(t, 1),
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 50 {
			_ = stream.RecvMsg(nil)
		}
	})
	wg.Go(func() {
		for range 50 {
			_ = stream.SendMsg(nil)
		}
	})
	wg.Wait()
}

// TestStreamUnchangedSequenceIsCheapNoOp verifies that when the config sequence has not advanced,
// per-message checks pass through without denying and forward to the underlying stream.
func TestStreamUnchangedSequenceIsCheapNoOp(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 1)
	authInfo := boundAuthInfo(f.identity())
	ss := &fakeServerStream{ctx: authContext(authInfo)}

	stream := &authServerStream{
		ServerStream:  ss,
		authInfo:      authInfo,
		provider:      enforcingProvider(bundle),
		fullMethod:    notifierStream,
		currentBundle: bundle,
	}

	require.NoError(t, stream.RecvMsg(nil))
	require.NoError(t, stream.SendMsg(nil))
	require.Equal(t, 1, ss.recvCalls)
	require.Equal(t, 1, ss.sendCalls)
}
