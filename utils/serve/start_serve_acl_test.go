/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-committer/utils/auth"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/serialization"
)

// aclTestFixture is a real bundle + signing identity derived from the same testcrypto crypto
// material, mirroring the pattern used across utils/auth's tests (setupAuthFixture) and
// acl_provider_test.go (loadBaseConfig). The bundle and signer MUST come from the same crypto
// material so the signer's identity is trusted by the bundle's MSP.
//
//nolint:ireturn // msp.SigningIdentity is an interface by design.
func newACLTestFixture(t *testing.T) (*channelconfig.Bundle, msp.SigningIdentity) {
	t.Helper()

	dir := t.TempDir()
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(dir, &testcrypto.ConfigBlock{
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	bundle, err := serialization.ExtractAppBundle(block.Data.Data[0])
	require.NoError(t, err)

	signer := auth.CreateTestSigner(t, dir)
	return bundle, signer
}

// protectedUnaryMethod is a method name present in auth.DefaultACL (Readers policy), used to
// exercise real ACL enforcement end-to-end without needing the full committerpb stubs.
const protectedUnaryMethod = "/committerpb.QueryService/GetRows"

// protectedStreamMethod is a streaming method name present in auth.DefaultACL (Readers policy).
const protectedStreamMethod = "/committerpb.Notifier/OpenNotificationStream"

// echoUnaryHandler implements a trivial unary RPC under protectedUnaryMethod's service/method
// name, letting the real interceptor chain installed by newGRPCServer run against a genuine
// (if minimal) registered gRPC method, exactly as it would for the real QueryService. Its
// parameter order is fixed by grpc.MethodDesc.Handler's type (grpc.methodHandler): (srv, ctx,
// dec, interceptor).
//
//nolint:revive // context-as-argument: signature is fixed by the grpc.methodHandler type.
func echoUnaryHandler(
	srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	handler := func(_ context.Context, req any) (any, error) {
		return req, nil
	}
	if interceptor == nil {
		return handler(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: protectedUnaryMethod}
	return interceptor(ctx, in, info, handler)
}

// noopStreamHandler returns immediately, closing the stream cleanly. Since
// auth.MetadataStreamServerInterceptor authenticates/authorizes at stream-open time (before ever
// calling the handler), this trivial handler is enough to exercise the real enforcement: a
// rejected stream never reaches here, and an accepted stream closes with io.EOF on the client.
func noopStreamHandler(any, grpc.ServerStream) error {
	return nil
}

// registerTestServices registers exempt (health) and protected (unary + stream, bound to real
// auth.DefaultACL entries) test services on srv, so a single server exercises all three
// interceptor code paths installed by newGRPCServer.
func registerTestServices(t *testing.T, srv *grpc.Server) {
	t.Helper()

	healthgrpc.RegisterHealthServer(srv, DefaultHealthCheckService())

	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "committerpb.QueryService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "GetRows", Handler: echoUnaryHandler},
		},
		Metadata: "acl_test",
	}, struct{}{})

	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "committerpb.Notifier",
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{
			{StreamName: "OpenNotificationStream", Handler: noopStreamHandler, ServerStreams: true},
		},
		Metadata: "acl_test",
	}, struct{}{})
}

// startTestGRPCServer starts srv on a loopback TCP listener and stops it on test cleanup. It
// returns the dial address.
func startTestGRPCServer(t *testing.T, srv *grpc.Server) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// dialTest opens a plain (non-TLS) client connection, optionally attaching the ACL client
// interceptors when signer is non-nil.
func dialTest(t *testing.T, addr string, signer msp.SigningIdentity) *grpc.ClientConn {
	t.Helper()

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if signer != nil {
		cfg := auth.ClientAuthConfig{Signer: signer, ChannelID: "testchannel"}
		opts = append(opts,
			grpc.WithChainUnaryInterceptor(auth.UnaryClientInterceptor(cfg)),
			grpc.WithChainStreamInterceptor(auth.StreamClientInterceptor(cfg)),
		)
	}
	cc, err := grpc.NewClient(addr, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// newACLServerConfig builds a minimal ServerConfig for newGRPCServer, with no rate limiting /
// concurrency limiting unless overridden by the caller. The ACL interceptors are always
// installed by newGRPCServer regardless of config; whether they enforce is decided by the
// provider passed alongside it.
func newACLServerConfig() *ServerConfig {
	return &ServerConfig{
		TLS: connection.TLSConfig{},
	}
}

// buildTestACLProvider builds an insecure (no-TLS) ACLProvider with an ACLUpdater carrying the
// given bundle, requiring ACL enforcement — mirroring how a real service (sidecar, query) wires
// up an ACLProvider via RegisterACLUpdater.
func buildTestACLProvider(t *testing.T, bundle *channelconfig.Bundle) *ACLProvider {
	t.Helper()

	provider, err := NewACLProvider(connection.TLSConfig{})
	require.NoError(t, err)

	updater := NewACLUpdater(true)
	RegisterACLUpdater(provider, updater)
	require.True(t, updater.UpdateBundle(bundle))
	return provider
}

// TestNewGRPCServer_ACLEnabled_EnforcesEnvelope is the primary end-to-end proof that
// newGRPCServer wires auth.MetadataUnaryServerInterceptor / auth.MetadataStreamServerInterceptor
// into the real *grpc.Server: a real client dialing a real (loopback TCP) server gets rejected
// on a protected method without a signed envelope, accepted with one, and an exempt method
// (health) always passes regardless.
func TestNewGRPCServer_ACLEnabled_EnforcesEnvelope(t *testing.T) {
	t.Parallel()

	bundle, signer := newACLTestFixture(t)
	provider := buildTestACLProvider(t, bundle)

	srv, err := newGRPCServer(newACLServerConfig(), provider, &ConnStatsHandler{})
	require.NoError(t, err)
	registerTestServices(t, srv)
	addr := startTestGRPCServer(t, srv)

	// Each subtest below calls t.Parallel(), which suspends the subtest and returns control to
	// this function immediately; the subtests only actually run after this function returns. A
	// context created and canceled here (e.g. via defer) would therefore already be canceled by
	// the time they run, so each subtest creates its own context instead.

	t.Run("exempt method passes without envelope", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cc := dialTest(t, addr, nil)
		_, err := healthgrpc.NewHealthClient(cc).Check(ctx, &healthgrpc.HealthCheckRequest{})
		require.NoError(t, err)
	})

	t.Run("protected unary method without envelope is rejected", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cc := dialTest(t, addr, nil)
		reply := new(emptypb.Empty)
		err := cc.Invoke(ctx, protectedUnaryMethod, &emptypb.Empty{}, reply)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("protected unary method with valid envelope succeeds", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cc := dialTest(t, addr, signer)
		reply := new(emptypb.Empty)
		err := cc.Invoke(ctx, protectedUnaryMethod, &emptypb.Empty{}, reply)
		require.NoError(t, err)
	})

	t.Run("protected stream method without envelope is rejected", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cc := dialTest(t, addr, nil)
		stream, err := cc.NewStream(ctx, &grpc.StreamDesc{StreamName: "OpenNotificationStream", ServerStreams: true},
			protectedStreamMethod)
		require.NoError(t, err) // NewStream itself never fails locally; rejection surfaces on Recv.
		err = stream.RecvMsg(new(emptypb.Empty))
		require.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("protected stream method with valid envelope succeeds", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cc := dialTest(t, addr, signer)
		stream, err := cc.NewStream(ctx, &grpc.StreamDesc{StreamName: "OpenNotificationStream", ServerStreams: true},
			protectedStreamMethod)
		require.NoError(t, err)
		err = stream.RecvMsg(new(emptypb.Empty))
		require.ErrorIs(t, err, io.EOF, "server handler returns immediately, closing the stream cleanly")
	})
}

// TestNewGRPCServer_NonEnforcingProvider_NoEnforcement proves the "optimistic" model: the ACL
// interceptors are always installed, but enforcement is decided by the provider, not by config.
// A provider that does not opt in — an internal service that never registered an ACLUpdater, or
// a service (e.g. the orderer) that registered with requiresACL=false — leaves a protected
// method (one that IS in auth.DefaultACL) reachable without any envelope.
func TestNewGRPCServer_NonEnforcingProvider_NoEnforcement(t *testing.T) {
	t.Parallel()

	bundle, _ := newACLTestFixture(t)

	tests := []struct {
		name     string
		provider *ACLProvider
	}{
		{name: "no updater registered (internal service)", provider: newProviderWithoutUpdater(t)},
		{name: "updater with requiresACL=false (orderer)", provider: newOptimisticProvider(t, bundle)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, err := newGRPCServer(newACLServerConfig(), tc.provider, &ConnStatsHandler{})
			require.NoError(t, err)
			registerTestServices(t, srv)
			addr := startTestGRPCServer(t, srv)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			cc := dialTest(t, addr, nil)
			err = cc.Invoke(ctx, protectedUnaryMethod, &emptypb.Empty{}, new(emptypb.Empty))
			require.NoError(t, err, "a non-enforcing provider must let protected methods through without an envelope")
		})
	}
}

// newProviderWithoutUpdater builds an insecure ACLProvider with no ACLUpdater registered — the
// shape an internal service (coordinator, verifier, VC) leaves behind. It never enforces ACL.
func newProviderWithoutUpdater(t *testing.T) *ACLProvider {
	t.Helper()
	provider, err := NewACLProvider(connection.TLSConfig{})
	require.NoError(t, err)
	return provider
}

// newOptimisticProvider builds an insecure ACLProvider whose updater is registered with
// requiresACL=false (the orderer's optimistic registration) and carries a bundle, proving that
// even a loaded bundle does not trigger enforcement when the service opted out.
func newOptimisticProvider(t *testing.T, bundle *channelconfig.Bundle) *ACLProvider {
	t.Helper()
	provider := newProviderWithoutUpdater(t)
	updater := NewACLUpdater(false)
	RegisterACLUpdater(provider, updater)
	require.True(t, updater.UpdateBundle(bundle))
	return provider
}

// TestNewGRPCServer_ACLWithRateLimitAndConcurrency_ComposesCleanly proves that switching the
// rate-limit / concurrency installs from the singular grpc.UnaryInterceptor/StreamInterceptor
// forms to the chained grpc.ChainUnaryInterceptor/ChainStreamInterceptor forms lets ACL,
// rate-limiting, and stream-concurrency-limiting all be installed on the same server: building
// the server must not panic or error, ACL enforcement still runs first (missing envelope is
// still rejected), and a valid-envelope call still completes (possibly rate-limited, but never
// misrouted to the wrong interceptor).
func TestNewGRPCServer_ACLWithRateLimitAndConcurrency_ComposesCleanly(t *testing.T) {
	t.Parallel()

	bundle, signer := newACLTestFixture(t)
	provider := buildTestACLProvider(t, bundle)

	cfg := newACLServerConfig()
	cfg.RateLimit = RateLimitConfig{RequestsPerSecond: 1000, Burst: 1000}
	cfg.MaxConcurrentStreams = 10

	require.NotPanics(t, func() {
		srv, err := newGRPCServer(cfg, provider, &ConnStatsHandler{})
		require.NoError(t, err)
		registerTestServices(t, srv)
		addr := startTestGRPCServer(t, srv)

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		// ACL still runs first: no envelope => Unauthenticated, never bypassed by the
		// rate-limit/concurrency interceptors that now sit behind it in the chain.
		ccNoEnvelope := dialTest(t, addr, nil)
		err = ccNoEnvelope.Invoke(ctx, protectedUnaryMethod, &emptypb.Empty{}, new(emptypb.Empty))
		require.Equal(t, codes.Unauthenticated, status.Code(err))

		// A valid envelope still gets through the full chain (ACL -> rate limit -> handler).
		ccValid := dialTest(t, addr, signer)
		err = ccValid.Invoke(ctx, protectedUnaryMethod, &emptypb.Empty{}, new(emptypb.Empty))
		require.NoError(t, err)
	})
}
