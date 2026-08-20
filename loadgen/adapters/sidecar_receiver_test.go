/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package adapters

import (
	"context"
	"net"
	"testing"

	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/utils/auth"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/serialization"
)

// protectedMethodForTest is a method present in auth.DefaultACL (Readers policy), used to
// exercise real ACL enforcement end-to-end against the dial options clientAuthDialOptions
// builds, without needing the full committerpb stubs.
const protectedMethodForTest = "/committerpb.QueryService/GetRows"

// staticBundleProvider is a minimal auth.BundleProvider backed by a fixed bundle, always
// requiring ACL enforcement.
type staticBundleProvider struct {
	bundle *channelconfig.Bundle
}

func (s *staticBundleProvider) GetBundle() (*channelconfig.Bundle, error) {
	return s.bundle, nil
}

func (*staticBundleProvider) RequiresACL() bool {
	return true
}

// echoUnaryHandlerForTest implements a trivial unary RPC under protectedMethodForTest's
// service/method name, letting the real auth.MetadataUnaryServerInterceptor run against a
// genuine (if minimal) registered gRPC method. Its parameter order is fixed by
// grpc.MethodDesc.Handler's type (grpc.methodHandler): (srv, ctx, dec, interceptor).
//
//nolint:revive // context-as-argument: signature is fixed by the grpc.methodHandler type.
func echoUnaryHandlerForTest(
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
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: protectedMethodForTest}
	return interceptor(ctx, in, info, handler)
}

// startACLEnforcedTestServer starts a loopback gRPC server with the real
// auth.MetadataUnaryServerInterceptor installed, enforcing ACL against bundle for
// protectedMethodForTest. It returns the dial address.
func startACLEnforcedTestServer(t *testing.T, bundle *channelconfig.Bundle) string {
	t.Helper()

	provider := &staticBundleProvider{bundle: bundle}
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.MetadataUnaryServerInterceptor(provider)))
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "committerpb.QueryService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "GetRows", Handler: echoUnaryHandlerForTest},
		},
		Metadata: "sidecar_receiver_test",
	}, struct{}{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// TestClientAuthDialOptions proves that clientAuthDialOptions/loadDeliverySigner — the helpers
// runSidecarReceiver uses to attach client-side ACL auth to the sidecar delivery dial — behave
// correctly at both ends: a policy pointing at real peer crypto artifacts produces a signer
// whose envelope a real ACL-enforcing server accepts, while a policy without artifacts (the
// non-ACL default) yields a nil signer, i.e. the interceptors stay no-op passthroughs and the
// same ACL-enforcing server rejects the call for lack of an envelope.
func TestClientAuthDialOptions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(dir, &testcrypto.ConfigBlock{
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	bundle, err := serialization.ExtractAppBundle(block.Data.Data[0])
	require.NoError(t, err)

	addr := startACLEnforcedTestServer(t, bundle)

	dial := func(t *testing.T, opts []grpc.DialOption) *grpc.ClientConn {
		t.Helper()
		dialOpts := append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, opts...)
		cc, err := grpc.NewClient(addr, dialOpts...)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cc.Close() })
		return cc
	}

	t.Run("policy with artifacts attaches a valid envelope and ACL accepts it", func(t *testing.T) {
		t.Parallel()
		policy := &workload.PolicyProfile{ArtifactsPath: dir, ChannelID: "testchannel"}
		opts, dialErr := clientAuthDialOptions(policy, connection.TLSConfig{})
		require.NoError(t, dialErr)

		cc := dial(t, opts)
		reply := new(emptypb.Empty)
		invokeErr := cc.Invoke(t.Context(), protectedMethodForTest, &emptypb.Empty{}, reply)
		require.NoError(t, invokeErr)
	})

	t.Run("policy without artifacts is a no-op and ACL rejects the call", func(t *testing.T) {
		t.Parallel()
		policy := &workload.PolicyProfile{ArtifactsPath: "", ChannelID: "testchannel"}
		opts, dialErr := clientAuthDialOptions(policy, connection.TLSConfig{})
		require.NoError(t, dialErr)

		cc := dial(t, opts)
		reply := new(emptypb.Empty)
		invokeErr := cc.Invoke(t.Context(), protectedMethodForTest, &emptypb.Empty{}, reply)
		require.Equal(t, codes.Unauthenticated, status.Code(invokeErr))
	})
}

// TestLoadDeliverySigner directly exercises loadDeliverySigner's two branches: absent
// artifacts must yield a nil signer without error (the non-ACL default), and real peer
// artifacts must yield a usable signing identity.
func TestLoadDeliverySigner(t *testing.T) {
	t.Parallel()

	t.Run("empty artifacts path yields a nil signer", func(t *testing.T) {
		t.Parallel()
		signer, err := loadDeliverySigner("")
		require.NoError(t, err)
		require.Nil(t, signer)
	})

	t.Run("real artifacts yield a usable signer", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		_, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(dir, &testcrypto.ConfigBlock{
			ChannelID:             "testchannel",
			PeerOrganizationCount: 1,
		})
		require.NoError(t, err)

		signer, err := loadDeliverySigner(dir)
		require.NoError(t, err)
		require.NotNil(t, signer)
	})
}
