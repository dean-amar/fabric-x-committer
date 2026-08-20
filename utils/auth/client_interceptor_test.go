/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth_test

import (
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hyperledger/fabric-x-committer/utils/auth"
)

// extractEnvelopeFromOutgoing reads and unmarshals the signed auth envelope that a client
// interceptor attaches to the outgoing gRPC metadata under auth.MetadataEnvelopeKey.
//
//nolint:revive // context-as-argument: t leads so this reads like the *testing.T helpers around it.
func extractEnvelopeFromOutgoing(t *testing.T, ctx context.Context) (*cb.Envelope, error) {
	t.Helper()

	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return nil, errors.New("no outgoing metadata")
	}
	vals := md.Get(auth.MetadataEnvelopeKey)
	if len(vals) == 0 {
		return nil, errors.New("no auth envelope in outgoing metadata")
	}
	env := &cb.Envelope{}
	if err := proto.Unmarshal([]byte(vals[0]), env); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal auth envelope from outgoing metadata")
	}
	return env, nil
}

// boundMethodOf unmarshals the method bound in the signed payload of env, mirroring how the
// server's validateBoundMethod reads it.
func boundMethodOf(t *testing.T, env *cb.Envelope) string {
	t.Helper()

	payload, err := protoutil.UnmarshalPayload(env.GetPayload())
	require.NoError(t, err)

	bound := &wrapperspb.StringValue{}
	require.NoError(t, proto.Unmarshal(payload.GetData(), bound))
	return bound.GetValue()
}

func TestUnaryClientInterceptor_NilSignerPassthrough(t *testing.T) {
	t.Parallel()
	interceptor := auth.UnaryClientInterceptor(auth.ClientAuthConfig{}) // nil signer
	called := false
	invoker := func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		called = true
		_, ok := metadata.FromOutgoingContext(ctx)
		require.False(t, ok, "no metadata should be added for a nil signer")
		return nil
	}
	err := interceptor(context.Background(), "/committerpb.QueryService/GetRows", nil, nil, nil, invoker)
	require.NoError(t, err)
	require.True(t, called)
}

func TestUnaryClientInterceptor_AttachesBoundEnvelope(t *testing.T) {
	t.Parallel()
	_, signer, certHash := setupAuthFixture(t)
	cfg := auth.ClientAuthConfig{Signer: signer, ChannelID: testChannelID, TLSCertHash: certHash}
	interceptor := auth.UnaryClientInterceptor(cfg)

	const method = "/committerpb.QueryService/GetRows"
	var gotEnvelopeMethod string
	invoker := func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		env, err := extractEnvelopeFromOutgoing(t, ctx) // test helper reading MetadataEnvelopeKey
		require.NoError(t, err)
		gotEnvelopeMethod = boundMethodOf(t, env) // unmarshal payload.Data StringValue
		return nil
	}
	err := interceptor(context.Background(), method, nil, nil, nil, invoker)
	require.NoError(t, err)
	require.Equal(t, method, gotEnvelopeMethod)
}

func TestStreamClientInterceptor_NilSignerPassthrough(t *testing.T) {
	t.Parallel()
	interceptor := auth.StreamClientInterceptor(auth.ClientAuthConfig{}) // nil signer
	called := false
	streamer := func(
		ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		called = true
		_, ok := metadata.FromOutgoingContext(ctx)
		require.False(t, ok, "no metadata should be added for a nil signer")
		return nil, nil
	}
	stream, err := interceptor(
		context.Background(), &grpc.StreamDesc{}, nil, "/committerpb.QueryService/BeginView", streamer)
	require.NoError(t, err)
	require.Nil(t, stream)
	require.True(t, called)
}

func TestStreamClientInterceptor_AttachesBoundEnvelope(t *testing.T) {
	t.Parallel()
	_, signer, certHash := setupAuthFixture(t)
	cfg := auth.ClientAuthConfig{Signer: signer, ChannelID: testChannelID, TLSCertHash: certHash}
	interceptor := auth.StreamClientInterceptor(cfg)

	const method = "/committerpb.QueryService/BeginView"
	var gotEnvelopeMethod string
	streamer := func(
		ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		env, err := extractEnvelopeFromOutgoing(t, ctx)
		require.NoError(t, err)
		gotEnvelopeMethod = boundMethodOf(t, env)
		return nil, nil
	}
	stream, err := interceptor(context.Background(), &grpc.StreamDesc{}, nil, method, streamer)
	require.NoError(t, err)
	require.Nil(t, stream)
	require.Equal(t, method, gotEnvelopeMethod)
}
