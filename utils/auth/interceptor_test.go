/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/utils/auth"
)

// fakeProvider is a test double for auth.BundleProvider.
type fakeProvider struct {
	bundle      *channelconfig.Bundle
	err         error
	requiresACL bool
}

func (p *fakeProvider) GetBundle() (*channelconfig.Bundle, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.bundle, nil
}

func (p *fakeProvider) RequiresACL() bool {
	return p.requiresACL
}

// generateThrowawayCert creates a self-signed leaf certificate for use as a peer TLS
// certificate in tests. The returned certificate's Raw field holds the exact DER bytes that
// production code (peerTLSCertHash) hashes, so a test can derive a matching cert hash via
// auth.ComputeTLSCertHash(cert.Raw).
func generateThrowawayCert(t *testing.T) *x509.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// incomingCtxWithEnvelopeAndCert builds a context carrying both the signed auth envelope in
// incoming gRPC metadata and a peer whose verified TLS chain leaf is cert, mimicking a
// terminated mTLS connection.
func incomingCtxWithEnvelopeAndCert(t *testing.T, env *cb.Envelope, cert *x509.Certificate) context.Context {
	t.Helper()

	raw, err := proto.Marshal(env)
	require.NoError(t, err)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
		auth.MetadataEnvelopeKey: []string{string(raw)},
	})

	return peer.NewContext(ctx, &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{cert}},
			},
		},
	})
}

// fakeServerStream is a minimal grpc.ServerStream test double: no real gRPC connection is
// needed since MetadataStreamServerInterceptor only calls Context() before delegating to the
// handler, and the wrapped mspServerStream only calls RecvMsg/SendMsg on the inner stream.
type fakeServerStream struct {
	grpc.ServerStream
	//nolint:containedctx // test double mimics grpc.ServerStream, which itself carries a context.
	ctx        context.Context
	recvCalled bool
	sendCalled bool
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func (s *fakeServerStream) RecvMsg(any) error {
	s.recvCalled = true
	return nil
}

func (s *fakeServerStream) SendMsg(any) error {
	s.sendCalled = true
	return nil
}

// revokeBundle derives a new *channelconfig.Bundle from base's own config: it bumps the
// config sequence by one and deletes the Application "Readers" policy, so a subsequent
// evaluation of any identity against the returned bundle's ACL fails with PermissionDenied.
// This simulates a real channel-configuration update (e.g. an org's access being revoked)
// landing while a stream is open, using the exact same Bundle/PolicyManager machinery
// production code uses — no interceptor logic is bypassed or stubbed.
func revokeBundle(t *testing.T, base *channelconfig.Bundle) *channelconfig.Bundle {
	t.Helper()

	origConfig := base.ConfigtxValidator().ConfigProto()
	require.NotNil(t, origConfig)

	newConfig, ok := proto.Clone(origConfig).(*cb.Config)
	require.True(t, ok)
	newConfig.Sequence = origConfig.Sequence + 1

	appGroup := newConfig.ChannelGroup.Groups[channelconfig.ApplicationGroupKey]
	require.NotNil(t, appGroup, "fixture must have an Application config group")
	require.Contains(t, appGroup.Policies, "Readers", "fixture must have a Readers policy to revoke")
	delete(appGroup.Policies, "Readers")

	newBundle, err := channelconfig.NewBundle(testChannelID, newConfig, factory.GetDefault())
	require.NoError(t, err)
	require.Greater(t, newBundle.ConfigtxValidator().Sequence(), base.ConfigtxValidator().Sequence())
	return newBundle
}

func TestUnaryInterceptor_ValidEnvelopePasses(t *testing.T) {
	t.Parallel()
	bundle, signer, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	const method = "/committerpb.QueryService/GetRows"

	cert := generateThrowawayCert(t)
	certHash := auth.ComputeTLSCertHash(cert.Raw)

	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)
	ctx := incomingCtxWithEnvelopeAndCert(t, env, cert) // helper: metadata + peer TLSInfo

	called := false
	handler := func(context.Context, any) (any, error) { called = true; return "ok", nil }
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)
	require.True(t, called)
}

func TestUnaryInterceptor_MissingEnvelopeUnauthenticated(t *testing.T) {
	t.Parallel()
	bundle, _, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(context.Context, any) (any, error) { return nil, nil })
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryInterceptor_BundleNotReadyUnavailable(t *testing.T) {
	t.Parallel()
	provider := &fakeProvider{err: auth.ErrNoBundle, requiresACL: true}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(context.Context, any) (any, error) { return nil, nil })
	require.Equal(t, codes.Unavailable, status.Code(err))
}

func TestUnaryInterceptor_ExemptMethodPasses(t *testing.T) {
	t.Parallel()
	provider := &fakeProvider{err: auth.ErrNoBundle, requiresACL: true}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	called := false
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"},
		func(context.Context, any) (any, error) { called = true; return nil, nil })
	require.NoError(t, err)
	require.True(t, called)
}

// TestUnaryInterceptor_WrongMethodUnauthenticated exercises the interceptor-level mapping of
// a method-binding mismatch to codes.Unauthenticated (the pure-function case is already
// covered by TestValidateAuthEnvelope_WrongMethodRejected in envelope_utils_test.go).
func TestUnaryInterceptor_WrongMethodUnauthenticated(t *testing.T) {
	t.Parallel()
	bundle, signer, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	const boundMethod = "/committerpb.QueryService/GetRows"
	const calledMethod = "/committerpb.QueryService/BeginView"

	cert := generateThrowawayCert(t)
	certHash := auth.ComputeTLSCertHash(cert.Raw)
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, boundMethod, certHash)
	require.NoError(t, err)
	ctx := incomingCtxWithEnvelopeAndCert(t, env, cert)

	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: calledMethod},
		func(context.Context, any) (any, error) { return nil, nil })
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestUnaryInterceptor_NoUpdaterPasses covers bundleForEnforcement's ErrNoUpdater branch:
// internal services with no ACLUpdater registered bypass enforcement entirely.
func TestUnaryInterceptor_NoUpdaterPasses(t *testing.T) {
	t.Parallel()
	provider := &fakeProvider{err: auth.ErrNoUpdater, requiresACL: true}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	called := false
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(context.Context, any) (any, error) { called = true; return nil, nil })
	require.NoError(t, err)
	require.True(t, called)
}

// TestUnaryInterceptor_NoBundleNotRequiredPasses covers bundleForEnforcement's
// ErrNoBundle-but-!RequiresACL branch: a service that doesn't require ACL enforcement bypasses
// even when the bundle isn't loaded yet.
func TestUnaryInterceptor_NoBundleNotRequiredPasses(t *testing.T) {
	t.Parallel()
	provider := &fakeProvider{err: auth.ErrNoBundle, requiresACL: false}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	called := false
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(context.Context, any) (any, error) { called = true; return nil, nil })
	require.NoError(t, err)
	require.True(t, called)
}

// TestUnaryInterceptor_BundleNotRequiredPasses covers bundleForEnforcement's
// bundle-present-but-!RequiresACL branch: enforcement is skipped even though a bundle is
// available, because the service doesn't require ACL.
func TestUnaryInterceptor_BundleNotRequiredPasses(t *testing.T) {
	t.Parallel()
	bundle, _, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: false}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	called := false
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(context.Context, any) (any, error) { called = true; return nil, nil })
	require.NoError(t, err)
	require.True(t, called)
}

// TestUnaryInterceptor_OtherProviderErrorInternal covers bundleForEnforcement's fallback
// branch: a provider error that is neither ErrNoUpdater nor ErrNoBundle is an unexpected
// internal condition and must not silently bypass enforcement.
func TestUnaryInterceptor_OtherProviderErrorInternal(t *testing.T) {
	t.Parallel()
	provider := &fakeProvider{err: errors.New("boom"), requiresACL: true}
	interceptor := auth.MetadataUnaryServerInterceptor(provider)
	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(context.Context, any) (any, error) { return nil, nil })
	require.Equal(t, codes.Internal, status.Code(err))
}

// TestStreamInterceptor_ValidEnvelopePasses covers the stream-open happy path: a valid
// envelope in the stream's context lets MetadataStreamServerInterceptor call the handler with
// a wrapped stream, with no error.
func TestStreamInterceptor_ValidEnvelopePasses(t *testing.T) {
	t.Parallel()
	bundle, signer, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	const method = "/committerpb.QueryService/GetRows"

	cert := generateThrowawayCert(t)
	certHash := auth.ComputeTLSCertHash(cert.Raw)
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)
	ctx := incomingCtxWithEnvelopeAndCert(t, env, cert)

	stream := &fakeServerStream{ctx: ctx}
	var handlerCalled bool
	var wrapped grpc.ServerStream
	handler := func(_ any, ss grpc.ServerStream) error {
		handlerCalled = true
		wrapped = ss
		return nil
	}
	interceptor := auth.MetadataStreamServerInterceptor(provider)
	err = interceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: method}, handler)
	require.NoError(t, err)
	require.True(t, handlerCalled)
	require.NotNil(t, wrapped)
}

// TestStreamInterceptor_MissingEnvelopeUnauthenticated mirrors the unary missing-envelope
// case at stream-open time: MetadataStreamServerInterceptor must reject before ever invoking
// the handler.
func TestStreamInterceptor_MissingEnvelopeUnauthenticated(t *testing.T) {
	t.Parallel()
	bundle, _, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	stream := &fakeServerStream{ctx: context.Background()}
	called := false
	interceptor := auth.MetadataStreamServerInterceptor(provider)
	err := interceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: "/committerpb.QueryService/GetRows"},
		func(any, grpc.ServerStream) error { called = true; return nil })
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.False(t, called)
}

// TestStreamInterceptor_SameSequencePassthrough is the key non-revocation counterpart: when
// the provider's bundle sequence hasn't advanced, checkConfigAndRevalidate's re-check is a
// cheap no-op and RecvMsg/SendMsg delegate straight through to the underlying stream.
func TestStreamInterceptor_SameSequencePassthrough(t *testing.T) {
	t.Parallel()
	bundle, signer, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	const method = "/committerpb.QueryService/GetRows"

	cert := generateThrowawayCert(t)
	certHash := auth.ComputeTLSCertHash(cert.Raw)
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)
	ctx := incomingCtxWithEnvelopeAndCert(t, env, cert)

	stream := &fakeServerStream{ctx: ctx}
	var wrapped grpc.ServerStream
	handler := func(_ any, ss grpc.ServerStream) error { wrapped = ss; return nil }
	interceptor := auth.MetadataStreamServerInterceptor(provider)
	require.NoError(t, interceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: method}, handler))
	require.NotNil(t, wrapped)

	// provider.bundle is unchanged (same pointer, same sequence) => re-check is a no-op.
	require.NoError(t, wrapped.RecvMsg("payload"))
	require.True(t, stream.recvCalled, "RecvMsg must delegate to the underlying stream")

	require.NoError(t, wrapped.SendMsg("payload"))
	require.True(t, stream.sendCalled, "SendMsg must delegate to the underlying stream")
}

// TestStreamInterceptor_MidStreamRevocationPermissionDenied is the key security property this
// task exists to verify: a channel-configuration update that advances the config sequence and
// revokes the client's ACL must be picked up on the very next Recv/Send and reject the call,
// even though the identity was already authenticated once at stream-open time.
func TestStreamInterceptor_MidStreamRevocationPermissionDenied(t *testing.T) {
	t.Parallel()
	bundle, signer, _ := setupAuthFixture(t)
	provider := &fakeProvider{bundle: bundle, requiresACL: true}
	const method = "/committerpb.QueryService/GetRows"

	cert := generateThrowawayCert(t)
	certHash := auth.ComputeTLSCertHash(cert.Raw)
	env, err := auth.BuildAuthEnvelope(signer, testChannelID, method, certHash)
	require.NoError(t, err)
	ctx := incomingCtxWithEnvelopeAndCert(t, env, cert)

	stream := &fakeServerStream{ctx: ctx}
	var wrapped grpc.ServerStream
	handler := func(_ any, ss grpc.ServerStream) error { wrapped = ss; return nil }
	interceptor := auth.MetadataStreamServerInterceptor(provider)
	require.NoError(t, interceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: method}, handler))
	require.NotNil(t, wrapped)

	// Simulate a channel-config update landing mid-stream: same channel, higher sequence,
	// Readers policy revoked. The provider now serves this bundle on the next GetBundle() call.
	provider.bundle = revokeBundle(t, bundle)

	err = wrapped.RecvMsg("payload")
	// The error is wrapped via errors.Wrapf inside checkConfigAndRevalidate; status.Code walks
	// the Unwrap chain via status.FromError, so the original gRPC code survives the wrap.
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.False(t, stream.recvCalled, "underlying RecvMsg must not be reached once access is revoked")
}
