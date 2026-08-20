/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// BundleProvider provides access to the channel configuration bundle.
type BundleProvider interface {
	GetBundle() (*channelconfig.Bundle, error)
	RequiresACL() bool
}

var (
	// ErrNoUpdater indicates no updater is registered (internal service).
	ErrNoUpdater = errors.New("no ACLUpdater registered")
	// ErrNoBundle indicates no channelconfig.Bundle is loaded yet.
	ErrNoBundle = errors.New("no channelconfig.Bundle loaded")

	logger = flogging.MustGetLogger("authentication")
)

// MetadataUnaryServerInterceptor authenticates and authorizes each unary RPC by verifying
// the signed envelope carried in gRPC metadata against the connection's TLS cert and the
// channel policy for info.FullMethod.
func MetadataUnaryServerInterceptor(provider BundleProvider) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (any, error) {
		if isExemptMethod(info.FullMethod) {
			return handler(ctx, req)
		}
		bundle, enforce, err := bundleForEnforcement(provider)
		if err != nil {
			return nil, err
		}
		if !enforce {
			return handler(ctx, req)
		}
		if _, err := authenticateAndAuthorize(ctx, bundle, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// MetadataStreamServerInterceptor verifies the envelope once at stream open, caches the
// resolved identity, and re-evaluates it against the current bundle on each Recv/Send so a
// mid-stream config change (e.g. the client's org removed from a policy) revokes access.
func MetadataStreamServerInterceptor(provider BundleProvider) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if isExemptMethod(info.FullMethod) {
			return handler(srv, ss)
		}
		bundle, enforce, err := bundleForEnforcement(provider)
		if err != nil {
			return err
		}
		if !enforce {
			return handler(srv, ss)
		}
		identity, err := authenticateAndAuthorize(ss.Context(), bundle, info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &mspServerStream{
			ServerStream:  ss,
			identity:      identity,
			provider:      provider,
			fullMethod:    info.FullMethod,
			currentBundle: bundle,
		})
	}
}

// authenticateAndAuthorize extracts + validates the envelope from ctx and evaluates policy.
// Returns the resolved identity for stream caching.
//
//nolint:ireturn // msp.Identity is an interface by design.
func authenticateAndAuthorize(
	ctx context.Context, bundle *channelconfig.Bundle, fullMethod string,
) (msp.Identity, error) {
	env, err := envelopeFromIncomingContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	certHash := peerTLSCertHash(ctx)
	identity, _, err := ValidateAuthEnvelope(
		env, bundle, certHash, fullMethod, DefaultEnvelopeFreshnessWindow, time.Now())
	if err != nil {
		logger.Warnf("authentication failed for %s: %+v", fullMethod, err)
		return nil, status.Error(codes.Unauthenticated, "authentication failed: "+err.Error())
	}
	if err := evaluatePolicy(bundle, identity, fullMethod); err != nil {
		return nil, err
	}
	return identity, nil
}

// peerTLSCertHash returns the SHA-256 of the peer's leaf TLS certificate, or nil when the
// connection is not mutually authenticated.
func peerTLSCertHash(ctx context.Context) []byte {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil
	}
	return ComputeTLSCertHash(tlsInfo.State.VerifiedChains[0][0].Raw)
}

// bundleForEnforcement resolves whether ACL enforcement applies. enforce is false for
// internal / non-ACL services. A non-nil error is a gRPC status ready to return.
func bundleForEnforcement(provider BundleProvider) (bundle *channelconfig.Bundle, enforce bool, err error) {
	b, e := provider.GetBundle()
	switch {
	case errors.Is(e, ErrNoUpdater):
		return nil, false, nil
	case errors.Is(e, ErrNoBundle):
		if !provider.RequiresACL() {
			return nil, false, nil
		}
		return nil, false, status.Error(codes.Unavailable, "channel configuration not available yet")
	case e != nil:
		return nil, false, status.Error(codes.Internal, "channel configuration error: "+e.Error())
	}
	if !provider.RequiresACL() {
		return nil, false, nil
	}
	return b, true, nil
}

// evaluatePolicy evaluates an identity against the policy for a method (fail-closed).
func evaluatePolicy(bundle *channelconfig.Bundle, identity msp.Identity, fullMethod string) error {
	appConfig, exists := bundle.ApplicationConfig()
	if !exists {
		return status.Error(codes.Internal, "no application config in bundle")
	}
	policyRef := appConfig.APIPolicyMapper().PolicyRefForAPI(fullMethod)
	if policyRef == "" {
		policyRef = DefaultACL[fullMethod]
	}
	if policyRef == "" {
		return status.Errorf(codes.PermissionDenied, "no ACL policy defined for resource %s", fullMethod)
	}
	policy, exists := bundle.PolicyManager().GetPolicy(policyRef)
	if !exists {
		return status.Errorf(codes.PermissionDenied, "no policy named %s", policyRef)
	}
	if err := policy.EvaluateIdentities([]msp.Identity{identity}); err != nil {
		return status.Errorf(codes.PermissionDenied, "access denied for %s: %v", fullMethod, err)
	}
	return nil
}

// mspServerStream re-evaluates the stream's cached identity against the current bundle when
// the config sequence advances, revoking access mid-stream on policy change.
type mspServerStream struct {
	grpc.ServerStream
	identity      msp.Identity
	provider      BundleProvider
	fullMethod    string
	currentBundle *channelconfig.Bundle
	mu            sync.Mutex
}

func (s *mspServerStream) RecvMsg(m any) error {
	if err := s.checkConfigAndRevalidate(); err != nil {
		return err
	}
	return s.ServerStream.RecvMsg(m)
}

func (s *mspServerStream) SendMsg(m any) error {
	if err := s.checkConfigAndRevalidate(); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(m)
}

func (s *mspServerStream) checkConfigAndRevalidate() error {
	latestBundle, err := s.provider.GetBundle()
	if err != nil {
		return status.Error(codes.Internal, "config not available: "+err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cachedSeq := s.currentBundle.ConfigtxValidator().Sequence()
	latestSeq := latestBundle.ConfigtxValidator().Sequence()
	if latestSeq == cachedSeq {
		return nil
	}
	if err := evaluatePolicy(latestBundle, s.identity, s.fullMethod); err != nil {
		return errors.Wrapf(err, "access revoked due to config change (seq %d -> %d)", cachedSeq, latestSeq)
	}
	s.currentBundle = latestBundle
	return nil
}
