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
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// BundleProvider provides access to the channel configuration bundle.
type BundleProvider interface {
	GetBundle() (*channelconfig.Bundle, error)
	RequiresACL() bool
}

var (
	// ErrNoPeerInfo is returned when peer information is not available.
	ErrNoPeerInfo = errors.New("no peer info in context")

	// ErrNoMSPAuthInfo is returned when MSPAuthInfo is not found.
	ErrNoMSPAuthInfo = errors.New("no MSP auth info found")

	// ErrNoUpdater indicates no ACLUpdater is registered (internal service).
	ErrNoUpdater = errors.New("no ACLUpdater registered")

	// ErrNoBundle indicates no channelconfig.Bundle is loaded.
	ErrNoBundle = errors.New("no channelconfig.Bundle loaded")

	logger = flogging.MustGetLogger("authentication")
)

// AuthorizeInterceptor creates a gRPC interceptor specifically for the Authorize RPC.
// It validates the signed envelope — including replay-prevention checks (timestamp
// freshness always, and TLS cert-hash binding under mTLS) — and binds the resolved MSP
// identity to the connection so subsequent RPCs on that connection reuse it.
//
// Behavior:
//   - Services with a registered ACLUpdater: processes authorization.
//   - Services without an updater (internal services): rejects (should not call Authorize).
//   - Missing bundle on an ACL-enforced service: rejects (configuration not ready).
func AuthorizeInterceptor(provider BundleProvider) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Only intercept the Authorize RPC; everything else is handled downstream.
		if info.FullMethod != AuthenticationResource {
			return handler(ctx, req)
		}

		authInfo, err := authInfoFromContext(ctx)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		// Resolve the bundle. A not-yet-loaded bundle on an ACL-enforced service returns
		// codes.Unavailable so the client retries during the bootstrap window; an internal
		// service (no updater / no ACL) has nothing to authorize against.
		bundle, enforce, err := bundleForEnforcement(provider)
		if err != nil {
			return nil, err
		}
		if !enforce {
			return &committerpb.AuthorizeResponse{
				Success: false,
				Message: "authorization not available for this service",
			}, nil
		}

		authReq, ok := req.(*committerpb.AuthorizeRequest)
		if !ok {
			return &committerpb.AuthorizeResponse{Success: false, Message: "invalid request type"}, nil
		}
		signedEnvelope := authReq.GetSignedEnvelope()
		if signedEnvelope == nil {
			return &committerpb.AuthorizeResponse{Success: false, Message: "signed envelope is required"}, nil
		}

		identity, mspID, err := ValidateAuthEnvelope(
			signedEnvelope, bundle, authInfo, DefaultEnvelopeFreshnessWindow, time.Now(),
		)
		if err != nil {
			// Report the denial in-band via the response, not as a gRPC error, so the client
			// gets a structured, permanent "not authorized" signal (and does not retry it as a
			// transport failure). This is intentional; the client inspects resp.Success.
			//nolint:nilerr // failure is reported in-band via AuthorizeResponse.Success=false.
			return &committerpb.AuthorizeResponse{
				Success: false,
				Message: "failed to authorize: " + err.Error(),
			}, nil
		}

		sequence := bundle.ConfigtxValidator().Sequence()
		authInfo.SetIdentity(identity, sequence)
		logger.Infof("Bound identity to connection: mspID=%s, identity=%s, configSequence=%d",
			mspID, identity.GetIdentifier(), sequence)

		return &committerpb.AuthorizeResponse{
			Success:        true,
			Message:        "authorized",
			MspId:          mspID,
			ConfigSequence: sequence,
		}, nil
	}
}

// MSPUnaryServerInterceptor creates a gRPC interceptor for MSP-based access control on unary RPCs.
//
// Behavior:
//   - Exempt methods (Authorize, health, reflection): always pass through.
//   - Internal services (no ACLUpdater) or services that don't require ACL: bypass.
//   - ACL-enforced services: require a bound identity and evaluate it against the ACL policy.
func MSPUnaryServerInterceptor(provider BundleProvider) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
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

		identity, err := boundIdentity(ctx)
		if err != nil {
			return nil, err
		}

		// Evaluate the policy on every unary call; short-lived RPCs need no caching.
		if err := evaluatePolicy(bundle, identity, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// MSPStreamServerInterceptor creates a gRPC stream interceptor for MSP-based access control.
//
// The wrapped stream re-checks the config sequence on every RecvMsg/SendMsg. If the config
// advanced, it re-evaluates the bound identity against the new policy, terminating the stream
// if access was revoked (e.g. the client's organization was removed from the channel).
func MSPStreamServerInterceptor(provider BundleProvider) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
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

		identity, err := boundIdentity(ss.Context())
		if err != nil {
			return err
		}

		// Initial policy evaluation at stream establishment.
		if err := evaluatePolicy(bundle, identity, info.FullMethod); err != nil {
			return err
		}

		authInfo, _ := GetMSPAuthInfoFromContext(ss.Context())
		return handler(srv, &authServerStream{
			ServerStream:  ss,
			authInfo:      authInfo,
			provider:      provider,
			fullMethod:    info.FullMethod,
			currentBundle: bundle,
		})
	}
}

// bundleForEnforcement resolves whether ACL enforcement applies for the current request
// and returns the bundle to evaluate against. enforce is false when the service is internal
// or otherwise does not require ACL. A non-nil error is a gRPC status ready to return.
func bundleForEnforcement(provider BundleProvider) (bundle *channelconfig.Bundle, enforce bool, err error) {
	b, e := provider.GetBundle()
	switch {
	case errors.Is(e, ErrNoUpdater):
		// No ACLUpdater registered → internal service → no ACL.
		return nil, false, nil
	case errors.Is(e, ErrNoBundle):
		if !provider.RequiresACL() {
			// Service doesn't enforce ACL (e.g. orderer) → bypass.
			return nil, false, nil
		}
		// ACL-enforced service, but the bundle hasn't been loaded yet. Fail closed;
		// Unavailable signals the client to retry once bootstrap completes.
		return nil, false, status.Error(codes.Unavailable, "channel configuration not available yet")
	case e != nil:
		return nil, false, status.Error(codes.Internal, "channel configuration error: "+e.Error())
	}
	// A bundle loaded successfully. Enforce ACL only for services that require it: a service
	// registered with requiresACL=false (e.g. one that loads a bundle solely for dynamic TLS CA
	// refresh) must not have enforcement silently switched on just because its bundle populated.
	if !provider.RequiresACL() {
		return nil, false, nil
	}
	return b, true, nil
}

// boundIdentity returns the MSP identity bound to the connection by a prior Authorize call,
// or an Unauthenticated status if the connection has not been authorized.
//
//nolint:ireturn // msp.Identity is an interface by design.
func boundIdentity(ctx context.Context) (msp.Identity, error) {
	authInfo, err := authInfoFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	identity, _ := authInfo.GetIdentity()
	if identity == nil {
		return nil, status.Error(codes.Unauthenticated, "connection not authorized: call Authorize first")
	}
	return identity, nil
}

// authInfoFromContext extracts the connection's *MSPAuthInfo from the gRPC context.
func authInfoFromContext(ctx context.Context) (*MSPAuthInfo, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, ErrNoPeerInfo
	}
	authInfo, ok := p.AuthInfo.(*MSPAuthInfo)
	if !ok {
		return nil, ErrNoMSPAuthInfo
	}
	return authInfo, nil
}

// authServerStream wraps grpc.ServerStream to detect config-sequence changes and
// re-evaluate the bound identity against the current policy on every message.
//
// A bidirectional stream (e.g. peer.Deliver, OpenNotificationStream) drives RecvMsg and SendMsg
// from separate goroutines, so both may call checkConfigAndRevalidate concurrently. mu guards the
// compare-and-update of currentBundle so that racing revalidations cannot corrupt the cached
// bundle or each other's view of the last-evaluated sequence.
type authServerStream struct {
	grpc.ServerStream
	authInfo   *MSPAuthInfo
	provider   BundleProvider
	fullMethod string

	mu            sync.Mutex
	currentBundle *channelconfig.Bundle // last bundle the identity was evaluated against; guarded by mu
}

// RecvMsg re-checks the config before receiving.
func (s *authServerStream) RecvMsg(m any) error {
	if err := s.checkConfigAndRevalidate(); err != nil {
		return err
	}
	return s.ServerStream.RecvMsg(m)
}

// SendMsg re-checks the config before sending.
func (s *authServerStream) SendMsg(m any) error {
	if err := s.checkConfigAndRevalidate(); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(m)
}

// checkConfigAndRevalidate re-evaluates the bound identity only when the config sequence
// has advanced since the last evaluation. On an unchanged sequence it is a cheap no-op.
func (s *authServerStream) checkConfigAndRevalidate() error {
	latestBundle, err := s.provider.GetBundle()
	if err != nil {
		return status.Error(codes.Internal, "config not available: "+err.Error())
	}

	identity, _ := s.authInfo.GetIdentity()
	if identity == nil {
		return status.Error(codes.Unauthenticated, "identity no longer bound to connection")
	}

	// RecvMsg and SendMsg may run concurrently on a bidirectional stream; serialize the
	// compare-and-update of the cached bundle so the two directions cannot race on it.
	s.mu.Lock()
	defer s.mu.Unlock()

	cachedSeq := s.currentBundle.ConfigtxValidator().Sequence()
	latestSeq := latestBundle.ConfigtxValidator().Sequence()
	if latestSeq == cachedSeq {
		return nil
	}

	logger.Infof("Config sequence advanced %d -> %d, re-evaluating identity for %s",
		cachedSeq, latestSeq, s.fullMethod)
	if err := evaluatePolicy(latestBundle, identity, s.fullMethod); err != nil {
		return errors.Wrapf(err, "access revoked due to config change (seq %d -> %d)", cachedSeq, latestSeq)
	}

	s.currentBundle = latestBundle
	s.authInfo.SetIdentity(identity, latestSeq)
	return nil
}

// evaluatePolicy evaluates an identity against the policy for a given method. Policy
// resolution is fail-closed: a method with no policy in the channel config and no default
// mapping is denied, so a newly-added RPC cannot be silently reachable.
func evaluatePolicy(bundle *channelconfig.Bundle, identity msp.Identity, fullMethod string) error {
	appConfig, exists := bundle.ApplicationConfig()
	if !exists {
		return status.Error(codes.Internal, "no application config in bundle")
	}

	// 1. Channel configuration ACLs section. 2. Hard-coded default map.
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

	logger.Debugf("Policy %s satisfied for method %s", policyRef, fullMethod)
	return nil
}

// GetMSPAuthInfoFromContext extracts MSPAuthInfo from the gRPC context.
func GetMSPAuthInfoFromContext(ctx context.Context) (*MSPAuthInfo, bool) {
	authInfo, err := authInfoFromContext(ctx)
	if err != nil {
		return nil, false
	}
	return authInfo, true
}
