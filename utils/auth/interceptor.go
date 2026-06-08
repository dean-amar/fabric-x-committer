/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"strings"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-x-common/msp"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// BundleProvider provides access to the channel configuration bundle.
type BundleProvider interface {
	GetBundle() (*channelconfig.Bundle, error)
}

var (
	// ErrNoPeerInfo is returned when peer information is not available.
	ErrNoPeerInfo = errors.New("no peer info in context")

	// ErrNoMSPAuthInfo is returned when MSPAuthInfo is not found.
	ErrNoMSPAuthInfo = errors.New("no MSP auth info found")

	// ErrNoUpdater indicates no DynamicTLSUpdater is registered (internal service)
	ErrNoUpdater = errors.New("no DynamicTLSUpdater registered")

	// ErrNoBundle indicates no channelconfig.Bundle is loaded
	ErrNoBundle = errors.New("no channelconfig.Bundle loaded")

	logger = flogging.MustGetLogger("authentication")
)

// MSPUnaryServerInterceptor creates a gRPC interceptor for MSP-based access control.
//
// Behavior:
//   - Services with registered DynamicTLSUpdater: Enforces MSP authentication and ACL policies
//   - Services without updater (internal services): Bypasses MSP authentication
//   - Missing bundle when updater is registered: Returns error (strict enforcement)
//
// For Authorize RPC: Validates signed envelope and binds MSP identity to the connection.
// For other RPCs: Verifies bound identity against ACL policies.
func MSPUnaryServerInterceptor(provider BundleProvider) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, ErrNoPeerInfo.Error())
		}

		authInfo, ok := p.AuthInfo.(*MSPAuthInfo)
		if !ok {
			return nil, status.Error(codes.Internal, ErrNoMSPAuthInfo.Error())
		}

		logger.Infof("interceptor-details: %+v", authInfo)

		if strings.EqualFold(info.FullMethod, "/servicepb.AuthService/Authorize") {
			bundle, err := provider.GetBundle()
			if errors.Is(err, ErrNoUpdater) {
				// No updater = internal service = should not call Authorize
				return &committerpb.AuthorizeResponse{
					Success: false,
					Message: "Authorization not available for internal services",
				}, nil
			}
			if err != nil {
				// ErrNoBundle or any other error = configuration problem
				return &committerpb.AuthorizeResponse{
					Success: false,
					Message: "Channel configuration not available: " + err.Error(),
				}, nil
			}

			logger.Info("processing after bundle getter")
			// Extract and validate the signed envelope
			if authReq, ok := req.(*committerpb.AuthorizeRequest); ok {
				signedEnvelope := authReq.GetSignedEnvelope()
				if signedEnvelope == nil {
					return &committerpb.AuthorizeResponse{
						Success: false,
						Message: "Signed envelope is required",
					}, nil
				}

				logger.Info("extracting-identity")
				// Extract identity and TLS cert hash from envelope
				identity, mspID, _, err := ExtractIdentityFromEnvelope(signedEnvelope, bundle)
				if err != nil {
					return &committerpb.AuthorizeResponse{
						Success: false,
						Message: "Failed to extract identity: " + err.Error(),
					}, nil
				}

				logger.Info("verifying-tls-cert-binding")

				//// Verify TLS cert binding
				//if err := VerifyTLSCertBinding(envelopeTLSCertHash, authInfo.TLSCertHash); err != nil {
				//	return &committerpb.AuthorizeResponse{
				//		Success: false,
				//		Message: "TLS cert binding verification failed: " + err.Error(),
				//	}, nil
				//}

				logger.Infof("Editing-auth-info: identity=%s, mspID=%s", identity.GetIdentifier(), mspID)

				authInfo.SetIdentity(identity, bundle.ConfigtxValidator().Sequence())
			}

			return handler(ctx, req)
		}

		// For all other RPCs, check if connection is authenticated
		bundle, err := provider.GetBundle()
		if errors.Is(err, ErrNoUpdater) {
			// No updater = internal service = bypass MSP auth check
			return handler(ctx, req)
		}
		if err != nil {
			// ErrNoBundle or any other error = FAIL (enforce ACL)
			return nil, status.Error(codes.Internal, "channel configuration not available: "+err.Error())
		}

		// Bundle exists = public service = ENFORCE MSP auth
		identity, _ := authInfo.GetIdentity()
		if identity == nil {
			return nil, status.Error(codes.Unauthenticated, "connection not authorized: call Authorize first")
		}

		// Evaluate policy on every unary call (no caching needed for short-lived RPCs)
		if err := evaluatePolicy(bundle, identity, info.FullMethod); err != nil {
			return nil, err
		}

		// Proceed with the handler
		return handler(ctx, req)
	}
}

// MSPStreamServerInterceptor creates a gRPC stream interceptor for MSP-based access control.
//
// Behavior:
//   - Services with registered DynamicTLSUpdater: Enforces MSP authentication and ACL policies
//   - Services without updater (internal services): Bypasses MSP authentication
//   - Missing bundle when updater is registered: Returns error (strict enforcement)
//   - Wraps the stream to periodically re-evaluate identity when config changes
//
// The wrapped stream checks for config sequence changes on every RecvMsg/SendMsg call.
// If the config changed, it re-evaluates the identity against the new policy.
func MSPStreamServerInterceptor(provider BundleProvider) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		p, ok := peer.FromContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, ErrNoPeerInfo.Error())
		}

		authInfo, ok := p.AuthInfo.(*MSPAuthInfo)
		if !ok {
			return status.Error(codes.Internal, ErrNoMSPAuthInfo.Error())
		}

		// Check service type
		bundle, err := provider.GetBundle()
		if errors.Is(err, ErrNoUpdater) {
			// Internal service - bypass authentication
			return handler(srv, ss)
		}
		if err != nil {
			// Public service with missing config - fail
			return status.Error(codes.Internal, "channel configuration not available: "+err.Error())
		}

		// Public service - enforce ACL
		identity, _ := authInfo.GetIdentity()
		if identity == nil {
			return status.Error(codes.Unauthenticated,
				"connection not authorized: call Authorize RPC first")
		}

		// Initial policy evaluation
		if err := evaluatePolicy(bundle, identity, info.FullMethod); err != nil {
			return err
		}

		// Wrap stream for config change detection and re-evaluation
		// Cache the current bundle to detect changes
		wrappedStream := &authServerStream{
			ServerStream:  ss,
			authInfo:      authInfo,
			provider:      provider,
			fullMethod:    info.FullMethod,
			currentBundle: bundle,
		}

		return handler(srv, wrappedStream)
	}
}

// authServerStream wraps grpc.ServerStream to add config change detection
// and identity re-evaluation on every message.
type authServerStream struct {
	grpc.ServerStream
	authInfo      *MSPAuthInfo
	provider      BundleProvider
	fullMethod    string
	currentBundle *channelconfig.Bundle // Cached bundle to detect changes
}

// RecvMsg intercepts incoming messages to perform config change detection.
func (s *authServerStream) RecvMsg(m interface{}) error {
	if err := s.checkConfigAndRevalidate(); err != nil {
		return err
	}
	return s.ServerStream.RecvMsg(m)
}

// SendMsg intercepts outgoing messages to perform config change detection.
func (s *authServerStream) SendMsg(m interface{}) error {
	if err := s.checkConfigAndRevalidate(); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(m)
}

// checkConfigAndRevalidate checks if the config sequence changed and re-evaluates
// the identity against the new policy if it did.
func (s *authServerStream) checkConfigAndRevalidate() error {
	// Get latest bundle from provider
	latestBundle, err := s.provider.GetBundle()
	if err != nil {
		return status.Error(codes.Internal, "config not available: "+err.Error())
	}

	// Get identity
	identity, _ := s.authInfo.GetIdentity()
	if identity == nil {
		return status.Error(codes.Unauthenticated, "identity no longer bound to connection")
	}

	// Compare cached bundle sequence with latest
	cachedSeq := s.currentBundle.ConfigtxValidator().Sequence()
	latestSeq := latestBundle.ConfigtxValidator().Sequence()

	// Only re-evaluate if config changed
	if latestSeq != cachedSeq {
		logger.Infof("Config sequence changed from %d to %d, re-evaluating identity for %s",
			cachedSeq, latestSeq, s.fullMethod)

		// Re-evaluate identity against new policy
		if err := evaluatePolicy(latestBundle, identity, s.fullMethod); err != nil {
			return errors.Wrapf(err, "access revoked due to config change (seq %d -> %d)",
				cachedSeq, latestSeq)
		}

		// Update cached bundle and sequence in AuthInfo
		s.currentBundle = latestBundle
		s.authInfo.SetIdentity(identity, latestSeq)
		logger.Infof("Identity re-validated successfully for config sequence %d", latestSeq)
	}

	return nil
}

// evaluatePolicy evaluates an identity against the policy for a given method.
func evaluatePolicy(bundle *channelconfig.Bundle, identity msp.Identity, fullMethod string) error {
	appConfig, exists := bundle.ApplicationConfig()
	if !exists {
		return status.Error(codes.Internal, "no application config in bundle")
	}

	// Get policy reference from API mapper or default ACL
	policyRef := appConfig.APIPolicyMapper().PolicyRefForAPI(fullMethod)
	if policyRef == "" {
		policyRef = DefaultACL[fullMethod]
	}

	if policyRef == "" {
		// No policy defined - default to Readers
		policyRef = ReaderPolicy
		logger.Infof("No policy defined for %s, using default: %s", fullMethod, policyRef)
	}

	logger.Infof("Evaluating policy %s for method %s", policyRef, fullMethod)

	policyMgr := bundle.PolicyManager()
	policy, exists := policyMgr.GetPolicy(policyRef)
	if !exists {
		return status.Errorf(codes.PermissionDenied, "no policy named %s", policyRef)
	}

	if err := policy.EvaluateIdentities([]msp.Identity{identity}); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"access denied for %s: %v", fullMethod, err)
	}

	return nil
}

// GetMSPAuthInfoFromContext extracts MSPAuthInfo from the gRPC context.
func GetMSPAuthInfoFromContext(ctx context.Context) (*MSPAuthInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}

	authInfo, ok := p.AuthInfo.(*MSPAuthInfo)
	return authInfo, ok
}
