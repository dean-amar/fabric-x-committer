/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package acl provides the two access-control components of the ACL feature, on opposite sides of an
// RPC:
//
//   - Enforcer (server side, this file): gRPC interceptors installed on a resource server (Query,
//     Sidecar) that authorize each incoming RPC by delegating to the central AuthService. The
//     Enforcer holds no signing keys and no MSP logic.
//   - TokenSource (client side, tokensource.go): a credentials.PerRPCCredentials that authenticates
//     once with the AuthService and attaches the resulting token to outgoing RPCs.
package acl

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-x-common/common/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

var logger = flogging.MustGetLogger("acl")

const (
	// TokenMetadataKey is the gRPC metadata key carrying the client's cert-bound JWT.
	TokenMetadataKey = "authorization"

	// healthServicePrefix is the gRPC health service. Its methods are exempt from ACL enforcement:
	// health probes are infrastructure calls that carry no token and must succeed for liveness and
	// readiness checks and load-balancer health monitoring to work once ACL is enabled.
	healthServicePrefix = "/grpc.health.v1.Health/"

	// authorizeTimeout bounds an Authorize/ReAuthorize call to the AuthService. Both stream
	// establishment and re-checks use a stream context that carries no request deadline, so without
	// this a hung AuthService could block indefinitely.
	authorizeTimeout = 10 * time.Second

	// defaultRevalidateInterval is how often an open stream re-authorizes when the caller does not
	// configure an interval.
	defaultRevalidateInterval = time.Minute
)

// ErrMissingToken is returned when a request carries no authorization token.
var ErrMissingToken = errors.New("missing authorization token")

// EnforcerConfig configures the server-side Enforcer.
type EnforcerConfig struct {
	// RevalidateInterval is how often an open stream re-authorizes its bound identity against the
	// latest policy. Zero uses defaultRevalidateInterval.
	RevalidateInterval time.Duration
}

// Enforcer authorizes a resource server's incoming RPCs against the AuthService. For unary calls and
// at stream establishment it forwards the caller's token (and TLS certificate hash) to Authorize; it
// binds the identity Authorize returns to the stream and, on a background timer, asks ReAuthorize to
// re-evaluate that identity against the latest policy - so a stream is torn down when a configuration
// change removes the identity's access, independently of the establishment token's lifetime and of
// whether the stream is actively transferring messages.
type Enforcer struct {
	client             servicepb.AuthServiceClient
	revalidateInterval time.Duration
}

// NewEnforcer creates an Enforcer that delegates authorization to the given AuthService client.
func NewEnforcer(client servicepb.AuthServiceClient, cfg EnforcerConfig) *Enforcer {
	interval := cfg.RevalidateInterval
	if interval <= 0 {
		interval = defaultRevalidateInterval
	}
	return &Enforcer{client: client, revalidateInterval: interval}
}

// UnaryInterceptor authorizes every unary RPC before its handler runs. Exempt methods (e.g. health
// checks) run without authorization.
func (e *Enforcer) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if isExempt(info.FullMethod) {
			return handler(ctx, req)
		}
		token, err := tokenFromMetadata(ctx)
		if err != nil {
			return nil, grpcerror.WrapUnauthenticated(err)
		}
		// The request body is available here, so the namespaces it touches are forwarded with the
		// authorization call and the AuthService decides on them.
		if _, err = e.authorize(ctx, token, info.FullMethod, scopeOfRequest(req)); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor authorizes a stream at establishment and binds the caller's token to the session,
// so the decision can be renewed from the token alone for as long as the stream lives. Exempt methods
// run without authorization and are not wrapped.
func (e *Enforcer) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if isExempt(info.FullMethod) {
			return handler(srv, ss)
		}

		token, err := tokenFromMetadata(ss.Context())
		if err != nil {
			return grpcerror.WrapUnauthenticated(err)
		}
		// A stream interceptor cannot see the request body - it arrives later through RecvMsg - so
		// establishment authorizes the method alone, and the wrapper authorizes the namespaces the
		// subscription asks for as soon as it receives them.
		resp, err := e.authorize(ss.Context(), token, info.FullMethod, requestScope{})
		if err != nil {
			return err
		}

		// Cancelled when a re-check reaches a definitive denial, so a handler parked on the context
		// observes the teardown; cancelling on handler return also releases the stream's resources.
		ctx, cancel := context.WithCancel(ss.Context())
		defer cancel()
		now := time.Now()
		stream := &aclServerStream{
			ServerStream:   ss,
			ctx:            ctx,
			cancel:         cancel,
			enforcer:       e,
			resource:       info.FullMethod,
			token:          token,
			certHash:       util.ExtractCertificateHashFromContext(ss.Context()),
			tokenExpiresAt: tokenExpiry(resp),
			validUntil:     e.decisionValidUntil(resp, now),
		}
		return handler(srv, stream)
	}
}

// authorize authorizes a call against the AuthService, forwarding the caller's token and the TLS
// certificate hash the connection presented (empty without mutual TLS; the AuthService checks it
// against the token's binding). It fails closed: a policy denial, an invalid or expired token, and an
// unreachable AuthService all surface as a gRPC status error the caller must not proceed past. The
// call is bounded by authorizeTimeout so a hung AuthService cannot pin a handler indefinitely - for a
// unary RPC without a client deadline, and for a stream, whose context carries none.
func (e *Enforcer) authorize(
	ctx context.Context, token, resource string, scope requestScope,
) (*servicepb.AuthorizeResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	resp, err := e.client.Authorize(callCtx, &servicepb.AuthorizeRequest{
		Token:         token,
		Resource:      resource,
		TlsCertHash:   util.ExtractCertificateHashFromContext(ctx),
		Namespaces:    scope.namespaces,
		AllNamespaces: scope.all,
	})
	if err != nil {
		return nil, grpcerror.WrapWithContext(err, fmt.Sprintf("ACL check failed for [%s]", resource))
	}
	return resp, nil
}

// reAuthorize renews a stream's decision from its bound token, bounded by authorizeTimeout. Passing
// the token (rather than the identity alone) is what makes token expiry and revocation observable to
// an established stream: the AuthService resolves the token to its record before evaluating policy, so
// a deleted or lapsed record denies the stream just as a policy change does.
func (e *Enforcer) reAuthorize(
	ctx context.Context, params *reAuthorizeParams,
) (*servicepb.AuthorizeResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	resp, err := e.client.Authorize(callCtx, &servicepb.AuthorizeRequest{
		Token:         params.token,
		Resource:      params.resource,
		TlsCertHash:   params.certHash,
		Namespaces:    params.scope.namespaces,
		AllNamespaces: params.scope.all,
	})
	if err != nil {
		return nil, grpcerror.WrapWithContext(err,
			fmt.Sprintf("ACL re-check failed for [%s]", params.resource))
	}
	return resp, nil
}

// reAuthorizeParams groups a re-authorization's inputs, which exceed the argument limit.
type reAuthorizeParams struct {
	token    string
	resource string
	certHash []byte
	scope    requestScope
}

// decisionValidUntil returns how long a stream may reuse an authorization decision: the revalidation
// interval, but never past the bound token's own expiry, so an expired token cannot keep a stream
// alive even if the AuthService becomes unreachable in the meantime.
func (e *Enforcer) decisionValidUntil(resp *servicepb.AuthorizeResponse, now time.Time) time.Time {
	validUntil := now.Add(e.revalidateInterval)
	if expiry := tokenExpiry(resp); !expiry.IsZero() && expiry.Before(validUntil) {
		return expiry
	}
	return validUntil
}

// tokenExpiry reads the bound token's expiry from an authorization response, returning the zero time
// when the AuthService did not report one. A zero expiry means "no locally known bound", not "expired
// at the epoch": the revalidation interval still bounds how long such a decision is reused.
func tokenExpiry(resp *servicepb.AuthorizeResponse) time.Time {
	if expiry := resp.GetTokenExpiresAt(); expiry > 0 {
		return time.Unix(expiry, 0)
	}
	return time.Time{}
}

// isExempt reports whether a gRPC method bypasses ACL enforcement.
func isExempt(fullMethod string) bool {
	return strings.HasPrefix(fullMethod, healthServicePrefix)
}

// tokenFromMetadata extracts the authorization token from the incoming gRPC metadata.
func tokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingToken
	}
	values := md.Get(TokenMetadataKey)
	if len(values) == 0 || values[0] == "" {
		return "", ErrMissingToken
	}
	return values[0], nil
}

// aclServerStream wraps a server stream whose authorization is renewed from its bound token. Every
// receive and send first calls authorizeIfLapsed, so no message crosses the wrapper while the stream's
// decision is stale: the token is re-resolved to its record (catching expiry and revocation) and the
// resulting identity re-evaluated against the latest configuration (catching a policy change). A valid
// decision is reused until it lapses, so the common case costs no round trip - a per-message check
// against the AuthService would put its latency on the data path of every block and batch.
type aclServerStream struct {
	grpc.ServerStream
	//nolint:containedctx // the wrapped stream must return this (cancelable) context from Context().
	ctx context.Context
	// cancel tears the stream down when a re-check reaches a definitive denial.
	cancel   context.CancelFunc
	enforcer *Enforcer
	resource string
	token    string
	certHash []byte

	// mu guards the cached decision. Recv and Send run on separate goroutines for a bidirectional
	// stream, so both the check and the refresh must be serialized; the refresh is held under the lock
	// deliberately, since letting a message through while the decision is being renewed would defeat
	// the check.
	mu sync.Mutex
	// tokenExpiresAt is the hard limit: past it the stream is denied without consulting the
	// AuthService, because the bound token is known to be dead.
	tokenExpiresAt time.Time
	// validUntil is when the cached decision must be renewed.
	validUntil time.Time
	// scope is the namespace scope the stream's subscription requested, once known, so later
	// re-checks re-verify it and not merely the method.
	scope requestScope
	// denied is the terminal error once a re-check has definitively failed.
	denied error
}

func (s *aclServerStream) Context() context.Context {
	return s.ctx
}

// RecvMsg authorizes the stream, receives the message, and - when that message is the subscription
// request naming the namespaces the stream wants - authorizes those namespaces before the handler ever
// sees it. That is the only point at which a stream's requested namespaces are known.
func (s *aclServerStream) RecvMsg(m any) error {
	if err := s.authorizeIfLapsed(); err != nil {
		return err
	}
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	return s.authorizeRequestScope(m)
}

func (s *aclServerStream) SendMsg(m any) error {
	if err := s.authorizeIfLapsed(); err != nil {
		return err
	}
	return s.ServerStream.SendMsg(m)
}

// authorizeIfLapsed renews the stream's authorization when the cached decision has lapsed, and
// terminates the stream on a definitive denial. A transient failure (the AuthService is briefly
// unreachable) leaves the established stream serving and is retried on the next message - but only
// until the bound token's own expiry, which is enforced locally, so an outage can never extend a
// stream past the lifetime of the token that established it.
func (s *aclServerStream) authorizeIfLapsed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.denied != nil {
		return s.denied
	}
	now := time.Now()
	if !s.tokenExpiresAt.IsZero() && now.After(s.tokenExpiresAt) {
		s.terminate(grpcerror.WrapUnauthenticated(
			errors.Newf("the token bound to stream [%s] has expired", s.resource),
		))
		return s.denied
	}
	if now.Before(s.validUntil) {
		return nil
	}

	resp, err := s.enforcer.reAuthorize(s.ctx, s.reAuthorizeParams(s.scope))
	if err != nil {
		if grpcerror.FilterUnavailableErrorCode(err) == nil {
			// Transient (Unavailable / DeadlineExceeded): keep serving and retry on the next message.
			// The token-expiry guard above still bounds how long this can continue.
			logger.Warnf("ACL re-check for [%s] failed transiently; keeping the stream open: %v",
				s.resource, err)
			return nil
		}
		logger.Warnf("ACL re-check for [%s] denied; terminating the stream: %v", s.resource, err)
		s.terminate(err)
		return s.denied
	}

	s.validUntil = s.enforcer.decisionValidUntil(resp, now)
	return nil
}

// authorizeRequestScope authorizes the namespaces a just-received subscription request asks for, and
// remembers them so every later re-check re-verifies them too. Messages that name no namespaces (every
// message after the request, on the methods that address namespaces at all) are left alone.
func (s *aclServerStream) authorizeRequestScope(m any) error {
	scope := scopeOfRequest(m)
	if !scope.isSet() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.denied != nil {
		return s.denied
	}

	resp, err := s.enforcer.reAuthorize(s.ctx, s.reAuthorizeParams(scope))
	if err != nil {
		if grpcerror.FilterUnavailableErrorCode(err) != nil {
			logger.Warnf("ACL check of the requested namespaces for [%s] denied: %v", s.resource, err)
			s.terminate(err)
			return s.denied
		}
		// Transient: the stream keeps its establishment authorization and the scope is re-checked on
		// the next lapse, which the token-expiry bound still limits.
		logger.Warnf("ACL check of the requested namespaces for [%s] failed transiently: %v", s.resource, err)
		return nil
	}

	s.scope = scope
	s.validUntil = s.enforcer.decisionValidUntil(resp, time.Now())
	return nil
}

// reAuthorizeParams builds the inputs for a re-check of this stream against the given namespace scope.
func (s *aclServerStream) reAuthorizeParams(scope requestScope) *reAuthorizeParams {
	return &reAuthorizeParams{
		token:    s.token,
		resource: s.resource,
		certHash: s.certHash,
		scope:    scope,
	}
}

// terminate records the terminal error and cancels the stream context. The caller must hold mu.
func (s *aclServerStream) terminate(err error) {
	s.denied = err
	s.cancel()
}
