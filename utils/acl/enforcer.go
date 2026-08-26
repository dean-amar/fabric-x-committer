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
	"sync/atomic"
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
		if _, err := e.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamInterceptor authorizes a stream at establishment, binds the returned identity to it, and runs
// a background loop that re-authorizes that identity every revalidation interval. Exempt methods run
// without authorization and are not wrapped.
func (e *Enforcer) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if isExempt(info.FullMethod) {
			return handler(srv, ss)
		}

		identity, err := e.authorize(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}

		// The revalidation loop cancels this context to tear the stream down on a definitive denial;
		// cancelling it when the handler returns also stops the loop.
		ctx, cancel := context.WithCancel(ss.Context())
		defer cancel()
		stream := &aclServerStream{
			ServerStream: ss,
			ctx:          ctx,
			enforcer:     e,
			resource:     info.FullMethod,
			identity:     identity,
		}
		go stream.revalidate(cancel)
		return handler(srv, stream)
	}
}

// authorize authorizes an incoming call at establishment: it forwards the caller's token and TLS
// certificate hash to the AuthService and returns the identity the AuthService bound to the token,
// so a stream can bind it for later re-authorization. It fails closed: a policy denial, an invalid
// token, and an unreachable AuthService all surface as a gRPC status error the caller must not
// proceed past. The certificate hash is whatever the connection presented (empty without mutual
// TLS); the AuthService checks it against the token's binding. The AuthService call is bounded by
// authorizeTimeout so a hung AuthService cannot pin the caller's handler indefinitely - for a unary
// RPC without a client deadline, and for stream establishment (the stream context has none).
func (e *Enforcer) authorize(ctx context.Context, resource string) ([]byte, error) {
	token, err := tokenFromMetadata(ctx)
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(err)
	}

	callCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	resp, err := e.client.Authorize(callCtx, &servicepb.AuthorizeRequest{
		Token:       token,
		Resource:    resource,
		TlsCertHash: util.ExtractCertificateHashFromContext(ctx),
	})
	if err != nil {
		return nil, grpcerror.WrapWithContext(err, fmt.Sprintf("ACL check failed for [%s]", resource))
	}
	return resp.GetIdentity(), nil
}

// reAuthorize re-evaluates a stream's bound identity against the latest resource policy, bounded by
// authorizeTimeout so a hung AuthService cannot block the revalidation loop.
func (e *Enforcer) reAuthorize(ctx context.Context, identity []byte, resource string) error {
	callCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	_, err := e.client.ReAuthorize(callCtx, &servicepb.ReAuthorizeRequest{Identity: identity, Resource: resource})
	if err != nil {
		return grpcerror.WrapWithContext(err, fmt.Sprintf("ACL re-check failed for [%s]", resource))
	}
	return nil
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

// denial records the terminal error that ends a stream, published once by the revalidation loop and
// observed by RecvMsg/SendMsg without a lock.
type denial struct {
	err error
}

// aclServerStream wraps a server stream whose bound identity is re-authorized on a background timer.
// On a definitive denial the loop records the terminal error and cancels the wrapped context, so the
// next receive or send returns that error and a handler that selects on its context observes the
// cancellation. Data reaches the client only through SendMsg, which checks the denial before every
// send, so a revoked client receives nothing further even if its handler is parked in RecvMsg; the
// connection itself is bounded by the server's keep-alive max-connection-age.
type aclServerStream struct {
	grpc.ServerStream
	//nolint:containedctx // the wrapped stream must return this (cancelable) context from Context().
	ctx      context.Context
	enforcer *Enforcer
	resource string
	identity []byte
	denied   atomic.Pointer[denial]
}

func (s *aclServerStream) Context() context.Context {
	return s.ctx
}

func (s *aclServerStream) RecvMsg(m any) error {
	if d := s.denied.Load(); d != nil {
		return d.err
	}
	return s.ServerStream.RecvMsg(m)
}

func (s *aclServerStream) SendMsg(m any) error {
	if d := s.denied.Load(); d != nil {
		return d.err
	}
	return s.ServerStream.SendMsg(m)
}

// revalidate re-authorizes the bound identity every revalidation interval until the stream ends. A
// transient error (the AuthService is briefly unreachable) is tolerated: the established stream keeps
// serving and the check is retried next tick, mirroring the client's cached-token fallback. Only a
// definitive denial - a policy or identity rejection - terminates the stream: the loop records the
// error (so the next receive/send returns it) and cancels the stream context.
func (s *aclServerStream) revalidate(cancel context.CancelFunc) {
	ticker := time.NewTicker(s.enforcer.revalidateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			err := s.enforcer.reAuthorize(s.ctx, s.identity, s.resource)
			if err == nil {
				continue
			}
			if grpcerror.FilterUnavailableErrorCode(err) == nil {
				// Transient (Unavailable / DeadlineExceeded): keep the stream, retry next tick.
				logger.Warnf("ACL re-check for [%s] failed transiently; keeping the stream open: %v",
					s.resource, err)
				continue
			}
			logger.Warnf("ACL re-check for [%s] denied; terminating the stream: %v", s.resource, err)
			s.denied.Store(&denial{err: err})
			cancel()
			return
		}
	}
}
