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
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-x-common/common/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
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

	// authorizeTimeout bounds an Authorize call to the AuthService. Both stream establishment and
	// re-checks use a stream context that carries no request deadline, so without this a hung
	// AuthService could block indefinitely.
	authorizeTimeout = 10 * time.Second

	// defaultRevalidateInterval is how often an open stream re-authorizes when the caller does not
	// configure an interval.
	defaultRevalidateInterval = time.Minute

	// transientRetryInterval paces re-checks after the AuthService was briefly unreachable, so an
	// outage costs one attempt per interval rather than one per message.
	transientRetryInterval = 5 * time.Second
)

// ErrMissingToken is returned when a request carries no authorization token.
var ErrMissingToken = errors.New("missing authorization token")

// Enforcer authorizes a resource server's incoming RPCs against the AuthService. It forwards the
// caller's token and the TLS certificate hash observed on the connection, and never inspects the
// request body; a stream binds the token so its decision can be renewed for as long as it lives.
type Enforcer struct {
	// Client is the AuthService every decision is delegated to.
	Client servicepb.AuthServiceClient
	// RevalidateInterval is how often an open stream re-authorizes its bound token against the latest
	// policy. Zero means defaultRevalidateInterval.
	RevalidateInterval time.Duration

	// conn is set only by NewEnforcer, which dials and therefore owns the connection. It stays nil for
	// an Enforcer built from a struct literal over an existing client, whose Close is then a no-op.
	conn *grpc.ClientConn
}

// NewEnforcer connects to the AuthService and returns an Enforcer that owns the connection, so a
// service can build one in its constructor - before the gRPC server exists - and release it with Close.
//
// A nil config means ACL is not configured, and yields a nil Enforcer and no error. Close is nil-safe to
// match, so a service needs no conditional on either side.
func NewEnforcer(config *ClientConfig) (*Enforcer, error) {
	if config == nil {
		return nil, nil //nolint:nilnil // no ACL section configured is a result, not a failure.
	}

	conn, err := connection.NewSingleConnection(config.Server)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to the auth service")
	}
	logger.Infof("ACL enforcement enabled via auth service at %s", config.Server.Endpoint.Address())
	return &Enforcer{
		Client:             servicepb.NewAuthServiceClient(conn),
		RevalidateInterval: config.StreamRevalidateInterval,
		conn:               conn,
	}, nil
}

// Close releases the connection the enforcer owns. It is safe on a nil Enforcer, so a service can
// defer it without first checking whether ACL is configured.
func (e *Enforcer) Close() {
	if e == nil || e.conn == nil {
		return
	}
	connection.CloseConnectionsLog(e.conn)
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
		if _, err = e.authorize(ctx, token, info.FullMethod); err != nil {
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
		resp, err := e.authorize(ss.Context(), token, info.FullMethod)
		if err != nil {
			return err
		}

		// Cancelled when a re-check reaches a definitive denial, so a handler parked on the context
		// observes the teardown; cancelling on handler return also releases the stream's resources.
		ctx, cancel := context.WithCancel(ss.Context())
		defer cancel()
		now := time.Now()
		stream := &authorizedStream{
			ServerStream:   ss,
			ctx:            ctx,
			cancel:         cancel,
			enforcer:       e,
			resource:       info.FullMethod,
			token:          token,
			tokenExpiresAt: tokenExpiry(resp),
			validUntil:     e.decisionValidUntil(resp, now),
		}
		return handler(srv, stream)
	}
}

// authorize authorizes a call against the AuthService. It fails closed: a policy denial, an invalid
// token, and an unreachable AuthService all surface as a gRPC status error. The call is bounded by
// authorizeTimeout, since neither a unary RPC without a deadline nor a stream context carries one.
func (e *Enforcer) authorize(
	ctx context.Context, token, resource string,
) (*servicepb.AuthorizeResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, authorizeTimeout)
	defer cancel()
	resp, err := e.Client.Authorize(callCtx, &servicepb.AuthorizeRequest{
		Token:       token,
		Resource:    resource,
		TlsCertHash: util.ExtractCertificateHashFromContext(ctx),
	})
	if err != nil {
		return nil, grpcerror.WrapWithContext(err, fmt.Sprintf("ACL check failed for [%s]", resource))
	}
	return resp, nil
}

// decisionValidUntil returns how long a stream may reuse an authorization decision: the revalidation
// interval, but never past the bound token's own expiry, so an expired token cannot keep a stream
// alive even if the AuthService becomes unreachable in the meantime.
func (e *Enforcer) decisionValidUntil(resp *servicepb.AuthorizeResponse, now time.Time) time.Time {
	interval := e.RevalidateInterval
	if interval <= 0 {
		interval = defaultRevalidateInterval
	}

	validUntil := now.Add(interval)
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
