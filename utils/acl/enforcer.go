/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

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

	// healthServicePrefix is exempt from enforcement: probes carry no token, and liveness, readiness and
	// load-balancer checks must keep working once ACL is on.
	healthServicePrefix = "/grpc.health.v1.Health/"

	// authorizeTimeout bounds an Authorize call: a stream context carries no request deadline, so a hung
	// AuthService would otherwise block indefinitely.
	authorizeTimeout = 10 * time.Second

	// transientRetryInterval paces re-checks after the AuthService was briefly unreachable, so an
	// outage costs one attempt per interval rather than one per message.
	transientRetryInterval = 5 * time.Second
)

// ErrMissingToken is returned when a request carries no authorization token.
var ErrMissingToken = errors.New("missing authorization token")

// Enforcer authorizes a resource server's RPCs against the AuthService, forwarding the caller's token and
// the certificate hash seen on the connection. It never inspects the request body.
type Enforcer struct {
	// Client is the AuthService every decision is delegated to.
	Client servicepb.AuthServiceClient
	// ReAuthorizeInterval is how often an open stream re-authorizes its bound token against the latest
	// policy, which is what makes a configuration change observable to it. Zero means
	// defaultReAuthorizeInterval. Set it high to rely on the token's own lifetime instead.
	ReAuthorizeInterval time.Duration

	// conn is set only by NewEnforcer, which dials and therefore owns the connection. It stays nil for
	// an Enforcer built from a struct literal over an existing client, whose Close is then a no-op.
	conn *grpc.ClientConn
}

// NewEnforcer dials the AuthService and owns the connection, so a service can build one in its
// constructor. A nil config means ACL is unconfigured: nil Enforcer, no error, and Close is nil-safe.
func NewEnforcer(config *Client) (*Enforcer, error) {
	if config == nil {
		return nil, nil //nolint:nilnil // no ACL section configured is a result, not a failure.
	}

	conn, err := connection.NewSingleConnection(config.Config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to the auth service")
	}
	logger.Infof("ACL enforcement enabled via auth service at %s", config.Config.Endpoint.Address())
	return &Enforcer{
		Client:              servicepb.NewAuthServiceClient(conn),
		ReAuthorizeInterval: config.StreamReAuthorizeInterval,
		conn:                conn,
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

// StreamInterceptor authorizes a stream at establishment and binds its token, so the decision can be
// renewed for as long as the stream lives. Exempt methods are not wrapped.
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
			ServerStream:    ss,
			ctx:             ctx,
			cancel:          cancel,
			enforcer:        e,
			resource:        info.FullMethod,
			token:           token,
			tokenExpiresAt:  tokenExpiry(resp),
			nextAuthorizeAt: now.Add(e.ReAuthorizeInterval),
		}
		return handler(srv, stream)
	}
}

// authorize fails closed: a policy denial, an invalid token and an unreachable AuthService all surface as
// a gRPC status error. Bounded by authorizeTimeout, since neither a unary nor a stream context carries one.
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

// tokenExpiry reads the bound token's expiry, or the zero time when none was reported. Zero means "no
// locally known bound", not "expired at the epoch": re-authorization still bounds reuse.
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
