/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-x-common/common/util"
	"google.golang.org/grpc"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

var logger = flogging.MustGetLogger("acl")

const (
	// TokenMetadataKey is the gRPC metadata key carrying the client's cert-bound opaque token.
	TokenMetadataKey = "authorization"

	// Defaults for the unset Config durations.
	defaultStreamReAuthorizeInterval = time.Minute
	defaultAuthorizeTimeout          = 10 * time.Second
)

var (
	// ErrMissingToken is returned when a request carries no authorization token.
	ErrMissingToken = errors.New("missing authorization token")

	// healthServicePrefix is exempt from enforcement: probes carry no token, and liveness, readiness and
	// load-balancer checks must keep working once ACL is on.
	healthServicePrefix = "/" + healthgrpc.Health_ServiceDesc.ServiceName + "/"
)

// Enforcer authorizes a resource server's RPCs against the AuthService, forwarding the caller's token and
// the certificate hash seen on the connection. It never inspects the request body.
type Enforcer struct {
	client servicepb.AuthServiceClient
	conn   *grpc.ClientConn
	config Config
}

// NewEnforcer dials the AuthService, or returns nil when the auth section is absent. A service creates it in
// Run before signaling ready, and registers it with its gRPC server (serve.RegisterACLEnforcer), where a nil
// enforcer leaves the server unenforced. Close is nil-safe, so a service closes the result either way.
func NewEnforcer(config *Config) (*Enforcer, error) {
	if config == nil {
		return nil, nil //nolint:nilnil // a nil enforcer is the deliberate result when ACL is not configured.
	}
	// An empty list would dial nothing and fail every RPC; refusing to start makes the misconfiguration loud.
	if len(config.Endpoints) == 0 {
		return nil, errors.New("the auth client lists no auth service endpoints")
	}
	conn, err := connection.NewLoadBalancedConnection(&config.MultiClientConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to the auth service")
	}
	logger.Infof("ACL enforcement enabled via auth service at %s",
		connection.AddressString(config.Endpoints...))

	e := &Enforcer{
		client: servicepb.NewAuthServiceClient(conn),
		conn:   conn,
		config: *config,
	}
	// Defaults are set here, not with `default` tags: viper registers a tag's default even when the auth
	// section is absent, which would decode a non-nil Auth for every service.
	if e.config.StreamReAuthorizeInterval <= 0 {
		e.config.StreamReAuthorizeInterval = defaultStreamReAuthorizeInterval
	}
	if e.config.AuthorizeTimeout <= 0 {
		e.config.AuthorizeTimeout = defaultAuthorizeTimeout
	}
	return e, nil
}

// Close releases the connection the enforcer owns.
func (e *Enforcer) Close() {
	if e == nil {
		return
	}
	connection.CloseConnectionsLog(e.conn)
}

// UnaryInterceptor authorizes every non-exempt unary RPC before its handler runs.
func (e *Enforcer) UnaryInterceptor(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
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

// StreamInterceptor authorizes a non-exempt stream at establishment and binds its token, so the decision
// can be renewed for as long as the stream lives.
func (e *Enforcer) StreamInterceptor(
	srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
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

	// Canceled when the stream's authorization ends, so a handler waiting on the context observes it;
	// cancelling on handler return also releases the stream's resources.
	ctx, cancel := context.WithCancel(ss.Context())
	defer cancel()
	// A reported expiry of zero means the AuthService knows of no bound, not "expired at the epoch":
	// leaving it as the zero time is what checkBoundTokenLocked reads as "no local bound".
	var tokenExpiresAt time.Time
	if expiry := resp.GetTokenExpiresAt(); expiry > 0 {
		tokenExpiresAt = time.Unix(expiry, 0)
	}
	return handler(srv, &authorizedStream{
		ServerStream:    ss,
		ctx:             ctx,
		cancel:          cancel,
		enforcer:        e,
		resource:        info.FullMethod,
		token:           token,
		tokenExpiresAt:  tokenExpiresAt,
		nextAuthorizeAt: time.Now().Add(e.config.StreamReAuthorizeInterval),
	})
}

// authorize fails closed: a policy denial, an invalid token and an unreachable AuthService all surface as
// a gRPC status error. Bounded by AuthorizeTimeout, since neither a unary nor a stream context carries one.
func (e *Enforcer) authorize(
	ctx context.Context, token, resource string,
) (*servicepb.AuthorizeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, e.config.AuthorizeTimeout)
	defer cancel()

	resp, err := e.client.Authorize(ctx, &servicepb.AuthorizeRequest{
		Token:       token,
		Resource:    resource,
		TlsCertHash: util.ExtractCertificateHashFromContext(ctx),
	})
	if err != nil {
		// Not logged: a denial is the caller's fault, and logging each one would let any client flood the
		// server's log with bad tokens.
		st := status.Convert(err)
		return nil, status.Errorf(st.Code(), "ACL check failed for [%s]: %s", resource, st.Message())
	}
	return resp, nil
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
