/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/channel"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring"
	"github.com/hyperledger/fabric-x-committer/utils/monitoring/promutil"
	"github.com/hyperledger/fabric-x-committer/utils/serve"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

var logger = flogging.MustGetLogger("auth")

// Service is the central authentication and authorization gRPC service. It composes focused
// collaborators, each with a single responsibility: a configProvider that reads the latest committed
// channel configuration from the database, a tokenSigner that mints and verifies ES256 tokens, a
// tokenStore that persists the token-to-identity binding, an authenticator that turns a signed
// envelope into a token, and an authorizer that answers authorization decisions. The service holds
// no per-connection state, so any instance can serve any client's request.
type Service struct {
	servicepb.UnimplementedAuthServiceServer
	config      *Config
	metrics     *perfMetrics
	ready       *channel.Ready
	healthcheck *health.Server

	provider      *configProvider
	store         *tokenStore
	authenticator *authenticator
	authorizer    *authorizer
}

// NewAuthService creates a new AuthService from a configuration. It performs only in-memory wiring;
// the database pool, signing key, and background loops are opened in Run.
func NewAuthService(config *Config) *Service {
	return &Service{
		config:      config,
		metrics:     newAuthServiceMetrics(),
		ready:       channel.NewReady(),
		healthcheck: serve.DefaultHealthCheckService(),
	}
}

// Run opens the signing key and database pool, wires the collaborators, warms the token store, starts
// the background configuration-refresh and token-sweep loops, and blocks until the context is done.
func (s *Service) Run(ctx context.Context) error {
	logger.Infof("Starting auth service (token TTL: %s)", s.config.TokenTTL)

	signer, err := newTokenSigner(s.config.SigningKeyPath)
	if err != nil {
		return err
	}

	pool, err := statedb.NewPool(ctx, s.config.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	s.store = newTokenStore(pool)
	if err = s.store.ensureTable(ctx); err != nil {
		return err
	}
	if warmed, warmErr := s.store.warmCache(ctx, time.Now()); warmErr != nil {
		// A warm-up failure is non-fatal: bindings still resolve from the database on demand.
		logger.Warnf("Token store warm-up failed: %v", warmErr)
	} else {
		logger.Infof("Warmed token store with %d records", warmed)
	}
	promutil.SetGauge(s.metrics.tokenStoreSize, s.store.size())

	s.provider = newConfigProvider(pool, s.metrics)
	s.authenticator = newAuthenticator(signer, s.store, s.config.EnvelopeFreshnessWindow, s.config.TokenTTL)
	s.authorizer = newAuthorizer(signer, s.store)

	s.ready.SignalReady()
	defer s.ready.Reset()

	// The loops run under an errgroup so Run blocks until both have stopped before its deferred
	// pool.Close runs - a background query can never hit a closed pool on shutdown. Each loop only
	// logs transient database errors and returns when the context ends, so the service stays up
	// (returning Unavailable for auth operations) rather than tearing itself down.
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error { s.provider.run(gCtx, s.config.ConfigRefreshInterval); return nil })
	g.Go(func() error { s.sweepExpiredLoop(gCtx); return nil })
	return g.Wait()
}

// sweepExpiredLoop periodically removes expired token records and updates the store-size metric.
func (s *Service) sweepExpiredLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.TokenCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.store.sweep(ctx, time.Now())
			if err != nil {
				logger.Errorf("Token sweep failed: %v", err)
				continue
			}
			if deleted > 0 {
				logger.Infof("Swept %d expired token records", deleted)
			}
			promutil.SetGauge(s.metrics.tokenStoreSize, s.store.size())
		}
	}
}

// WaitForReady waits until the service is ready to answer requests, or returns false if the context
// ended first.
func (s *Service) WaitForReady(ctx context.Context) bool {
	return s.ready.WaitForReady(ctx)
}

// RegisterService registers the AuthService's gRPC handlers and monitoring server.
func (s *Service) RegisterService(srv serve.Servers) {
	servicepb.RegisterAuthServiceServer(srv.GRPC, s)
	healthgrpc.RegisterHealthServer(srv.GRPC, s.healthcheck)
	monitoring.RegisterMonitoringServer(srv.HTTP, s.metrics.Provider)
	serve.RegisterConnStatHandler(srv.ConnStatsHandler, s.metrics.serverConnections)
}

// Authenticate exchanges a signed envelope for a cert-bound token. The signature is verified once
// here; subsequent authorization carries the identity forward via the persisted binding.
func (s *Service) Authenticate(
	ctx context.Context, req *servicepb.AuthenticateRequest,
) (*servicepb.AuthenticateResponse, error) {
	start := time.Now()
	bundle, err := s.provider.current()
	if err != nil {
		return nil, s.record(methodAuthenticate, start, grpcerror.WrapUnavailable(err))
	}
	resp, err := s.authenticator.authenticate(ctx, req.GetSignedEnvelope(), req.GetRequestedScope(), bundle)
	return resp, s.record(methodAuthenticate, start, err)
}

// Authorize evaluates a token against a resource policy for a resource server.
func (s *Service) Authorize(
	ctx context.Context, req *servicepb.AuthorizeRequest,
) (*servicepb.AuthorizeResponse, error) {
	start := time.Now()
	bundle, err := s.provider.current()
	if err != nil {
		return nil, s.record(methodAuthorize, start, grpcerror.WrapUnavailable(err))
	}
	resp, err := s.authorizer.authorize(ctx, req, bundle)
	return resp, s.record(methodAuthorize, start, err)
}

// ReAuthorize re-evaluates a stream session's bound identity against the latest resource policy.
func (s *Service) ReAuthorize(
	_ context.Context, req *servicepb.ReAuthorizeRequest,
) (*servicepb.AuthorizeResponse, error) {
	start := time.Now()
	bundle, err := s.provider.current()
	if err != nil {
		return nil, s.record(methodReAuthorize, start, grpcerror.WrapUnavailable(err))
	}
	resp, err := s.authorizer.reAuthorize(req, bundle)
	return resp, s.record(methodReAuthorize, start, err)
}

// record observes the request latency and increments the request counter with the outcome derived
// from err's gRPC code. It returns err unchanged so handlers can `return s.record(...)`.
func (s *Service) record(method string, start time.Time, err error) error {
	promutil.Observe(s.metrics.requestsLatency.WithLabelValues(method), time.Since(start))
	s.metrics.requests.WithLabelValues(method, outcomeForError(err)).Inc()
	return err
}

// outcomeForError maps a handler's returned error to a metrics outcome label. A nil error is the only
// success; any non-nil error - including a bare error that carries no gRPC status - is an error
// outcome, never "ok".
func outcomeForError(err error) string {
	if err == nil {
		return outcomeOK
	}
	switch grpcerror.GetCode(err) {
	case codes.Unauthenticated:
		return outcomeUnauthenticated
	case codes.PermissionDenied:
		return outcomeDenied
	case codes.Unavailable:
		return outcomeUnavailable
	default:
		return outcomeError
	}
}

// newTokenID generates a random, opaque token id (the jti claim and the store's row key).
func newTokenID() (string, error) {
	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate token id")
	}
	return id.String(), nil
}
