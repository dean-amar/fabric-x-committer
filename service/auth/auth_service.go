/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
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
// tokenStore that persists the token-to-identity binding, a nonceStore that issues and redeems
// single-use authentication challenges, an authenticator that turns a signed envelope into a token,
// and an authorizer that answers authorization decisions. The service holds no per-connection state,
// so any instance can serve any client's request.
type Service struct {
	servicepb.UnimplementedAuthServiceServer

	config  *Config
	metrics *perfMetrics
	// challenges throttles the two RPCs reachable without a token. Nil when the limit is disabled.
	challenges  *rate.Limiter
	ready       *channel.Ready
	healthcheck *health.Server

	configBlockProvider *configProvider
	tokens              *tokenStore
	nonces              *nonceStore
	authenticator       *authenticator
	authorizer          *authorizer
}

// NewAuthService creates a new AuthService from a configuration. It performs only in-memory wiring;
// the database pool, signing key, and background loops are opened in Run.
func NewAuthService(config *Config) *Service {
	// A zero rate means "no throttling", so the limiter is left nil rather than built: a
	// rate.NewLimiter(0, 0) permits nothing, which would reject every IssueNonce and Authenticate and
	// lock out the only two RPCs a caller can reach before it holds a token.
	var challenges *rate.Limiter
	if config.ChallengeRequestsPerSecond > 0 {
		challenges = rate.NewLimiter(
			rate.Limit(config.ChallengeRequestsPerSecond), config.ChallengeBurst,
		)
	}
	return &Service{
		config:      config,
		metrics:     newAuthServiceMetrics(),
		ready:       channel.NewReady(),
		healthcheck: serve.DefaultHealthCheckService(),
		challenges:  challenges,
	}
}

// Run opens the signing key and the database pool, builds the collaborators that need them, warms the
// token cache, signals readiness, and blocks on the background loops until the context is done.
//
// Everything that can fail lives here rather than in NewAuthService, so constructing a Service is always
// safe and a failure can be returned. It does not create its tables: they are part of the system schema
// the `init-db` command applies (statedb.SetupSystemTablesAndNamespaces), so a running service needs no
// DDL privileges.
func (s *Service) Run(ctx context.Context) error {
	logger.Infof("Starting auth service with token TTL: %s, and nonce TTL: %s",
		s.config.TokenTTL, s.config.NonceTTL)

	signer, err := newTokenSigner(s.config.SigningKeyPath)
	if err != nil {
		return err
	}

	pool, err := statedb.NewPool(ctx, s.config.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	s.tokens = &tokenStore{
		pool: pool,
	}
	s.nonces = &nonceStore{
		pool: pool,
		ttl:  s.config.NonceTTL,
	}
	s.configBlockProvider = &configProvider{
		pool:    pool,
		metrics: s.metrics,
	}
	s.authenticator = &authenticator{
		signer:                  signer,
		tokens:                  s.tokens,
		nonces:                  s.nonces,
		envelopeFreshnessWindow: s.config.EnvelopeFreshnessWindow,
		tokenTTL:                s.config.TokenTTL,
	}
	s.authorizer = &authorizer{
		signer: signer,
		tokens: s.tokens,
	}

	logger.Info("Attempting to warm the token store caching from database")
	if warmed, warmErr := s.tokens.warmCache(ctx, time.Now()); warmErr != nil {
		// A warm-up failure is non-fatal: bindings still resolve from the database on demand.
		logger.Warnf("Token store warm-up failed: %v", warmErr)
	} else {
		logger.Infof("Warmed token store with %d records", warmed)
	}
	promutil.SetGauge(s.metrics.tokenStoreSize, s.tokens.size())

	s.ready.SignalReady()
	defer s.ready.Reset()

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return s.configBlockProvider.run(gCtx, s.config.ConfigRefreshInterval)
	})
	g.Go(func() error {
		return s.sweepExpiredLoop(gCtx)
	})
	return g.Wait()
}

// sweepExpiredLoop periodically removes expired token records and updates the store-size metric.
func (s *Service) sweepExpiredLoop(ctx context.Context) error {
	ticker := time.NewTicker(s.config.TokenCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now()

			if deletedTokens, err := s.tokens.sweep(ctx, now); err != nil {
				logger.Errorf("Token sweep failed: %v", err)
			} else if deletedTokens > 0 {
				logger.Infof("Swept %d expired token records", deletedTokens)
			}

			promutil.SetGauge(s.metrics.tokenStoreSize, s.tokens.size())

			if deletedNonces, err := s.nonces.sweep(ctx, now); err != nil {
				logger.Errorf("Nonce sweep failed: %v", err)
			} else if deletedNonces > 0 {
				logger.Infof("Swept %d expired nonces", deletedNonces)
			}
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
	serve.RegisterServerMetrics(srv.StatsHandler, s.metrics.serverMetrics)
}

// IssueNonce issues a single-use nonce for the client's next Authenticate call. It needs no
// configuration bundle: a nonce carries no authority on its own, and handing one out before the
// service can authenticate lets a client have its challenge ready the moment enforcement is active.
func (s *Service) IssueNonce(
	ctx context.Context, _ *servicepb.IssueNonceRequest,
) (*servicepb.IssueNonceResponse, error) {
	if err := s.allowChallenge(); err != nil {
		return nil, grpcerror.WrapResourceExhaustedOrCancelled(ctx, err)
	}
	nonce, expiresAt, err := s.nonces.issue(ctx, time.Now())
	if err != nil {
		return nil, grpcerror.WrapInternalError(err)
	}
	return &servicepb.IssueNonceResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt.Unix(),
	}, nil
}

// Authenticate exchanges a signed envelope for a cert-bound token. The signature is verified once
// here; subsequent authorization carries the identity forward via the persisted binding.
func (s *Service) Authenticate(
	ctx context.Context, req *servicepb.AuthenticateRequest,
) (*servicepb.AuthenticateResponse, error) {
	if err := s.allowChallenge(); err != nil {
		return nil, grpcerror.WrapResourceExhaustedOrCancelled(ctx, err)
	}
	bundle, err := s.configBlockProvider.current()
	if err != nil {
		return nil, grpcerror.WrapUnavailable(err)
	}
	return s.authenticator.authenticate(ctx, req, bundle)
}

// Authorize evaluates a token against a resource policy for a resource server. A resource server
// calls it at every RPC and, for a stream, whenever its cached decision lapses, so token expiry and
// configuration changes both take effect without the stream re-presenting anything other than the
// token it was established with.
func (s *Service) Authorize(
	ctx context.Context, req *servicepb.AuthorizeRequest,
) (*servicepb.AuthorizeResponse, error) {
	bundle, err := s.configBlockProvider.current()
	if err != nil {
		return nil, grpcerror.WrapUnavailable(err)
	}
	return s.authorizer.authorize(ctx, req, bundle)
}

func (s *Service) allowChallenge() error {
	if s.challenges == nil || s.challenges.Allow() {
		return nil
	}
	return errors.New("rate limit exceeded")
}
