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

var logger = flogging.MustGetLogger("authentication-service")

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
	nonces        *nonceStore
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
	s.nonces = newNonceStore(pool, s.config.NonceTTL)
	if err = s.nonces.ensureTable(ctx); err != nil {
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
	s.authenticator = newAuthenticator(&authenticatorConfig{
		signer:          signer,
		store:           s.store,
		nonces:          s.nonces,
		freshnessWindow: s.config.EnvelopeFreshnessWindow,
		tokenTTL:        s.config.TokenTTL,
	})
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
			now := time.Now()
			deleted, err := s.store.sweep(ctx, now)
			if err != nil {
				logger.Errorf("Token sweep failed: %v", err)
				continue
			}
			if deleted > 0 {
				logger.Infof("Swept %d expired token records", deleted)
			}
			promutil.SetGauge(s.metrics.tokenStoreSize, s.store.size())

			// Unredeemed nonces accumulate whenever a client asks for one and never authenticates,
			// so they are swept on the same tick as tokens.
			if staleNonces, nonceErr := s.nonces.sweep(ctx, now); nonceErr != nil {
				logger.Errorf("Nonce sweep failed: %v", nonceErr)
			} else if staleNonces > 0 {
				logger.Infof("Swept %d expired nonces", staleNonces)
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
	nonce, expiresAt, err := s.nonces.issue(ctx, time.Now())
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, grpcerror.WrapInternalError(err)
	}
	return &servicepb.IssueNonceResponse{Nonce: nonce, ExpiresAt: expiresAt.Unix()}, nil
}

// Authenticate exchanges a signed envelope for a cert-bound token. The signature is verified once
// here; subsequent authorization carries the identity forward via the persisted binding.
func (s *Service) Authenticate(
	ctx context.Context, req *servicepb.AuthenticateRequest,
) (*servicepb.AuthenticateResponse, error) {
	bundle, err := s.provider.current()
	if err != nil {
		return nil, grpcerror.WrapUnavailable(err)
	}
	return s.authenticator.authenticate(ctx, req, bundle)
}

// Authorize evaluates a token against a resource policy for a resource server. A resource server
// calls it at every RPC and, for a stream, whenever its cached decision lapses, so token expiry,
// revocation, and configuration changes all take effect without the stream re-presenting anything
// other than the token it was established with.
func (s *Service) Authorize(
	ctx context.Context, req *servicepb.AuthorizeRequest,
) (*servicepb.AuthorizeResponse, error) {
	bundle, err := s.provider.current()
	if err != nil {
		return nil, grpcerror.WrapUnavailable(err)
	}
	return s.authorizer.authorize(ctx, req, bundle)
}

// newTokenID generates a random, opaque token id (the jti claim and the store's row key).
func newTokenID() (string, error) {
	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate token id")
	}
	return id.String(), nil
}
