/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitoring

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

const (
	httpsScheme    = "https://"
	httpScheme     = "http://"
	metricsSubPath = "/metrics"
	pprofSubPath   = "/debug/pprof/"

	// Default retry configuration for Prometheus server startup
	defaultPrometheusRetryInitialInterval = 500 * time.Millisecond
	defaultPrometheusRetryMaxInterval     = 5 * time.Second
	defaultPrometheusRetryMaxElapsedTime  = 30 * time.Second
	defaultPrometheusRetryMultiplier      = 2.0
)

// Config holds the configuration for the monitoring provider.
type Config struct {
	Server *connection.ServerConfig `mapstructure:"server" yaml:"server"`
	Retry  *connection.RetryProfile `mapstructure:"retry" yaml:"retry"`
}

// Provider is a prometheus metrics provider.
type Provider struct {
	registry *prometheus.Registry
	url      string
}

var logger = flogging.MustGetLogger("monitoring")

// NewProvider creates a new prometheus metrics provider.
func NewProvider() *Provider {
	return &Provider{registry: prometheus.NewRegistry()}
}

// StartPrometheusServer starts a prometheus server with a default retry mechanism.
// It also starts the given monitoring methods. Their context will cancel once the server is cancelled.
// This method returns once the server is shutdown and all monitoring methods returns.
// The server will retry startup with exponential backoff for up to 30 seconds by default.
// Deprecated: Use StartPrometheusServerWithConfig instead for configurable retry behavior.
func (p *Provider) StartPrometheusServer(
	ctx context.Context, serverConfig *connection.ServerConfig, monitor ...func(context.Context),
) error {
	// Use default retry profile for Prometheus server startup
	defaultRetry := &connection.RetryProfile{
		InitialInterval: defaultPrometheusRetryInitialInterval,
		MaxInterval:     defaultPrometheusRetryMaxInterval,
		MaxElapsedTime:  defaultPrometheusRetryMaxElapsedTime,
		Multiplier:      defaultPrometheusRetryMultiplier,
	}
	return p.StartPrometheusServerWithRetry(ctx, serverConfig, defaultRetry, monitor...)
}

// StartPrometheusServerWithConfig starts a prometheus server using the provided configuration.
// It also starts the given monitoring methods. Their context will cancel once the server is cancelled.
// This method returns once the server is shutdown and all monitoring methods returns.
// If config.Retry is nil, a default retry profile will be used.
func (p *Provider) StartPrometheusServerWithConfig(
	ctx context.Context, config *Config, monitor ...func(context.Context),
) error {
	if config == nil || config.Server == nil {
		return errors.New("monitoring config and server config are required")
	}

	retry := config.Retry
	if retry == nil {
		// Use default retry profile if not specified
		retry = &connection.RetryProfile{
			InitialInterval: defaultPrometheusRetryInitialInterval,
			MaxInterval:     defaultPrometheusRetryMaxInterval,
			MaxElapsedTime:  defaultPrometheusRetryMaxElapsedTime,
			Multiplier:      defaultPrometheusRetryMultiplier,
		}
	}

	return p.StartPrometheusServerWithRetry(ctx, config.Server, retry, monitor...)
}

// StartPrometheusServerWithRetry starts a prometheus server with configurable retry mechanism.
// It also starts the given monitoring methods. Their context will cancel once the server is cancelled.
// This method returns once the server is shutdown and all monitoring methods returns.
// If retryProfile is nil, the server will attempt to start only once without retries.
func (p *Provider) StartPrometheusServerWithRetry(
	ctx context.Context, serverConfig *connection.ServerConfig, retryProfile *connection.RetryProfile, monitor ...func(context.Context),
) error {
	var serverStartErr error

	startOperation := func() error {
		serverStartErr = p.startPrometheusServerOnce(ctx, serverConfig, monitor...)
		if serverStartErr != nil {
			logger.Warnf("Failed to start prometheus server: %v", serverStartErr)
			return serverStartErr
		}
		return nil
	}

	// If no retry profile is provided, attempt to start the server once
	if retryProfile == nil {
		return startOperation()
	}

	// Use retry mechanism with exponential backoff
	b := retryProfile.NewBackoff()
	retryErr := backoff.Retry(startOperation, backoff.WithContext(b, ctx))
	if retryErr != nil {
		return errors.Wrap(serverStartErr, "failed to start prometheus server after retries")
	}

	return nil
}

// startPrometheusServerOnce attempts to start the prometheus server once without retries.
func (p *Provider) startPrometheusServerOnce(
	ctx context.Context, serverConfig *connection.ServerConfig, monitor ...func(context.Context),
) error {
	logger.Debugf("Creating prometheus server with secure mode: %v", serverConfig.TLS.Mode)
	// Generate TLS configuration from the server config.
	serverMaterials, err := connection.NewTLSMaterials(serverConfig.TLS)
	if err != nil {
		return errors.Wrap(err, "failed to create TLS materials for prometheus server")
	}
	serverTLSConfig, err := serverMaterials.CreateServerTLSConfig()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle(
		metricsSubPath,
		promhttp.HandlerFor(
			p.Registry(),
			promhttp.HandlerOpts{
				Registry: p.Registry(),
			},
		),
	)

	// Register pprof handlers for profiling.
	// Note: We must explicitly register these handlers because we're using a custom ServeMux.
	// The net/http/pprof package's init() function only registers handlers on http.DefaultServeMux,
	// which we're not using. Simply importing the package is insufficient for custom muxes.
	//
	// The Index handler dynamically serves all runtime profiles (heap, goroutine, allocs, block,
	// mutex, threadcreate, etc.) without requiring explicit registration. Only special handlers
	// (cmdline, profile, symbol, trace) need to be registered separately.
	mux.HandleFunc(pprofSubPath, pprof.Index)
	mux.HandleFunc(pprofSubPath+"cmdline", pprof.Cmdline)
	mux.HandleFunc(pprofSubPath+"profile", pprof.Profile)
	mux.HandleFunc(pprofSubPath+"symbol", pprof.Symbol)
	mux.HandleFunc(pprofSubPath+"trace", pprof.Trace)
	server := &http.Server{
		ReadTimeout: 30 * time.Second,
		Handler:     mux,
		TLSConfig:   serverTLSConfig,
	}

	l, err := serverConfig.Listener(ctx)
	if err != nil {
		return err
	}
	defer connection.CloseConnectionsLog(l)

	if serverTLSConfig != nil {
		l = tls.NewListener(l, serverTLSConfig)
	}

	p.url, err = MakeMetricsURL(l.Addr().String(), serverTLSConfig)
	if err != nil {
		return err
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		logger.Infof("Prometheus serving on URL: %s", p.url)
		defer logger.Info("Prometheus stopped serving")
		return server.Serve(l)
	})

	// The following ensures the method does not return before all monitor methods return.
	for _, m := range monitor {
		g.Go(func() error {
			m(gCtx)
			return nil
		})
	}

	// The following ensures the method does not return before the close procedure is complete.
	stopAfter := context.AfterFunc(ctx, func() {
		g.Go(func() error {
			if errClose := server.Close(); err != nil {
				return errors.Wrap(errClose, "failed to close prometheus server")
			}
			return nil
		})
	})
	defer stopAfter()

	if err = g.Wait(); !errors.Is(err, http.ErrServerClosed) {
		return errors.Wrap(err, "prometheus server stopped with an error")
	}
	return nil
}

// URL returns the prometheus server URL.
func (p *Provider) URL() string {
	return p.url
}

// NewCounter creates a new prometheus counter.
func (p *Provider) NewCounter(opts prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(opts)
	p.registry.MustRegister(c)
	return c
}

// NewCounterVec creates a new prometheus counter vector.
func (p *Provider) NewCounterVec(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	cv := prometheus.NewCounterVec(opts, labels)
	p.registry.MustRegister(cv)
	return cv
}

// NewGauge creates a new prometheus gauge.
func (p *Provider) NewGauge(opts prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(opts)
	p.registry.MustRegister(g)
	return g
}

// NewGaugeVec creates a new prometheus gauge vector.
func (p *Provider) NewGaugeVec(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	gv := prometheus.NewGaugeVec(opts, labels)
	p.registry.MustRegister(gv)
	return gv
}

// NewHistogram creates a new prometheus histogram.
func (p *Provider) NewHistogram(opts prometheus.HistogramOpts) prometheus.Histogram {
	h := prometheus.NewHistogram(opts)
	p.registry.MustRegister(h)
	return h
}

// NewHistogramVec creates a new prometheus histogram vector.
func (p *Provider) NewHistogramVec(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	hv := prometheus.NewHistogramVec(opts, labels)
	p.registry.MustRegister(hv)
	return hv
}

// NewThroughputCounter creates a new prometheus throughput counter.
func (p *Provider) NewThroughputCounter(
	component, subComponent string,
	direction ThroughputDirection,
) prometheus.Counter {
	return p.NewCounter(prometheus.CounterOpts{
		Namespace: component,
		Subsystem: subComponent,
		Name:      fmt.Sprintf("%s_throughput", direction),
		Help:      "Incoming requests/Outgoing responses for a component",
	})
}

// NewConnectionMetrics supports common connection metrics.
func (p *Provider) NewConnectionMetrics(opts ConnectionMetricsOpts) *ConnectionMetrics {
	subsystem := fmt.Sprintf("grpc_%s", opts.RemoteNamespace)
	return &ConnectionMetrics{
		Status: p.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: opts.Namespace,
			Subsystem: subsystem,
			Name:      "connection_status",
			Help: fmt.Sprintf(
				"Connection status to %s service by grpc target (1 = connected, 0 = disconnected).",
				opts.RemoteNamespace,
			),
		}, []string{"grpc_target"}),
		FailureTotal: p.NewCounterVec(prometheus.CounterOpts{
			Namespace: opts.Namespace,
			Subsystem: subsystem,
			Name:      "connection_failure_total",
			Help: fmt.Sprintf("Total number of connection failures to %s service.", opts.RemoteNamespace) +
				"Short-lived failures may not always be captured.",
		}, []string{"grpc_target"}),
	}
}

// Registry returns the prometheus registry.
func (p *Provider) Registry() *prometheus.Registry {
	return p.registry
}

// MakeMetricsURL construct the Prometheus metrics URL.
// based on the secure level, we set the url scheme to http or https.
func MakeMetricsURL(address string, tlsConf *tls.Config) (string, error) {
	scheme := httpScheme
	if tlsConf != nil {
		scheme = httpsScheme
	}
	ret, err := url.JoinPath(scheme, address, metricsSubPath)
	return ret, errors.Wrap(err, "failed to make prometheus URL")
}
