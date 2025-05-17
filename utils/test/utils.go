/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/channel"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection/tlsgen"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

type (
	// GrpcServers holds the server instances and their respective configurations.
	GrpcServers struct {
		Servers []*grpc.Server
		Configs []*connection.ServerConfig
	}
)

// FailHandler registers a [gomega] fail handler.
func FailHandler(t *testing.T) {
	t.Helper()
	gomega.RegisterFailHandler(func(message string, _ ...int) {
		t.Helper()
		t.Errorf("received error message: %s", message)
		t.FailNow()
	})
}

// ServerToClientConfig is used to create client configuration from existing server(s).
func ServerToClientConfig(servers ...*connection.ServerConfig) *connection.ClientConfig {
	endpoints := make([]*connection.Endpoint, len(servers))
	for i, server := range servers {
		endpoints[i] = &server.Endpoint
	}
	return &connection.ClientConfig{
		Endpoints: endpoints,
	}
}

// RunGrpcServerForTest starts a GRPC server using a register method.
// It handles the cleanup of the GRPC server at the end of a test, and ensure the test is ended
// only when the GRPC server is down.
// It also updates the server config endpoint port to the actual port if the configuration
// did not specify a port.
// The method asserts that the GRPC server did not end with failure.
func RunGrpcServerForTest(
	ctx context.Context, t *testing.T, serverConfig *connection.ServerConfig, register ...func(server *grpc.Server),
) *grpc.Server {
	t.Helper()
	listener, err := serverConfig.Listener()
	require.NoError(t, err)
	server, err := serverConfig.GrpcServer()
	require.NoError(t, err)

	// We register a health check service for all servers in tests to allow waiting for readiness.
	healthcheck := health.NewServer()
	healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	healthgrpc.RegisterHealthServer(server, healthcheck)

	// We support instantiating a server with multiple APIs for testing.
	// We also support no APIs (only the health check API).
	for _, r := range register {
		r(server)
	}

	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	t.Cleanup(server.Stop)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// We use assert to prevent panicking for cleanup errors.
		assert.NoError(t, server.Serve(listener))
	}()

	_ = context.AfterFunc(ctx, func() {
		server.Stop()
	})
	return server
}

// StartGrpcServersForTest starts multiple GRPC servers with a default configuration.
func StartGrpcServersForTest(
	ctx context.Context,
	t *testing.T,
	numService int,
	register ...func(*grpc.Server, int),
) *GrpcServers {
	t.Helper()
	sc := make([]*connection.ServerConfig, numService)
	for i := range sc {
		sc[i] = connection.NewLocalHostServer()
	}
	return StartGrpcServersWithConfigForTest(ctx, t, sc, register...)
}

// StartGrpcServersWithConfigForTest starts multiple GRPC servers with given configurations.
func StartGrpcServersWithConfigForTest(
	ctx context.Context, t *testing.T, sc []*connection.ServerConfig, register ...func(*grpc.Server, int),
) *GrpcServers {
	t.Helper()
	grpcServers := make([]*grpc.Server, len(sc))
	for i, s := range sc {
		grpcServers[i] = RunGrpcServerForTest(ctx, t, s, func(server *grpc.Server) {
			for _, r := range register {
				r(server, i)
			}
		})
	}
	return &GrpcServers{
		Servers: grpcServers,
		Configs: sc,
	}
}

// RunServiceForTest runs a service using the given service method, and waits for it to be ready
// given the waitFunc method.
// It handles the cleanup of the service at the end of a test, and ensure the test is ended
// only when the service return.
// The method asserts that the service did not end with failure.
// Returns a ready flag that indicate that the service is done.
func RunServiceForTest(
	ctx context.Context,
	tb testing.TB,
	service func(ctx context.Context) error,
	waitFunc func(ctx context.Context) bool,
) *channel.Ready {
	tb.Helper()
	ready := channel.NewReady()
	var wg sync.WaitGroup
	// NOTE: we should cancel the context before waiting for the completion. Therefore, the
	//       order of cleanup matters, which is last added first called.
	tb.Cleanup(wg.Wait)
	dCtx, cancel := context.WithCancel(ctx)
	tb.Cleanup(cancel)
	wg.Add(1)

	// We extract caller information to ensure we have sufficient information for debugging.
	pc, file, no, ok := runtime.Caller(1)
	require.True(tb, ok)
	go func() {
		defer wg.Done()
		defer ready.SignalReady()
		// We use assert to prevent panicking for cleanup errors.
		assert.NoErrorf(tb, service(dCtx), "called from %s:%d\n\t%s", file, no, runtime.FuncForPC(pc).Name())
	}()

	if waitFunc == nil {
		return ready
	}

	initCtx, initCancel := context.WithTimeout(dCtx, 2*time.Minute)
	tb.Cleanup(initCancel)
	require.True(tb, waitFunc(initCtx), "service is not ready")
	return ready
}

// RunServiceAndGrpcForTest combines running a service and its GRPC server.
// It is intended for services that implements the Service API (i.e., command line services).
//
//nolint:revive // maximum number of arguments per function exceeded; max 4 but got 5.
func RunServiceAndGrpcForTest(
	ctx context.Context,
	t *testing.T,
	service connection.Service,
	serverConfig *connection.ServerConfig,
	register ...func(server *grpc.Server),
) *grpc.Server {
	t.Helper()
	RunServiceForTest(ctx, t, func(ctx context.Context) error {
		return connection.FilterStreamRPCError(service.Run(ctx))
	}, service.WaitForReady)
	if serverConfig == nil || register == nil {
		return nil
	}
	return RunGrpcServerForTest(ctx, t, serverConfig, register...)
}

// WaitUntilGrpcServerIsReady uses the health check API to check a service readiness.
func WaitUntilGrpcServerIsReady(
	ctx context.Context,
	t *testing.T,
	conn grpc.ClientConnInterface,
) {
	t.Helper()
	if conn == nil {
		return
	}
	healthClient := healthgrpc.NewHealthClient(conn)
	res, err := healthClient.Check(ctx, &healthgrpc.HealthCheckRequest{}, grpc.WaitForReady(true))
	assert.NotEqual(t, codes.Canceled, status.Code(err))
	require.NoError(t, err)
	require.Equal(t, healthgrpc.HealthCheckResponse_SERVING, res.Status)
}

// StatusRetriever provides implementation retrieve status of given transaction identifiers.
type StatusRetriever interface {
	GetTransactionsStatus(
		context.Context,
		*protoblocktx.QueryStatus,
		...grpc.CallOption,
	) (*protoblocktx.TransactionsStatus, error)
}

// EnsurePersistedTxStatus fails the test if the given TX IDs does not match the expected status.
//
//nolint:revive // maximum number of arguments per function exceeded; max 4 but got 5.
func EnsurePersistedTxStatus(
	ctx context.Context,
	t *testing.T,
	r StatusRetriever,
	txIDs []string,
	expected map[string]*protoblocktx.StatusWithHeight,
) {
	t.Helper()
	if len(txIDs) == 0 {
		return
	}
	actualStatus, err := r.GetTransactionsStatus(ctx, &protoblocktx.QueryStatus{TxIDs: txIDs})
	require.NoError(t, err)
	require.EqualExportedValues(t, expected, actualStatus.Status)
}

// CheckServerStopped returns true if the grpc server listening on a
// given address has been stopped.
func CheckServerStopped(t *testing.T, addr string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	conn, err := grpc.DialContext( //nolint:staticcheck
		ctx,
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), //nolint:staticcheck
	)
	if err != nil {
		return true
	}
	_ = conn.Close()
	return false
}

// SetupDebugging can be added for development to tests that required additional debugging info.
func SetupDebugging() {
	logging.SetupWithConfig(&logging.Config{
		Enabled:     true,
		Level:       logging.Debug,
		Caller:      true,
		Development: true,
	})
}

// SecureConnectionFunctionArguments groups the arguments required to run a secure connection test.
type SecureConnectionFunctionArguments struct {
	ServerCN      string
	ServerStarter ServerStarter
	ClientStarter ClientStarter
	Parallel      bool
}

// ServerStarter is a func that receives a TLS config, start the server and return its endpoint.
type ServerStarter func(t *testing.T, serverTLS *connection.ConfigTLS) (endpoint connection.Endpoint)

// ClientStarter dials the service and returns a func that executes a request.
type ClientStarter func(t *testing.T, endpoint *connection.Endpoint, cfg *connection.ConfigTLS) RequestFunc

// RequestFunc performs a request and returns the resulting error.
type RequestFunc func(ctx context.Context) error

// RunSecureConnectionTest starts a gRPC server with mTLS enabled and
// tests client connections using various TLS configurations to verify that
// the server correctly accepts or rejects connections based on the client's setup.
func RunSecureConnectionTest(
	t *testing.T,
	secureConnArguments SecureConnectionFunctionArguments,
) {
	t.Helper()

	tlsMgr := tlsgen.NewSecureCommunicationManager(t)
	serverCreds := tlsMgr.CreateServerCertificate(t, secureConnArguments.ServerCN)
	serverTLS := CreateTLSConfigFromPaths(connection.TLSMutual, serverCreds, "")
	endpoint := secureConnArguments.ServerStarter(t, &serverTLS)

	clientCreds := tlsMgr.CreateClientCertificate(t)
	baseClientTLS := CreateTLSConfigFromPaths(connection.TLSNone, clientCreds, secureConnArguments.ServerCN)

	cases := []struct {
		desc      string
		tlsMode   connection.TLSMode
		expectErr bool
	}{
		{"correct client credentials", connection.TLSMutual, false},
		{"without mTLS", connection.TLSServer, true},
		{"with no TLS at all", connection.TLSNone, true},
	}

	for _, tc := range cases {
		testCase := tc
		t.Run(fmt.Sprintf("%s/%s", secureConnArguments.ServerCN, testCase.desc), func(t *testing.T) {
			if secureConnArguments.Parallel {
				t.Parallel()
			}

			cfg := baseClientTLS
			cfg.Mode = testCase.tlsMode

			requestFunc := secureConnArguments.ClientStarter(t, &endpoint, &cfg)

			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()

			err := requestFunc(ctx)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// CreateClientWithTLS creates and returns a typed gRPC client using the provided TLS configuration.
// It establishes a secure connection to the given endpoint
// and returns the generated client using the provided client creation proto function.
func CreateClientWithTLS[T any](
	t *testing.T,
	endpoint *connection.Endpoint,
	tlsCfg *connection.ConfigTLS,
	protoClient func(grpc.ClientConnInterface) T,
) T {
	t.Helper()

	creds, err := tlsCfg.ClientOption()
	require.NoError(t, err)

	conn, err := connection.Connect(
		connection.NewDialConfigWithCreds(endpoint, creds),
	)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	return protoClient(conn)
}

// CreateTLSConfigFromPaths creates and returns a TLS configuration based on the
// given TLS mode, credential file paths, and the expected server name.
func CreateTLSConfigFromPaths(
	connectionMode connection.TLSMode,
	paths map[string]string,
	serverName string,
) connection.ConfigTLS {
	return connection.ConfigTLS{
		Mode:        connectionMode,
		ServerName:  serverName,
		CertPath:    paths["PublicKey"],
		KeyPath:     paths["PrivateKey"],
		CACertPaths: []string{paths["CACertificate"]},
	}
}
