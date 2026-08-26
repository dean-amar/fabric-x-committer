/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/hyperledger/fabric-x-committer/utils/serve"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// interceptorRegisterer registers the health service and contributes counting interceptors through
// the optional provider interfaces, so a test can confirm they are installed and invoked.
type interceptorRegisterer struct {
	health      *health.Server
	unaryCalls  atomic.Int32
	streamCalls atomic.Int32
}

func (r *interceptorRegisterer) RegisterService(s serve.Servers) {
	healthgrpc.RegisterHealthServer(s.GRPC, r.health)
}

func (r *interceptorRegisterer) UnaryServerInterceptors() []grpc.UnaryServerInterceptor {
	return []grpc.UnaryServerInterceptor{
		func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			r.unaryCalls.Add(1)
			return handler(ctx, req)
		},
	}
}

func (r *interceptorRegisterer) StreamServerInterceptors() []grpc.StreamServerInterceptor {
	return []grpc.StreamServerInterceptor{
		func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			r.streamCalls.Add(1)
			return handler(srv, ss)
		},
	}
}

// TestRegistererInterceptorsAreInstalled verifies that interceptors contributed through the
// UnaryInterceptorProvider / StreamInterceptorProvider interfaces run on real RPCs.
func TestRegistererInterceptorsAreInstalled(t *testing.T) {
	t.Parallel()
	reg := &interceptorRegisterer{health: serve.DefaultHealthCheckService()}

	serverConfig := test.NewLocalHostServiceConfig(test.InsecureTLSConfig)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	test.ServeForTest(ctx, t, serverConfig, reg)

	client := healthgrpc.NewHealthClient(test.NewInsecureConnection(t, &serverConfig.GRPC.Endpoint))

	_, err := client.Check(ctx, &healthgrpc.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(1), reg.unaryCalls.Load())

	stream, err := client.Watch(ctx, &healthgrpc.HealthCheckRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	require.NoError(t, err)
	require.Equal(t, int32(1), reg.streamCalls.Load())
}
