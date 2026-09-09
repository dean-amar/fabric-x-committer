/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve_test

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
	"github.com/hyperledger/fabric-x-committer/utils/serve"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// aclRegisterer registers the health service and, like a real resource service, exposes the enforcer it
// built so serve installs its interceptors when the gRPC server is created.
type aclRegisterer struct {
	committerpb.UnimplementedQueryServiceServer
	health   *health.Server
	enforcer *acl.Enforcer
}

func (r *aclRegisterer) RegisterService(s serve.Servers) {
	healthgrpc.RegisterHealthServer(s.GRPC, r.health)
	// A registered, non-exempt method is needed to observe enforcement: gRPC answers an unknown
	// method with Unimplemented before any interceptor runs.
	committerpb.RegisterQueryServiceServer(s.GRPC, r)
}

func (r *aclRegisterer) ACLEnforcer() *acl.Enforcer {
	return r.enforcer
}

// TestACLEnforcerInstalledAtConstruction is the guarantee the design rests on: the enforcer a service
// built in Run is read when the server is created, so its interceptors are in place before the first
// RPC. An unauthenticated call must therefore be rejected by the interceptor, not reach the handler.
func TestACLEnforcerInstalledAtConstruction(t *testing.T) {
	t.Parallel()
	// A nil client is never dialled: the call is rejected for the missing token first.
	reg := &aclRegisterer{
		health:   serve.DefaultHealthCheckService(),
		enforcer: acl.NewEnforcer(nil, acl.EnforcerConfig{}),
	}
	conn, ctx := serveForACLTest(t, reg)

	_, err := healthgrpc.NewHealthClient(conn).Check(ctx, &healthgrpc.HealthCheckRequest{})
	require.NoError(t, err, "health checks are exempt from enforcement")

	// A non-exempt method with no token is rejected by the installed interceptor.
	_, err = committerpb.NewQueryServiceClient(conn).GetRows(ctx, &committerpb.Query{})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
}

// TestACLEnforcerAbsentServesWithoutEnforcement verifies a service that exposes no enforcer is served
// exactly as before: the same call reaches the server and fails only because the method is unknown.
func TestACLEnforcerAbsentServesWithoutEnforcement(t *testing.T) {
	t.Parallel()
	reg := &aclRegisterer{health: serve.DefaultHealthCheckService()}
	conn, ctx := serveForACLTest(t, reg)

	_, err := committerpb.NewQueryServiceClient(conn).GetRows(ctx, &committerpb.Query{})
	require.Equal(t, codes.Unimplemented, grpcerror.GetCode(err),
		"without an enforcer the call reaches the handler, which is the unimplemented stub")
}

// serveForACLTest starts a server for the registerer and returns a connection to it.
func serveForACLTest(t *testing.T, reg *aclRegisterer) (*grpc.ClientConn, context.Context) {
	t.Helper()
	serverConfig := test.NewLocalHostServiceConfig(test.InsecureTLSConfig)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	test.ServeForTest(ctx, t, serverConfig, reg)
	return test.NewInsecureConnection(t, &serverConfig.GRPC.Endpoint), ctx
}
