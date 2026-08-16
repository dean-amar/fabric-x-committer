/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"

	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var logger = flogging.MustGetLogger("auth")

// Service implements the AuthService gRPC service.
//
// The actual authorization work — validating the signed envelope and binding the MSP
// identity to the connection — is performed by auth.AuthorizeInterceptor, which is
// installed as a unary interceptor on the query and sidecar gRPC servers. The interceptor
// short-circuits the Authorize RPC and returns the response directly, so the handler below
// is a defensive fallback: reaching it means the interceptor was not installed.
type Service struct {
	committerpb.UnimplementedAuthServiceServer
}

// NewAuthService creates a new auth service bound to the given TLS/bundle provider.
func NewAuthService() *Service {
	return &Service{}
}

// Authorize is a defensive fallback. In normal operation auth.AuthorizeInterceptor handles
// the Authorize RPC before it reaches this handler. If execution reaches here, the ACL
// interceptor chain is misconfigured, so we fail closed rather than binding any identity.
func (*Service) Authorize(
	_ context.Context, _ *committerpb.AuthorizeRequest,
) (*committerpb.AuthorizeResponse, error) {
	logger.Error("Authorize handler reached directly; the ACL interceptor is not installed")
	return nil, status.Error(codes.Internal, "authorization interceptor not installed")
}
