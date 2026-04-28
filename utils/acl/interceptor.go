/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor creates a gRPC unary server interceptor that enforces ACL checks.
// The interceptor runs before the actual RPC handler and performs the following:
//  1. Checks if ACL is enabled (if disabled, passes through)
//  2. Extracts client identity from the TLS connection
//  3. Validates the identity against the policy for the requested method
//  4. Returns PermissionDenied error if access is denied
//  5. Calls the handler if access is granted
//
// Usage:
//
//	provider := acl.NewProvider(config)
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(acl.UnaryServerInterceptor(provider)),
//	)
func UnaryServerInterceptor(provider *Provider) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip ACL check if provider is disabled (backward compatible)
		if !provider.IsEnabled() {
			return handler(ctx, req)
		}

		// Perform ACL check
		if err := provider.CheckACL(ctx, info.FullMethod); err != nil {
			// Convert ACL error to gRPC PermissionDenied status
			return nil, status.Errorf(codes.PermissionDenied,
				"access denied for method %s: %v", info.FullMethod, err)
		}

		// Access granted, proceed with handler
		return handler(ctx, req)
	}
}

// StreamServerInterceptor creates a gRPC stream server interceptor that enforces ACL checks.
// Similar to UnaryServerInterceptor but for streaming RPCs.
// The ACL check is performed once at stream establishment time.
//
// Usage:
//
//	provider := acl.NewProvider(config)
//	server := grpc.NewServer(
//	    grpc.StreamInterceptor(acl.StreamServerInterceptor(provider)),
//	)
func StreamServerInterceptor(provider *Provider) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip ACL check if provider is disabled (backward compatible)
		if !provider.IsEnabled() {
			return handler(srv, ss)
		}

		// Perform ACL check using the stream's context
		if err := provider.CheckACL(ss.Context(), info.FullMethod); err != nil {
			// Convert ACL error to gRPC PermissionDenied status
			return status.Errorf(codes.PermissionDenied,
				"access denied for method %s: %v", info.FullMethod, err)
		}

		// Access granted, proceed with handler
		return handler(srv, ss)
	}
}
