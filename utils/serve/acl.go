/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
)

type (
	// ACLHandler is the authorization seam attached to every gRPC server, as ServerStatsHandler is the
	// metrics seam. NewServers creates it and newGRPCServer installs its interceptors; a service fills
	// it in later, during RegisterService, via acl.RegisterEnforcer.
	//
	// The indirection is what makes register-and-use work: interceptors can only be given to
	// grpc.NewServer at construction, which happens before RegisterService runs. Consulting a handler
	// per RPC decouples the two. Until an enforcer is registered, it passes RPCs straight through.
	//
	// It holds interceptors rather than the enforcer so serve stays independent of the authorization
	// implementation; utils/acl imports serve, never the reverse.
	ACLHandler struct {
		interceptors atomic.Pointer[aclInterceptors]
	}

	// aclInterceptors is the pair an enforcer contributes, stored together so one is never read
	// without the other.
	aclInterceptors struct {
		unary  grpc.UnaryServerInterceptor
		stream grpc.StreamServerInterceptor
	}
)

// RegisterACLInterceptors installs the interceptors that authorize this server's RPCs. Services reach
// it through acl.RegisterEnforcer rather than calling it directly.
func RegisterACLInterceptors(
	h *ACLHandler, unary grpc.UnaryServerInterceptor, stream grpc.StreamServerInterceptor,
) {
	h.interceptors.Store(&aclInterceptors{unary: unary, stream: stream})
}

// UnaryInterceptor delegates to the registered enforcer, or passes the RPC through when none is set.
func (h *ACLHandler) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		i := h.interceptors.Load()
		if i == nil {
			return handler(ctx, req)
		}
		return i.unary(ctx, req, info, handler)
	}
}

// StreamInterceptor is the streaming counterpart of UnaryInterceptor.
func (h *ACLHandler) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		i := h.interceptors.Load()
		if i == nil {
			return handler(srv, ss)
		}
		return i.stream(srv, ss, info, handler)
	}
}
