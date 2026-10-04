/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
)

// ACLProvider enforces ACL on a gRPC server once a service registers an enforcer with it. Every server
// carries it, so the interceptors are in place before the first RPC; without an enforcer they pass calls
// through.
//
// The design separates writers (services) from readers (server), ensuring a linear dependency flow:
//
//	Service -> acl.Enforcer <- ACLProvider <- Server
type ACLProvider struct {
	enforcer atomic.Pointer[acl.Enforcer]
}

// RegisterACLEnforcer registers an acl.Enforcer with an ACLProvider. It is safe to call while the server
// serves, but RPCs received before it are not enforced, so call it from RegisterService.
func RegisterACLEnforcer(p *ACLProvider, e *acl.Enforcer) {
	p.enforcer.Store(e)
}

func (p *ACLProvider) unaryInterceptor(
	ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
) (any, error) {
	e := p.enforcer.Load()
	if e == nil {
		return handler(ctx, req)
	}
	return e.UnaryInterceptor(ctx, req, info, handler)
}

func (p *ACLProvider) streamInterceptor(
	srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler,
) error {
	e := p.enforcer.Load()
	if e == nil {
		return handler(srv, ss)
	}
	return e.StreamInterceptor(srv, ss, info, handler)
}
