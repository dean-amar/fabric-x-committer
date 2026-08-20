/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/msp"
	"google.golang.org/grpc"
)

// ClientAuthConfig configures the client-side envelope attachment. A nil Signer makes both
// interceptors no-op passthroughs, so non-ACL deployments share the same dial path.
type ClientAuthConfig struct {
	Signer      msp.SigningIdentity
	ChannelID   string
	TLSCertHash []byte
}

// UnaryClientInterceptor attaches a freshly-signed, method-bound envelope to the outgoing
// metadata of every unary RPC.
func UnaryClientInterceptor(cfg ClientAuthConfig) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context, method string, req, reply any,
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption,
	) error {
		if cfg.Signer == nil {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		authCtx, err := cfg.attach(ctx, method)
		if err != nil {
			return err
		}
		return invoker(authCtx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor attaches the envelope (bound to the stream's method) at stream open.
func StreamClientInterceptor(cfg ClientAuthConfig) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		if cfg.Signer == nil {
			return streamer(ctx, desc, cc, method, opts...)
		}
		authCtx, err := cfg.attach(ctx, method)
		if err != nil {
			return nil, err
		}
		return streamer(authCtx, desc, cc, method, opts...)
	}
}

func (cfg ClientAuthConfig) attach(ctx context.Context, method string) (context.Context, error) {
	var env *cb.Envelope
	env, err := BuildAuthEnvelope(cfg.Signer, cfg.ChannelID, method, cfg.TLSCertHash)
	if err != nil {
		return ctx, err
	}
	return envelopeToOutgoingContext(ctx, env)
}
