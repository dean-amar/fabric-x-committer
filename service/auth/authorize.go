/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// authorizer answers authorization decisions for resource servers. Authorize verifies a token,
// resolves the bound identity from the identity store, and evaluates the resource policy;
// reAuthorize re-evaluates an already-bound identity against the latest policy for a long-lived
// stream, without a token.
type authorizer struct {
	signer *tokenSigner
	store  *tokenStore
}

func newAuthorizer(signer *tokenSigner, store *tokenStore) *authorizer {
	return &authorizer{signer: signer, store: store}
}

// authorize verifies the token, checks its certificate binding and scope, resolves the bound
// identity against the latest bundle, and evaluates the resource policy. On success it returns the
// serialized identity so the caller can bind it to a stream session for later re-authorization.
// Every non-authorized outcome is a gRPC status error (Unauthenticated / PermissionDenied).
func (a *authorizer) authorize(
	ctx context.Context, req *servicepb.AuthorizeRequest, bundle *channelconfig.Bundle,
) (*servicepb.AuthorizeResponse, error) {
	claims, err := a.signer.verify(req.GetToken())
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(errors.Wrap(err, "invalid token"))
	}

	rec, err := a.store.get(ctx, claims.ID)
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(errors.New("token is not recognized"))
	}

	// The certificate presented at the resource server must match the one the token was bound to, so
	// a leaked token cannot be replayed from a different connection.
	if !bytes.Equal(rec.GetCertHashSha256(), req.GetTlsCertHash()) {
		return nil, grpcerror.WrapUnauthenticated(errors.New("token is not bound to this certificate"))
	}

	if !scopeAllows(rec.GetScope(), req.GetResource()) {
		return nil, grpcerror.WrapPermissionDenied(
			errors.Newf("resource %s is outside the token scope", req.GetResource()),
		)
	}

	if err = evaluateResourcePolicy(bundle, req.GetResource(), rec.GetSerializedIdentity()); err != nil {
		logger.Debugf("Authorization denied for [%s]: %v", req.GetResource(), err)
		return nil, grpcerror.WrapPermissionDenied(err)
	}

	return &servicepb.AuthorizeResponse{Authorized: true, Identity: rec.GetSerializedIdentity()}, nil
}

// reAuthorize re-evaluates an identity already bound to a stream session against the resource policy
// under the latest bundle. It takes the identity directly (not a token), so a long-lived stream's
// authorization tracks the identity's current permissions - a configuration change that removes the
// identity's organization tears the stream down - independently of the establishment token's TTL.
func (*authorizer) reAuthorize(
	req *servicepb.ReAuthorizeRequest, bundle *channelconfig.Bundle,
) (*servicepb.AuthorizeResponse, error) {
	if len(req.GetIdentity()) == 0 {
		return nil, grpcerror.WrapInvalidArgument(errors.New("identity is required"))
	}
	if err := evaluateResourcePolicy(bundle, req.GetResource(), req.GetIdentity()); err != nil {
		logger.Debugf("Stream re-authorization denied for [%s]: %v", req.GetResource(), err)
		return nil, grpcerror.WrapPermissionDenied(err)
	}
	return &servicepb.AuthorizeResponse{Authorized: true, Identity: req.GetIdentity()}, nil
}
