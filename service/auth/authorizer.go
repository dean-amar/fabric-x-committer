/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// authorizer verifies a token, resolves the bound identity from the store and evaluates the resource
// policy. Nothing here is stream-specific: a stream renews by calling authorize with the same token.
type authorizer struct {
	signer *tokenSigner
	tokens *tokenStore
}

// authorize verifies the token, binding and scope, re-resolves the identity and evaluates the policy.
func (a *authorizer) authorize(
	ctx context.Context, req *servicepb.AuthorizeRequest, bundle *channelconfig.Bundle,
) (*servicepb.AuthorizeResponse, error) {
	claims, err := a.signer.verify(req.GetToken())
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(errors.Wrap(err, "invalid token"))
	}

	tokenRecord, err := a.tokens.get(ctx, claims.ID)
	switch {
	case errors.Is(err, ErrTokenNotFound):
		return nil, grpcerror.WrapUnauthenticated(errors.New("token is not recognized"))
	case err != nil:
		return nil, grpcerror.WrapUnavailable(errors.New("the token store is unavailable"))
	}

	// The certificate presented at the resource server must match the one the token was bound to, so
	// a leaked token cannot be replayed from a different connection.
	if !bytes.Equal(tokenRecord.GetCertHashSha256(), req.GetTlsCertHash()) {
		return nil, grpcerror.WrapUnauthenticated(errors.New("token is not bound to this certificate"))
	}

	if !scopeAllows(tokenRecord.GetScope(), req.GetResource()) {
		return nil, grpcerror.WrapPermissionDenied(
			errors.Newf("resource %s is outside the token scope", req.GetResource()),
		)
	}

	if err = evaluateResourcePolicy(bundle, req.GetResource(), tokenRecord.GetIdentity()); err != nil {
		logger.Debugf("Authorization denied for [%s]: %v", req.GetResource(), err)
		return nil, grpcerror.WrapPermissionDenied(err)
	}

	return &servicepb.AuthorizeResponse{
		Authorized:     true,
		TokenExpiresAt: tokenRecord.GetExpiresAt(),
	}, nil
}

// scopeAllows reports whether a resource is within a token's scope. An empty scope imposes no restriction;
// a non-empty one allows only the resources it lists, matched by exact gRPC full-method name.
func scopeAllows(scope []string, resource string) bool {
	if len(scope) == 0 {
		return true
	}
	return slices.Contains(scope, resource)
}
