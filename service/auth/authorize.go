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

	if err = namespacesAllowed(rec.GetNamespaces(), req); err != nil {
		logger.Debugf("Authorization denied for [%s]: %v", req.GetResource(), err)
		return nil, grpcerror.WrapPermissionDenied(err)
	}

	if err = evaluateResourcePolicy(bundle, req.GetResource(), rec.GetIdentity()); err != nil {
		logger.Debugf("Authorization denied for [%s]: %v", req.GetResource(), err)
		return nil, grpcerror.WrapPermissionDenied(err)
	}

	return &servicepb.AuthorizeResponse{
		Authorized:     true,
		TokenExpiresAt: rec.GetExpiresAt(),
	}, nil
}

// namespacesAllowed checks the namespaces a request touches against the token's namespace scope. An
// unscoped token may touch anything; a scoped one may touch only what it lists, and cannot satisfy a
// request that asks for every namespace (an unfiltered subscription) - that is denied outright rather
// than narrowed, so a client is never left believing it is subscribed to more than it will receive.
func namespacesAllowed(allowed []string, req *servicepb.AuthorizeRequest) error {
	if len(allowed) == 0 {
		return nil
	}
	if req.GetAllNamespaces() {
		return errors.Newf(
			"resource %s requests every namespace, which a namespace-scoped token cannot satisfy; "+
				"restrict the request to %v", req.GetResource(), allowed,
		)
	}
	for _, nsID := range req.GetNamespaces() {
		if !slices.Contains(allowed, nsID) {
			return errors.Newf("namespace %s is outside the token's namespace scope %v", nsID, allowed)
		}
	}
	return nil
}
