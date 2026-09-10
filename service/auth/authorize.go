/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// authorizer answers authorization decisions for resource servers: it verifies a token, resolves the
// bound identity from the token store, and evaluates the resource policy. A long-lived stream renews
// its decision by calling authorize again with the same token, so nothing here is stream-specific.
//
// Like the authenticator, it has no constructor: both its fields come from its single caller, so a
// keyed struct literal says the same thing without a second declaration to keep in step.
type authorizer struct {
	signer *tokenSigner
	tokens *tokenStore
}

// authorize verifies the token, checks its certificate binding and resource scope, resolves and
// validates the bound identity against the latest bundle, and evaluates the resource policy. On success
// it returns the decision and the bound token's expiry - never the identity, which the caller has no use
// for because it re-presents the token. Every other outcome is a gRPC status error: Unauthenticated for
// a token problem, PermissionDenied for a scope or policy denial, Unavailable for a store failure.
func (a *authorizer) authorize(
	ctx context.Context, req *servicepb.AuthorizeRequest, bundle *channelconfig.Bundle,
) (*servicepb.AuthorizeResponse, error) {
	claims, err := a.signer.verify(req.GetToken())
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(errors.Wrap(err, "invalid token"))
	}

	rec, err := a.tokens.get(ctx, claims.ID)
	switch {
	case errors.Is(err, ErrTokenNotFound):
		return nil, grpcerror.WrapUnauthenticated(errors.New("token is not recognized"))
	case err != nil:
		// A store failure is not a denial, and must not be reported as one: a resource server treats
		// Unauthenticated as definitive and tears the stream down, so a database blip here would kill
		// every established stream at once. Unavailable is the code its transient tolerance recognizes.
		// The cause is logged rather than returned, so no database detail crosses the wire.
		logger.Errorf("%+v", err)
		return nil, grpcerror.WrapUnavailable(errors.New("the token store is unavailable"))
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

	if err = evaluateResourcePolicy(bundle, req.GetResource(), rec.GetIdentity()); err != nil {
		logger.Debugf("Authorization denied for [%s]: %v", req.GetResource(), err)
		return nil, grpcerror.WrapPermissionDenied(err)
	}

	return &servicepb.AuthorizeResponse{
		Authorized:     true,
		TokenExpiresAt: rec.GetExpiresAt(),
	}, nil
}

// scopeAllows reports whether a resource is within a token's granted scope. An empty scope imposes
// no restriction (the token carries the identity's full authority); a non-empty scope allows only
// the resources it lists explicitly, matched by exact gRPC full-method name.
func scopeAllows(scope []string, resource string) bool {
	if len(scope) == 0 {
		return true
	}
	return slices.Contains(scope, resource)
}

// normalizeScope cleans a requested scope: it trims each entry, drops empties, and removes
// duplicates while preserving order. An empty or all-empty requested scope normalizes to nil,
// meaning the token is unscoped and carries the identity's full authority.
//
// Scope entries are gRPC resource (full-method) names, e.g. "/committerpb.QueryService/GetRows".
// A scope can only narrow authority: it restricts which resources a token may be used for, and is
// checked in addition to - never instead of - the channel policy, so it can never grant access the
// identity's policy would deny.
func normalizeScope(requested []string) []string {
	if len(requested) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(requested))
	normalized := make([]string, 0, len(requested))
	for _, entry := range requested {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}
