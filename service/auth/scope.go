/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"slices"
	"strings"
)

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

// scopeAllows reports whether a resource is within a token's granted scope. An empty scope imposes
// no restriction (the token carries the identity's full authority); a non-empty scope allows only
// the resources it lists explicitly, matched by exact gRPC full-method name.
func scopeAllows(scope []string, resource string) bool {
	if len(scope) == 0 {
		return true
	}
	return slices.Contains(scope, resource)
}
