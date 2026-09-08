/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/hyperledger/fabric-x-common/api/committerpb"
)

// requestScope describes which namespaces an incoming request touches, so the AuthService can check
// them against the token's namespace scope. The decision stays in the AuthService; the interceptor's
// only job is to read the request and report what it asks for.
type requestScope struct {
	// namespaces are the namespace ids the request names explicitly.
	namespaces []string
	// all is true when the request is not restricted to particular namespaces, such as a subscription
	// with no namespace filter. It is reported rather than treated as "no namespaces", because a
	// namespace-scoped token must not silently receive everything.
	all bool
}

// isSet reports whether a request actually addressed namespaces, so a message that says nothing about
// them (any message after a subscription request) does not trigger an authorization call of its own.
func (s requestScope) isSet() bool {
	return len(s.namespaces) > 0 || s.all
}

// scopeOfRequest reads the namespaces a request touches out of its body.
//
// This is an explicit switch over the ACL-protected request shapes rather than a generic reflection
// pass: the set is small, the mapping from a message to "the namespaces it touches" is genuinely
// per-message (a query names them directly, a subscription filters on them), and a reader can see at a
// glance exactly what is forwarded for authorization. A request type that is not listed reports no
// namespaces, which is correct for the methods that do not address namespaces at all.
func scopeOfRequest(req any) requestScope {
	switch r := req.(type) {
	case *committerpb.Query:
		namespaces := make([]string, 0, len(r.GetNamespaces()))
		for _, ns := range r.GetNamespaces() {
			namespaces = append(namespaces, ns.GetNsId())
		}
		return requestScope{namespaces: namespaces, all: len(namespaces) == 0}
	case *committerpb.StreamAllRequest:
		// An empty filter means "every namespace", which is the case a scoped token must not satisfy.
		filter := r.GetFilterNamespaces()
		return requestScope{namespaces: filter, all: len(filter) == 0}
	default:
		return requestScope{}
	}
}
