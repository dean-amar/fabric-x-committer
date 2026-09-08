/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"testing"

	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
)

// TestScopeOfRequest verifies what the interceptor forwards for authorization. The AuthService makes
// the decision; this only checks that the namespaces a request touches are read out of it faithfully -
// including the "every namespace" case, which must be reported rather than looking like "none".
func TestScopeOfRequest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		request  any
		expected requestScope
	}{
		{
			name: "a query reports the namespaces it names",
			request: &committerpb.Query{Namespaces: []*committerpb.QueryNamespace{
				{NsId: testNS1, Keys: [][]byte{[]byte("k")}},
				{NsId: testNS2, Keys: [][]byte{[]byte("k")}},
			}},
			expected: requestScope{namespaces: []string{testNS1, testNS2}, all: false},
		},
		{
			name:     "a query naming no namespace asks for everything",
			request:  &committerpb.Query{},
			expected: requestScope{namespaces: []string{}, all: true},
		},
		{
			name:     "a filtered subscription reports its filter",
			request:  &committerpb.StreamAllRequest{FilterNamespaces: []string{testNS2}},
			expected: requestScope{namespaces: []string{testNS2}, all: false},
		},
		{
			// The leak this closes: an unfiltered subscription would otherwise look like a request for
			// no namespaces and pass a scoped token's check while streaming every namespace.
			name:     "an unfiltered subscription asks for everything",
			request:  &committerpb.StreamAllRequest{},
			expected: requestScope{all: true},
		},
		{
			name:     "a request that does not address namespaces reports none",
			request:  &committerpb.TxStatusQuery{TxIds: []string{"tx1"}},
			expected: requestScope{},
		},
		{
			name:     "an unrecognized message reports none",
			request:  nil,
			expected: requestScope{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, scopeOfRequest(tc.request))
		})
	}
}

func TestRequestScopeIsSet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		scope    requestScope
		expected bool
	}{
		{name: "named namespaces", scope: requestScope{namespaces: []string{testNS1}}, expected: true},
		{name: "every namespace", scope: requestScope{all: true}, expected: true},
		{name: "nothing addressed", scope: requestScope{}, expected: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, tc.scope.isSet())
		})
	}
}
