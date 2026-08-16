/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsExemptMethod(t *testing.T) {
	t.Parallel()
	// Exempt methods bypass ACL enforcement.
	for _, tc := range []struct {
		name   string
		method string
	}{
		{name: "authorize RPC", method: AuthenticationResource},
		{name: "health check", method: "/grpc.health.v1.Health/Check"},
		{name: "health watch", method: "/grpc.health.v1.Health/Watch"},
		{name: "reflection v1", method: "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"},
		{name: "reflection v1alpha", method: "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.True(t, isExemptMethod(tc.method))
		})
	}

	// Non-exempt methods are subject to enforcement.
	for _, tc := range []struct {
		name   string
		method string
	}{
		{name: "query GetRows", method: "/committerpb.QueryService/GetRows"},
		{name: "deliver", method: "/protos.Deliver/Deliver"},
		{name: "unknown method", method: "/some.Unknown/Method"},
		{name: "empty method", method: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.False(t, isExemptMethod(tc.method))
		})
	}
}

// TestDefaultACLReferencesKnownPolicies ensures every default mapping points at one of the
// implicit-meta channel policies the RFC relies on. A typo here would resolve to a policy the
// PolicyManager cannot find, denying a resource that operators expect to be reachable.
func TestDefaultACLReferencesKnownPolicies(t *testing.T) {
	t.Parallel()
	valid := map[string]struct{}{ReaderPolicy: {}, WriterPolicy: {}}
	for resource, policyRef := range DefaultACL {
		_, ok := valid[policyRef]
		require.Truef(t, ok, "resource %s maps to unexpected policy %s", resource, policyRef)
	}
}
