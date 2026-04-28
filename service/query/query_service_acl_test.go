/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
)

// TestQueryService_ACL_Configuration tests that Query Service properly initializes
// with ACL configuration and fails fast on invalid configuration.
func TestQueryService_ACL_Configuration(t *testing.T) {
	t.Parallel()

	// Test 1: Service with valid ACL configuration
	t.Run("valid ACL configuration creates enabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled: true,
				Policies: map[string]string{
					"/committerpb.QueryService/GetRows": "reader",
				},
			},
		}

		service := NewQueryService(config, nil)
		require.NotNil(t, service)
		require.NotNil(t, service.aclProvider)
		require.True(t, service.aclProvider.IsEnabled())
	})

	// Test 2: Service with disabled ACL
	t.Run("disabled ACL configuration creates disabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled: false,
			},
		}

		service := NewQueryService(config, nil)
		require.NotNil(t, service)
		require.NotNil(t, service.aclProvider)
		require.False(t, service.aclProvider.IsEnabled())
	})

	// Test 3: Service with nil ACL config
	t.Run("nil ACL configuration creates disabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: nil,
		}

		service := NewQueryService(config, nil)
		require.NotNil(t, service)
		require.NotNil(t, service.aclProvider)
		require.False(t, service.aclProvider.IsEnabled())
	})

	// Test 4: Service with invalid ACL configuration should panic
	t.Run("invalid ACL configuration causes panic", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled: true,
				Policies: map[string]string{
					"/committerpb.QueryService/GetRows": "invalid-role",
				},
			},
		}

		// Should panic due to invalid role
		require.Panics(t, func() {
			NewQueryService(config, nil)
		}, "Service should panic on invalid ACL configuration")
	})

	// Test 5: Service with default ACL policies
	t.Run("enabled ACL with no policies uses defaults", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled:  true,
				Policies: nil, // Will use defaults
			},
		}

		service := NewQueryService(config, nil)
		require.NotNil(t, service)
		require.NotNil(t, service.aclProvider)
		require.True(t, service.aclProvider.IsEnabled())
	})
}

// TestQueryService_ACL_DefaultPolicies verifies that default ACL policies
// are properly configured for all Query Service methods.
func TestQueryService_ACL_DefaultPolicies(t *testing.T) {
	t.Parallel()

	// Verify that all Query Service methods have default ACL policies
	expectedMethods := []string{
		"/committerpb.QueryService/BeginView",
		"/committerpb.QueryService/EndView",
		"/committerpb.QueryService/GetRows",
		"/committerpb.QueryService/GetTransactionStatus",
		"/committerpb.QueryService/GetNamespacePolicies",
		"/committerpb.QueryService/GetConfigTransaction",
	}

	for _, method := range expectedMethods {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			policy := acl.DefaultACLs[method]
			require.NotEmpty(t, policy, "Method %s should have a default ACL policy", method)
			require.Equal(t, "reader", policy, "Query methods should require 'reader' role")
		})
	}
}

// Made with Bob
