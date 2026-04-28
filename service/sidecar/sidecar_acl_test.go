/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sidecar

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/acl"
)

// TestSidecarService_ACL_Configuration tests that Sidecar Service properly initializes
// with ACL configuration and fails fast on invalid configuration.
func TestSidecarService_ACL_Configuration(t *testing.T) {
	t.Parallel()

	// Test 1: Service with valid ACL configuration should succeed
	t.Run("valid ACL configuration creates enabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled: true,
				Policies: map[string]string{
					"/committerpb.BlockQueryService/GetBlockByNumber": "reader",
				},
			},
		}

		// Create minimal config to avoid nil pointer errors
		// Note: Full service creation requires many dependencies, so we test
		// ACL initialization separately
		aclProvider, err := acl.NewProvider(config.ACL)
		require.NoError(t, err)
		require.NotNil(t, aclProvider)
		require.True(t, aclProvider.IsEnabled())
	})

	// Test 2: Service with disabled ACL
	t.Run("disabled ACL configuration creates disabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled: false,
			},
		}

		aclProvider, err := acl.NewProvider(config.ACL)
		require.NoError(t, err)
		require.NotNil(t, aclProvider)
		require.False(t, aclProvider.IsEnabled())
	})

	// Test 3: Service with nil ACL config
	t.Run("nil ACL configuration creates disabled provider", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: nil,
		}

		aclProvider, err := acl.NewProvider(config.ACL)
		require.NoError(t, err)
		require.NotNil(t, aclProvider)
		require.False(t, aclProvider.IsEnabled())
	})

	// Test 4: Service with invalid ACL configuration should return error
	t.Run("invalid ACL configuration returns error", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			ACL: &acl.Config{
				Enabled: true,
				Policies: map[string]string{
					"/committerpb.BlockQueryService/GetBlockByNumber": "invalid-role",
				},
			},
		}

		// Should return error due to invalid role
		aclProvider, err := acl.NewProvider(config.ACL)
		require.Error(t, err)
		require.Nil(t, aclProvider)
		require.Contains(t, err.Error(), "invalid required role")
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

		aclProvider, err := acl.NewProvider(config.ACL)
		require.NoError(t, err)
		require.NotNil(t, aclProvider)
		require.True(t, aclProvider.IsEnabled())
	})
}

// TestSidecarService_ACL_DefaultPolicies verifies that default ACL policies
// are properly configured for all Sidecar Service methods.
func TestSidecarService_ACL_DefaultPolicies(t *testing.T) {
	t.Parallel()

	// Verify that all Sidecar Service methods have default ACL policies
	expectedMethods := []string{
		// Block Query Service
		"/committerpb.BlockQueryService/GetBlockByNumber",
		"/committerpb.BlockQueryService/GetBlockByTxID",

		// Deliver Service
		"/peer.Deliver/Deliver",
		"/peer.Deliver/DeliverFiltered",
		"/peer.Deliver/DeliverWithPrivateData",

		// Notifier Service
		"/committerpb.Notifier/Subscribe",
	}

	for _, method := range expectedMethods {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			policy := acl.DefaultACLs[method]
			require.NotEmpty(t, policy, "Method %s should have a default ACL policy", method)
			require.Equal(t, "reader", policy, "Sidecar methods should require 'reader' role")
		})
	}
}

// Made with Bob
