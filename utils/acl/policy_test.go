/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicy_Evaluate(t *testing.T) {
	t.Parallel()

	// Success cases - identity satisfies policy
	for _, tc := range []struct {
		name         string
		identityRole string
		requiredRole string
	}{
		{
			name:         "admin can access admin resource",
			identityRole: RoleAdmin,
			requiredRole: RoleAdmin,
		},
		{
			name:         "admin can access reader resource",
			identityRole: RoleAdmin,
			requiredRole: "reader",
		},
		{
			name:         "admin can access member resource",
			identityRole: RoleAdmin,
			requiredRole: RoleMember,
		},
		{
			name:         "client can access reader resource",
			identityRole: RoleClient,
			requiredRole: "reader",
		},
		{
			name:         "client can access member resource",
			identityRole: RoleClient,
			requiredRole: RoleMember,
		},
		{
			name:         "member can access member resource",
			identityRole: RoleMember,
			requiredRole: RoleMember,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := &Policy{
				Resource:     "/test.Service/Method",
				RequiredRole: tc.requiredRole,
			}

			identity := &Identity{
				Certificate:  &x509.Certificate{},
				Organization: "TestOrg",
				Role:         tc.identityRole,
			}

			err := policy.Evaluate(identity)
			require.NoError(t, err)
		})
	}

	// Failure cases - identity does not satisfy policy
	for _, tc := range []struct {
		name         string
		identityRole string
		requiredRole string
	}{
		{
			name:         "member cannot access reader resource",
			identityRole: RoleMember,
			requiredRole: "reader",
		},
		{
			name:         "member cannot access admin resource",
			identityRole: RoleMember,
			requiredRole: RoleAdmin,
		},
		{
			name:         "client cannot access admin resource",
			identityRole: RoleClient,
			requiredRole: RoleAdmin,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := &Policy{
				Resource:     "/test.Service/Method",
				RequiredRole: tc.requiredRole,
			}

			identity := &Identity{
				Certificate:  &x509.Certificate{},
				Organization: "TestOrg",
				Role:         tc.identityRole,
			}

			err := policy.Evaluate(identity)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrAccessDenied)
		})
	}
}

func TestPolicy_Evaluate_InvalidInputs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		identity     *Identity
		requiredRole string
		expectedErr  error
	}{
		{
			name:         "nil identity",
			identity:     nil,
			requiredRole: "reader",
			expectedErr:  ErrAccessDenied,
		},
		{
			name: "invalid identity role",
			identity: &Identity{
				Certificate:  &x509.Certificate{},
				Organization: "TestOrg",
				Role:         "invalid-role",
			},
			requiredRole: "reader",
			expectedErr:  ErrInvalidRole,
		},
		{
			name: "invalid required role",
			identity: &Identity{
				Certificate:  &x509.Certificate{},
				Organization: "TestOrg",
				Role:         RoleClient,
			},
			requiredRole: "invalid-role",
			expectedErr:  ErrInvalidRole,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := &Policy{
				Resource:     "/test.Service/Method",
				RequiredRole: tc.requiredRole,
			}

			err := policy.Evaluate(tc.identity)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

func TestRoleHierarchySatisfies(t *testing.T) {
	t.Parallel()

	// Success cases
	for _, tc := range []struct {
		name         string
		actualRole   string
		requiredRole string
	}{
		{name: "admin satisfies admin", actualRole: RoleAdmin, requiredRole: RoleAdmin},
		{name: "admin satisfies reader", actualRole: RoleAdmin, requiredRole: "reader"},
		{name: "admin satisfies client", actualRole: RoleAdmin, requiredRole: RoleClient},
		{name: "admin satisfies member", actualRole: RoleAdmin, requiredRole: RoleMember},
		{name: "client satisfies reader", actualRole: RoleClient, requiredRole: "reader"},
		{name: "client satisfies client", actualRole: RoleClient, requiredRole: RoleClient},
		{name: "client satisfies member", actualRole: RoleClient, requiredRole: RoleMember},
		{name: "member satisfies member", actualRole: RoleMember, requiredRole: RoleMember},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := roleHierarchySatisfies(tc.actualRole, tc.requiredRole)
			require.True(t, result, "expected %s to satisfy %s", tc.actualRole, tc.requiredRole)
		})
	}

	// Failure cases
	for _, tc := range []struct {
		name         string
		actualRole   string
		requiredRole string
	}{
		{name: "member does not satisfy reader", actualRole: RoleMember, requiredRole: "reader"},
		{name: "member does not satisfy client", actualRole: RoleMember, requiredRole: RoleClient},
		{name: "member does not satisfy admin", actualRole: RoleMember, requiredRole: RoleAdmin},
		{name: "client does not satisfy admin", actualRole: RoleClient, requiredRole: RoleAdmin},
		{name: "invalid actual role", actualRole: "invalid", requiredRole: "reader"},
		{name: "invalid required role", actualRole: RoleClient, requiredRole: "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := roleHierarchySatisfies(tc.actualRole, tc.requiredRole)
			require.False(t, result, "expected %s to not satisfy %s", tc.actualRole, tc.requiredRole)
		})
	}
}

func TestIsValidRole(t *testing.T) {
	t.Parallel()

	// Valid roles
	for _, tc := range []struct {
		name string
		role string
	}{
		{name: "admin is valid", role: RoleAdmin},
		{name: "client is valid", role: RoleClient},
		{name: "member is valid", role: RoleMember},
		{name: "reader is valid", role: "reader"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.True(t, isValidRole(tc.role))
		})
	}

	// Invalid roles
	for _, tc := range []struct {
		name string
		role string
	}{
		{name: "empty string is invalid", role: ""},
		{name: "random string is invalid", role: "random"},
		{name: "uppercase is invalid", role: "ADMIN"},
		{name: "mixed case is invalid", role: "Admin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.False(t, isValidRole(tc.role))
		})
	}
}

func TestNewPolicy(t *testing.T) {
	t.Parallel()

	// Success cases
	for _, tc := range []struct {
		name         string
		resource     string
		requiredRole string
	}{
		{
			name:         "valid policy with admin role",
			resource:     "/test.Service/Method",
			requiredRole: RoleAdmin,
		},
		{
			name:         "valid policy with reader role",
			resource:     "/test.Service/Method",
			requiredRole: "reader",
		},
		{
			name:         "valid policy with member role",
			resource:     "/test.Service/Method",
			requiredRole: RoleMember,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy, err := NewPolicy(tc.resource, tc.requiredRole)
			require.NoError(t, err)
			require.NotNil(t, policy)
			require.Equal(t, tc.resource, policy.Resource)
			require.Equal(t, tc.requiredRole, policy.RequiredRole)
		})
	}

	// Failure cases
	for _, tc := range []struct {
		name         string
		resource     string
		requiredRole string
	}{
		{
			name:         "empty resource",
			resource:     "",
			requiredRole: "reader",
		},
		{
			name:         "invalid required role",
			resource:     "/test.Service/Method",
			requiredRole: "invalid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy, err := NewPolicy(tc.resource, tc.requiredRole)
			require.Error(t, err)
			require.Nil(t, policy)
		})
	}
}

func TestPolicy_Evaluate_WithRealCertificate(t *testing.T) {
	t.Parallel()

	// Create a mock certificate with proper subject
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "user1@org1.example.com",
			Organization:       []string{"Org1MSP"},
			OrganizationalUnit: []string{RoleClient},
		},
	}

	identity := &Identity{
		Certificate:  cert,
		Organization: "Org1MSP",
		Role:         RoleClient,
	}

	policy := &Policy{
		Resource:     "/committerpb.QueryService/GetRows",
		RequiredRole: "reader",
	}

	err := policy.Evaluate(identity)
	require.NoError(t, err)
}
