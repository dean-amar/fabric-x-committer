/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/cockroachdb/errors"
)

// roleLevels defines the role hierarchy (higher number = higher privilege).
// This is used to determine if one role satisfies another role requirement.
var roleLevels = map[string]int{
	RoleMember: 1,
	RoleClient: 2, // client is treated as reader
	RoleAdmin:  3,
}

// Policy defines the access control requirements for a specific resource (gRPC method).
// It specifies which role is required to access the resource.
type Policy struct {
	// Resource is the gRPC method name (e.g., "/committerpb.QueryService/GetRows")
	Resource string

	// RequiredRole is the minimum role required to access this resource.
	// Valid values: "admin", "reader", "member"
	RequiredRole string
}

var (
	// ErrAccessDenied is returned when an identity does not satisfy the required role.
	ErrAccessDenied = errors.New("access denied")

	// ErrInvalidRole is returned when a role value is not recognized.
	ErrInvalidRole = errors.New("invalid role")
)

// Evaluate checks if the given identity satisfies this policy's role requirements.
// It uses role hierarchy where higher privilege roles can access lower privilege resources:
//   - admin can access everything
//   - reader can access reader and member resources
//   - member can only access member resources
//
// Returns nil if access is granted, or an error describing why access was denied.
func (p *Policy) Evaluate(identity *Identity) error {
	if identity == nil {
		return errors.Wrap(ErrAccessDenied, "identity is nil")
	}

	// Validate that the required role is valid
	if !isValidRole(p.RequiredRole) {
		return errors.Wrapf(ErrInvalidRole, "policy has invalid required role: %s", p.RequiredRole)
	}

	// Validate that the identity's role is valid
	if !isValidRole(identity.Role) {
		return errors.Wrapf(ErrInvalidRole, "identity has invalid role: %s", identity.Role)
	}

	// Check if the identity's role satisfies the required role using hierarchy
	if !roleHierarchySatisfies(identity.Role, p.RequiredRole) {
		return errors.Wrapf(ErrAccessDenied,
			"identity role '%s' does not satisfy required role '%s' for resource '%s'",
			identity.Role, p.RequiredRole, p.Resource)
	}

	return nil
}

// roleHierarchySatisfies checks if actualRole satisfies requiredRole based on role hierarchy.
// The hierarchy is: admin > reader > member
//
// Examples:
//   - admin satisfies any role requirement (admin, reader, member)
//   - reader satisfies reader and member requirements
//   - member only satisfies member requirement
func roleHierarchySatisfies(actualRole, requiredRole string) bool {
	// Special case: "reader" is an alias for "client" in policy definitions
	if requiredRole == "reader" {
		requiredRole = RoleClient
	}

	actualLevel, actualExists := roleLevels[actualRole]
	requiredLevel, requiredExists := roleLevels[requiredRole]

	// If either role is not in the hierarchy, deny access
	if !actualExists || !requiredExists {
		return false
	}

	// Access granted if actual role level >= required role level
	return actualLevel >= requiredLevel
}

// isValidRole checks if a role string is one of the valid role values.
func isValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleClient, RoleMember, "reader":
		return true
	default:
		return false
	}
}

// NewPolicy creates a new Policy for the given resource and required role.
// It validates that the required role is valid.
func NewPolicy(resource string, requiredRole string) (*Policy, error) {
	if resource == "" {
		return nil, errors.New("resource cannot be empty")
	}

	if !isValidRole(requiredRole) {
		return nil, errors.Wrapf(ErrInvalidRole, "invalid required role: %s", requiredRole)
	}

	return &Policy{
		Resource:     resource,
		RequiredRole: requiredRole,
	}, nil
}
