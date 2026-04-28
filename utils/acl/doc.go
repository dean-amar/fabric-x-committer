/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

/*
Package acl provides Access Control List (ACL) functionality for fabric-x-committer services.

This package implements a simple, role-based access control system that validates client
identities from mTLS certificates and enforces access policies on gRPC methods.

# Architecture

The ACL system consists of three main layers:

1. Configuration Layer: Loads ACL policies and MSP (Membership Service Provider) configurations
2. Provider Layer: Coordinates identity extraction and policy evaluation
3. Validation Layer: Validates certificates and evaluates role-based policies

# Design Principles

This implementation follows the fabric-x-committer project guidelines:
  - Simple, readable code over clever abstractions
  - No unnecessary interfaces or generics
  - Concrete types with clear error handling
  - Optional by default (backward compatible)

# Usage

Basic usage with gRPC server:

	// Load ACL configuration (optional)
	aclConfig, err := acl.LoadConfig("acl-config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	// Create ACL provider
	provider := acl.NewProvider(aclConfig)

	// Create gRPC server with ACL interceptor
	server := grpc.NewServer(
		grpc.UnaryInterceptor(acl.UnaryServerInterceptor(provider)),
	)

If no configuration is provided, the ACL system is disabled and all requests are allowed:

	// Disabled ACL (backward compatible)
	provider := acl.NewProvider(nil)

# Certificate Requirements

Client certificates must include:
  - Organization (O field): The organization identifier (e.g., "Org1MSP")
  - Organizational Unit (OU field): The role ("admin", "client", or "member")

Example certificate subject:

	CN=user1@org1.example.com, OU=client, O=Org1MSP

# Role Hierarchy

The system implements a simple role hierarchy:
  - admin: Highest privilege, can access all resources
  - reader: Can access read-only resources (Query Service, Sidecar)
  - member: Default role, no special privileges

# Security Considerations

The ACL system provides:
  - Certificate chain validation against trusted CAs
  - Certificate expiration checking
  - Role extraction with whitelist validation
  - Audit logging for all access decisions
  - Prometheus metrics for monitoring

For detailed security considerations, see the project documentation.
*/
package acl
