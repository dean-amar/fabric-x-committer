/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

// DefaultACLs defines the default access control mappings for all exposed gRPC methods.
// These mappings specify which role is required to access each method.
//
// All Query Service and Sidecar Service operations are read-only and require "reader" role.
// The "reader" role is satisfied by clients with "client" or "admin" roles.
var DefaultACLs = map[string]string{
	// Query Service - All read operations require reader role
	"/committerpb.QueryService/BeginView":            "reader",
	"/committerpb.QueryService/EndView":              "reader",
	"/committerpb.QueryService/GetRows":              "reader",
	"/committerpb.QueryService/GetTransactionStatus": "reader",
	"/committerpb.QueryService/GetNamespacePolicies": "reader",
	"/committerpb.QueryService/GetConfigTransaction": "reader",

	// Sidecar - Deliver Service (peer.Deliver)
	// These methods stream blocks to clients
	"/peer.Deliver/Deliver":                "reader",
	"/peer.Deliver/DeliverFiltered":        "reader",
	"/peer.Deliver/DeliverWithPrivateData": "reader",

	// Sidecar - Notifier Service
	// Subscribe to transaction status updates
	"/committerpb.Notifier/Subscribe": "reader",

	// Sidecar - Block Query Service
	// Query specific blocks by number or transaction ID
	"/committerpb.BlockQueryService/GetBlockByNumber": "reader",
	"/committerpb.BlockQueryService/GetBlockByTxID":   "reader",
}

// GetDefaultPolicy returns the default required role for a given gRPC method.
// Returns empty string if no default policy is defined for the method.
func GetDefaultPolicy(method string) string {
	return DefaultACLs[method]
}

// IsMethodProtected returns true if the given gRPC method has a default ACL policy.
// Methods without policies are not protected by ACL.
func IsMethodProtected(method string) bool {
	_, exists := DefaultACLs[method]
	return exists
}
