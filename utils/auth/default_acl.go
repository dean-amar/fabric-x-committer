/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

const (
	// AuthenticationResource is the full gRPC method name of the Authorize RPC.
	// It matches committerpb.AuthService_Authorize_FullMethodName.
	AuthenticationResource = "/servicepb.AuthService/Authorize"

	// ReaderPolicy and WriterPolicy are the channel policy references used by the
	// default resource-to-policy map. They mirror Fabric's implicit-meta policies.
	ReaderPolicy = "/Channel/Application/Readers"
	// WriterPolicy is the channel policy reference for write access.
	WriterPolicy = "/Channel/Application/Writers"
)

// exemptMethods are gRPC methods that bypass ACL enforcement entirely: the Authorize
// RPC (which establishes the identity), and infrastructure services that are not
// application resources and must remain reachable without a bound identity (health
// probes have no way to Authorize, and reflection carries no channel semantics).
var exemptMethods = map[string]struct{}{
	AuthenticationResource:                                           {},
	"/grpc.health.v1.Health/Check":                                   {},
	"/grpc.health.v1.Health/Watch":                                   {},
	"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo":      {},
	"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo": {},
}

// isExemptMethod reports whether the given full gRPC method bypasses ACL enforcement.
func isExemptMethod(fullMethod string) bool {
	_, ok := exemptMethods[fullMethod]
	return ok
}

// DefaultACL maps gRPC methods to channel policy references. It is the fallback used
// when the channel configuration's ACLs section has no entry for a resource. It applies
// to the public-facing services (query, sidecar) that enforce MSP authentication.
//
// A method absent from both the channel config and this map is denied (fail-closed) by
// evaluatePolicy, so every exposed RPC must have an explicit entry here.
var DefaultACL = map[string]string{
	// QueryService RPCs (unary) — query service.
	"/committerpb.QueryService/BeginView":            ReaderPolicy,
	"/committerpb.QueryService/EndView":              ReaderPolicy,
	"/committerpb.QueryService/GetRows":              ReaderPolicy,
	"/committerpb.QueryService/GetTransactionStatus": ReaderPolicy,
	"/committerpb.QueryService/GetNamespacePolicies": ReaderPolicy,
	"/committerpb.QueryService/GetConfigTransaction": ReaderPolicy,

	// BlockQueryService RPCs (unary) — sidecar.
	"/committerpb.BlockQueryService/GetBlockchainInfo": ReaderPolicy,
	"/committerpb.BlockQueryService/GetBlockByNumber":  ReaderPolicy,
	"/committerpb.BlockQueryService/GetBlockByTxID":    ReaderPolicy,
	"/committerpb.BlockQueryService/GetTxByID":         ReaderPolicy,

	// Notifier RPCs (stream) — sidecar.
	"/committerpb.Notifier/OpenNotificationStream": ReaderPolicy,
	"/committerpb.Notifier/StreamAllTransactions":  ReaderPolicy,

	// Deliver RPCs (stream) — sidecar (Fabric peer.Deliver compatibility).
	// The gRPC service name is "protos.Deliver" (see fabric-protos-go-apiv2/peer).
	"/protos.Deliver/Deliver":                ReaderPolicy,
	"/protos.Deliver/DeliverFiltered":        ReaderPolicy,
	"/protos.Deliver/DeliverWithPrivateData": ReaderPolicy,
}
