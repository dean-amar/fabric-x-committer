/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

// MetadataEnvelopeKey is the gRPC metadata key carrying the signed authentication
// envelope. The "-bin" suffix makes gRPC base64-encode the raw bytes on the wire and
// decode them on the server automatically.
const MetadataEnvelopeKey = "fabric-auth-envelope-bin"

const (
	// ReaderPolicy and WriterPolicy mirror Fabric's implicit-meta channel policies.
	ReaderPolicy = "/Channel/Application/Readers"
	// WriterPolicy is the channel policy reference for write access.
	WriterPolicy = "/Channel/Application/Writers"
)

// exemptMethods bypass ACL enforcement entirely: infrastructure services that are not
// application resources and must remain reachable without an envelope.
var exemptMethods = map[string]struct{}{
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

// DefaultACL maps gRPC methods to channel policy references, used when the channel
// configuration's ACLs section has no entry for a resource. A method absent from both the
// channel config and this map is denied (fail-closed). It also enumerates exactly the set
// of methods a client may bind into an envelope.
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
	"/protos.Deliver/Deliver":                ReaderPolicy,
	"/protos.Deliver/DeliverFiltered":        ReaderPolicy,
	"/protos.Deliver/DeliverWithPrivateData": ReaderPolicy,
}
