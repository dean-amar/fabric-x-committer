package auth

const (
	AuthenticationResource = "/servicepb.AuthService/Authorize"

	ReaderPolicy = "/Channel/Application/Readers"
	WriterPolicy = "/Channel/Application/Writers"
)

// DefaultACL maps gRPC methods to channel policy resources.
// This applies to public-facing services (query, sidecar) that enforce MSP authentication.
var DefaultACL = map[string]string{
	// QueryService RPCs (Unary)
	"/committerpb.QueryService/BeginView":            ReaderPolicy,
	"/committerpb.QueryService/EndView":              ReaderPolicy,
	"/committerpb.QueryService/GetRows":              ReaderPolicy,
	"/committerpb.QueryService/GetTransactionStatus": ReaderPolicy,
	"/committerpb.QueryService/GetNamespacePolicies": ReaderPolicy,

	// BlockQueryService RPCs (Unary) - Sidecar
	"/committerpb.BlockQueryService/GetBlockchainInfo": ReaderPolicy,
	"/committerpb.BlockQueryService/GetBlockByNumber":  ReaderPolicy,

	// NotifierService RPCs (Stream) - Sidecar
	"/committerpb.Notifier/OpenNotificationStream": ReaderPolicy,

	// DeliverService RPCs (Stream) - Sidecar (Fabric peer.Deliver compatibility)
	"/peer.Deliver/Deliver":                ReaderPolicy,
	"/peer.Deliver/DeliverFiltered":        ReaderPolicy,
	"/peer.Deliver/DeliverWithPrivateData": ReaderPolicy,
}
