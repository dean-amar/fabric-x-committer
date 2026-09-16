/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/protoutil/identity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

type (
	// Credentials attaches one already-minted token to every RPC, as gRPC per-RPC credentials. It holds
	// no auth-service client and never re-authenticates: the token is minted once by MintToken and used
	// unchanged until it expires, at which point the resource server rejects it and the caller mints a
	// new one. A client that must outlive its token therefore requests a lifetime that covers its run.
	Credentials struct {
		// Token is the encoded JWT sent as authorization metadata.
		Token string
		// SecureTransportOnly reports whether the token may travel only over a secure transport; it is
		// what the credentials interface's RequireTransportSecurity returns.
		SecureTransportOnly bool
	}

	// AuthEnvelopeParams describes the authentication envelope to build.
	AuthEnvelopeParams struct {
		// Signer is the client's MSP signing identity; it signs the envelope.
		Signer identity.SignerSerializer
		// ChannelID is the channel the envelope is scoped to.
		ChannelID string
		// TLSCertHash is the SHA-256 of the client's TLS certificate, or nil without mutual TLS.
		TLSCertHash []byte
		// Nonce is the single-use challenge obtained from IssueNonce.
		Nonce []byte
	}

	// MintParams describes the token MintToken should obtain.
	MintParams struct {
		// Client authenticates against the AuthService.
		Client servicepb.AuthServiceClient
		// Signer is the client's MSP signing identity; it signs the authentication envelope.
		Signer identity.SignerSerializer
		// ChannelID is the channel the authentication envelope is scoped to.
		ChannelID string
		// TLSCertHash is the SHA-256 of the client's own TLS certificate, bound into the token, or nil
		// without mutual TLS. It must equal the hash the AuthService computes from the certificate the
		// client presents on its connection, or authorization fails the certificate-binding check.
		TLSCertHash []byte
		// Scope optionally requests a least-privilege token limited to these resources.
		Scope []string
		// SecureTransportOnly is passed through to the returned Credentials.
		SecureTransportOnly bool
	}
)

var _ credentials.PerRPCCredentials = (*Credentials)(nil)

// MintToken performs the whole client side of authentication: it fetches a single-use nonce, signs it
// into an envelope, and exchanges that for a token bound to the client's certificate. It is the only
// way to obtain Credentials, so every caller pays the signature-verification cost exactly once,
// up front, where the failure is reported - rather than inside an unrelated RPC.
func MintToken(ctx context.Context, params *MintParams) (*Credentials, error) {
	// A nonce is fetched per attempt rather than cached: it is valid for exactly one Authenticate call,
	// so there is nothing to reuse.
	nonce, err := params.Client.IssueNonce(ctx, &servicepb.IssueNonceRequest{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain an authentication nonce")
	}
	envelope, err := BuildAuthEnvelope(&AuthEnvelopeParams{
		Signer:      params.Signer,
		ChannelID:   params.ChannelID,
		TLSCertHash: params.TLSCertHash,
		Nonce:       nonce.GetNonce(),
	})
	if err != nil {
		return nil, err
	}

	resp, err := params.Client.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
		RequestedScope: params.Scope,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to authenticate with the auth service")
	}
	return &Credentials{
		Token:               resp.GetToken(),
		SecureTransportOnly: params.SecureTransportOnly,
	}, nil
}

// GetRequestMetadata returns the token as authorization metadata. It satisfies
// credentials.PerRPCCredentials.
func (c *Credentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{TokenMetadataKey: c.Token}, nil
}

// RequireTransportSecurity satisfies credentials.PerRPCCredentials.
func (c *Credentials) RequireTransportSecurity() bool {
	return c.SecureTransportOnly
}

// BuildAuthEnvelope creates the signed envelope a client presents to Authenticate: an empty-payload
// application message scoped to the channel, carrying the client's TLS certificate hash for the token's
// binding and the server-issued nonce in its SignatureHeader.
//
// It is exported because it is the whole client side of the envelope contract: MintToken calls it for
// the normal path, and a caller that must present a deliberately malformed challenge - a missing or
// replayed nonce - needs exactly this and cannot go through MintToken.
//
// It builds the envelope directly rather than calling protoutil.CreateSignedEnvelopeWithTLSBinding
// because that helper generates its own random nonce, and the whole point of the challenge is that the
// *server* chooses it. The signature covers the entire marshaled payload - which includes the
// SignatureHeader - so the nonce cannot be substituted without invalidating the signature.
func BuildAuthEnvelope(params *AuthEnvelopeParams) (*common.Envelope, error) {
	creator, err := params.Signer.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signing identity")
	}

	channelHeader := protoutil.MakeChannelHeader(common.HeaderType_MESSAGE, 0, params.ChannelID, 0)
	channelHeader.TlsCertHash = params.TLSCertHash
	signatureHeader := protoutil.MakeSignatureHeader(creator, params.Nonce)

	// Data is deliberately left empty: an authentication envelope carries no application data, and
	// that emptiness is what distinguishes it from a replayed transaction sharing this header type.
	payloadBytes, err := proto.Marshal(&common.Payload{
		Header: protoutil.MakePayloadHeader(channelHeader, signatureHeader),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal authentication payload")
	}

	signature, err := params.Signer.Sign(payloadBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign authentication envelope")
	}
	return &common.Envelope{Payload: payloadBytes, Signature: signature}, nil
}
