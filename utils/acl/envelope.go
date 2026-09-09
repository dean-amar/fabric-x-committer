/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/protoutil/identity"
	"google.golang.org/protobuf/proto"
)

// AuthEnvelopeParams describes the authentication envelope to build.
type AuthEnvelopeParams struct {
	// Signer is the client's MSP signing identity; it signs the envelope.
	Signer identity.SignerSerializer
	// ChannelID is the channel the envelope is scoped to.
	ChannelID string
	// TLSCertHash is the SHA-256 of the client's TLS certificate, or nil without mutual TLS.
	TLSCertHash []byte
	// Nonce is the single-use challenge obtained from IssueNonce.
	Nonce []byte
}

// BuildAuthEnvelope creates the signed envelope a client presents to Authenticate: an empty-payload
// application message scoped to the channel, carrying the client's TLS certificate hash for the token's
// binding and the server-issued nonce in its SignatureHeader.
//
// TokenSource calls it as part of authenticating, and it is exported because it is the whole client
// side of the envelope contract: a caller that manages tokens itself, rather than through TokenSource,
// needs exactly this.
//
// It builds the envelope directly rather than calling protoutil.CreateSignedEnvelopeWithTLSBinding
// because that helper generates its own random nonce, and the whole point of the challenge is that
// the *server* chooses it. The signature covers the entire marshaled payload - which includes the
// SignatureHeader - so the nonce cannot be substituted without invalidating the signature, and the
// envelope can travel as a typed message because its payload is carried as opaque bytes.
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
