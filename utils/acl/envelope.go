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

// authEnvelopeParams describes the authentication envelope to build.
type authEnvelopeParams struct {
	signer      identity.SignerSerializer
	channelID   string
	tlsCertHash []byte
	nonce       []byte
}

// buildAuthEnvelope creates the signed envelope the client presents to Authenticate: an empty-payload
// application message scoped to the channel, carrying the client's TLS certificate hash for the
// token's binding and the server-issued nonce in its SignatureHeader.
//
// It builds the envelope directly rather than calling protoutil.CreateSignedEnvelopeWithTLSBinding
// because that helper generates its own random nonce, and the whole point of the challenge is that
// the *server* chooses it. The signature covers the entire marshaled payload - which includes the
// SignatureHeader - so the nonce cannot be substituted without invalidating the signature, and the
// envelope can travel as a typed message because its payload is carried as opaque bytes.
func buildAuthEnvelope(params *authEnvelopeParams) (*common.Envelope, error) {
	creator, err := params.signer.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signing identity")
	}

	channelHeader := protoutil.MakeChannelHeader(common.HeaderType_MESSAGE, 0, params.channelID, 0)
	channelHeader.TlsCertHash = params.tlsCertHash
	signatureHeader := protoutil.MakeSignatureHeader(creator, params.nonce)

	// Data is deliberately left empty: an authentication envelope carries no application data, and
	// that emptiness is what distinguishes it from a replayed transaction sharing this header type.
	payloadBytes, err := proto.Marshal(&common.Payload{
		Header: protoutil.MakePayloadHeader(channelHeader, signatureHeader),
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal authentication payload")
	}

	signature, err := params.signer.Sign(payloadBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign authentication envelope")
	}
	return &common.Envelope{Payload: payloadBytes, Signature: signature}, nil
}
