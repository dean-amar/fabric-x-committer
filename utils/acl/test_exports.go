/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"github.com/hyperledger/fabric-x-common/protoutil/identity"
)

// AuthEnvelopeParams describes an authentication envelope to build for a test.
type AuthEnvelopeParams struct {
	// Signer is the client's MSP signing identity.
	Signer identity.SignerSerializer
	// ChannelID is the channel the envelope is scoped to.
	ChannelID string
	// TLSCertHash is the SHA-256 of the client's TLS certificate, or nil without mutual TLS.
	TLSCertHash []byte
	// Nonce is the challenge to sign into the envelope's SignatureHeader. A test sets it to a nonce
	// obtained from GetNonce, to a value the server never issued, or to nil to omit it entirely.
	Nonce []byte
}

// BuildAuthEnvelopeForTest builds the signed envelope a client presents to Authenticate, with an
// explicit nonce. Production clients get this from TokenSource, which fetches the nonce itself; a test
// needs to choose the nonce so it can exercise a valid, absent, forged, or already-spent challenge.
func BuildAuthEnvelopeForTest(params *AuthEnvelopeParams) ([]byte, error) {
	return buildAuthEnvelope(&authEnvelopeParams{
		signer:      params.Signer,
		channelID:   params.ChannelID,
		tlsCertHash: params.TLSCertHash,
		nonce:       params.Nonce,
	})
}
