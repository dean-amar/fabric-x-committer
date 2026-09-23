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
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

type (
	// Credentials attaches one already-minted token to every RPC and never re-authenticates, so a client
	// that must outlive its token requests a lifetime covering its whole run.
	Credentials struct {
		// Token is the encoded JWT sent as authorization metadata.
		Token string
	}

	// AuthEnvelopeParams describes the authentication envelope to build.
	AuthEnvelopeParams struct {
		CommonParams
		// Nonce is the single-use challenge obtained from IssueNonce.
		Nonce []byte
	}

	// MintParams describes the token MintToken should obtain.
	MintParams struct {
		CommonParams
		// Client authenticates against the AuthService.
		Client servicepb.AuthServiceClient
		// Scope optionally requests a least-privilege token limited to these resources.
		Scope []string
	}

	// CommonParams is the identity material shared by minting a token and building the envelope it is
	// minted from, so the two cannot drift apart.
	CommonParams struct {
		// Signer is the client's MSP signing identity; it signs the envelope.
		Signer identity.SignerSerializer
		// ChannelID is the channel the envelope is scoped to.
		ChannelID string
		// TLSCertHash is the SHA-256 of the client's TLS certificate, or nil without mutual TLS.
		TLSCertHash []byte
	}
)

// TLSCertHash returns the SHA-256 of the certificate tlsConfig presents, for MintParams.TLSCertHash. It is
// nil unless the mode is mutual TLS: only then does the connection carry a certificate to bind a token to.
func TLSCertHash(tlsConfig connection.TLSConfig) ([]byte, error) {
	creds, err := connection.NewClientTLSCredentials(tlsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load the client TLS credentials")
	}
	if creds.Mode != connection.MutualTLSMode {
		return nil, nil
	}
	hash, err := protoutil.HashTLSCertificate(creds.Cert)
	return hash, errors.Wrap(err, "failed to hash the client certificate")
}

// MintToken runs the whole client side of authentication: fetch a nonce, sign it into an envelope, exchange
// it for a cert-bound token. Failure surfaces here rather than inside an unrelated RPC.
func MintToken(ctx context.Context, params *MintParams) (*Credentials, error) {
	// A nonce is fetched per attempt rather than cached: it is valid for exactly one Authenticate call,
	// so there is nothing to reuse.
	nonce, err := params.Client.IssueNonce(ctx, &servicepb.IssueNonceRequest{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain an authentication nonce")
	}
	envelope, err := BuildAuthEnvelope(&AuthEnvelopeParams{
		CommonParams: params.CommonParams,
		Nonce:        nonce.GetNonce(),
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
		Token: resp.GetToken(),
	}, nil
}

// BuildAuthEnvelope builds the envelope Authenticate expects: empty payload, channel-scoped, cert hash,
// server-issued nonce. protoutil's helper picks its own nonce, which would defeat the challenge.
func BuildAuthEnvelope(params *AuthEnvelopeParams) (*common.Envelope, error) {
	creator, err := params.Signer.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signing identity")
	}

	channelHeader := protoutil.MakeChannelHeader(common.HeaderType_MESSAGE, 0, params.ChannelID, 0)
	channelHeader.TlsCertHash = params.TLSCertHash
	signatureHeader := protoutil.MakeSignatureHeader(creator, params.Nonce)

	// Data is deliberately empty: a transaction-shaped signer cannot produce that shape, which is the
	// domain separation the AuthService checks. Replay itself is stopped by the nonce.
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
