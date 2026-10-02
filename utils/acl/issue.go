/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acl

import (
	"context"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/protoutil/identity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

type (
	// IssueParams describes the token IssueToken should obtain.
	IssueParams struct {
		EnvelopeParams
		// Client authenticates against the AuthService.
		Client servicepb.AuthServiceClient
		// Scope optionally requests a least-privilege token limited to these resources.
		Scope []string
	}

	// EnvelopeParams is the identity material an authentication envelope is built from.
	EnvelopeParams struct {
		Signer      identity.SignerSerializer
		ChannelID   string
		TLSCertHash []byte
	}

	// Credentials attaches a token to every RPC of a connection dialed with [grpc.WithPerRPCCredentials],
	// authenticating again once half of the current token's lifetime has passed. A stream is bound to the
	// token it opened with, so a stream that reconnects picks up a live token rather than retrying forever
	// with the one that expired.
	Credentials struct {
		Params *IssueParams

		// mu is held while authenticating, so concurrent RPCs wait for one new token rather than each
		// fetching their own.
		mu      sync.Mutex
		token   string
		renewAt time.Time
	}
)

// GetRequestMetadata implements [credentials.PerRPCCredentials].
func (c *Credentials) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if now := time.Now(); c.token == "" || !now.Before(c.renewAt) {
		resp, err := IssueToken(ctx, c.Params)
		if err != nil {
			return nil, err
		}
		c.token = resp.GetToken()
		c.renewAt = now.Add(time.Unix(resp.GetExpiresAt(), 0).Sub(now) / 2)
	}
	return map[string]string{TokenMetadataKey: c.token}, nil
}

// RequireTransportSecurity implements [credentials.PerRPCCredentials]. It does not insist on TLS: the
// connection's TLS mode is the operator's choice, and the token's binding follows from it.
func (*Credentials) RequireTransportSecurity() bool {
	return false
}

// IssueToken runs the whole client side of authentication: fetch a nonce, sign it into an envelope, exchange
// it for a cert-bound token.
func IssueToken(ctx context.Context, params *IssueParams) (*servicepb.AuthenticateResponse, error) {
	nonce, err := params.Client.IssueNonce(ctx, &servicepb.IssueNonceRequest{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain an authentication nonce")
	}
	envelope, err := BuildAuthEnvelope(&params.EnvelopeParams, nonce.GetNonce())
	if err != nil {
		return nil, err
	}

	resp, err := params.Client.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
		RequestedScope: params.Scope,
	})
	return resp, errors.Wrap(err, "failed to authenticate with the auth service")
}

// BuildAuthEnvelope builds the envelope Authenticate expects: channel-scoped, bound to the TLS certificate, and
// signed over the server-issued nonce. Its data is deliberately empty: a transaction always carries a payload,
// which is the domain separation the AuthService checks.
func BuildAuthEnvelope(params *EnvelopeParams, nonce []byte) (*common.Envelope, error) {
	creator, err := params.Signer.Serialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to serialize signing identity")
	}
	envelope, err := protoutil.CreateSignedEnvelopeWithSignatureHeader(&protoutil.SignedEnvelopeParameters{
		TxType:          common.HeaderType_MESSAGE,
		ChannelID:       params.ChannelID,
		Signer:          params.Signer,
		Data:            &emptypb.Empty{},
		TLSCertHash:     params.TLSCertHash,
		SignatureHeader: protoutil.MakeSignatureHeader(creator, nonce),
	})
	return envelope, errors.Wrap(err, "failed to build authentication envelope")
}

// TLSCertHash returns the SHA-256 of the certificate a client presents under tlsConfig, which is what a token
// is bound to. Only mutual TLS puts a client certificate on the connection, so any other mode returns nil.
func TLSCertHash(tlsConfig connection.TLSConfig) ([]byte, error) {
	creds, err := connection.NewClientTLSCredentials(tlsConfig)
	if err != nil {
		return nil, err
	}
	if creds.Mode != connection.MutualTLSMode {
		return nil, nil //nolint:nilnil // without a client certificate there is nothing to bind to.
	}
	hash, err := protoutil.HashTLSCertificate(creds.Cert)
	return hash, errors.Wrap(err, "failed to hash the client TLS certificate")
}

// ContextWithToken returns ctx carrying the token in the metadata key the enforcer reads, which is how a
// caller authorizes one RPC without binding a token to a whole connection.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, TokenMetadataKey, token)
}
