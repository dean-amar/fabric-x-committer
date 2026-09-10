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
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

// tokenRefreshSkew re-authenticates this long before a token actually expires, so an RPC never
// carries a token that lapses between the client attaching it and the resource server checking it.
const tokenRefreshSkew = 30 * time.Second

type (
	// TokenSource hides the whole client side of authentication behind gRPC's per-RPC credentials: a
	// caller attaches it with grpc.WithPerRPCCredentials and then makes ordinary RPCs. On the first call it
	// fetches a nonce, signs it into an envelope, exchanges that for a cert-bound token, and attaches the
	// token to every RPC, re-authenticating shortly before the token expires - so the client pays the
	// signature-verification cost once, not on every call, and never handles a nonce or envelope itself.
	//
	// It is usable from a struct literal; every field below is set by the caller, and the cached token
	// beneath them is this type's own state.
	TokenSource struct {
		// Client authenticates against the AuthService.
		Client servicepb.AuthServiceClient
		// Signer is the client's MSP signing identity; it signs the authentication envelope.
		Signer identity.SignerSerializer
		// ChannelID is the channel the authentication envelope is scoped to.
		ChannelID string
		// TLSCertHash is the SHA-256 of the client's own TLS certificate, bound into the token. It must
		// equal the hash the AuthService computes from the certificate the client presents on its
		// connection, or authorization will fail the certificate-binding check.
		TLSCertHash []byte
		// SecureTransportOnly reports whether the token may travel only over a secure transport; it is
		// what the credentials interface's RequireTransportSecurity returns.
		SecureTransportOnly bool
		// Scope optionally requests a least-privilege token limited to these resources.
		Scope []string

		mu        sync.Mutex
		token     string
		issuedAt  time.Time
		expiresAt time.Time
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
)

var _ credentials.PerRPCCredentials = (*TokenSource)(nil)

// GetRequestMetadata returns the authorization metadata for an RPC, authenticating or refreshing the
// token as needed. It satisfies credentials.PerRPCCredentials.
func (t *TokenSource) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := t.currentToken(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{TokenMetadataKey: token}, nil
}

// RequireTransportSecurity satisfies credentials.PerRPCCredentials.
func (t *TokenSource) RequireTransportSecurity() bool {
	return t.SecureTransportOnly
}

// currentToken returns a valid token, re-authenticating when none is cached or the cached one is
// within the refresh skew of expiry. If re-authentication fails while a cached token is still
// genuinely valid (within the skew, but not yet expired), it falls back to the cached token so a
// brief auth-service outage does not fail RPCs that a usable token could still serve.
//
// The mutex is not held across the network Authenticate call: the hot path (a still-fresh cached
// token) takes only a brief lock, so a slow refresh never serializes unrelated RPCs behind it. Two
// concurrent refreshes are possible but harmless - the second simply overwrites with an equally
// valid token.
func (t *TokenSource) currentToken(ctx context.Context) (string, error) {
	now := time.Now()

	t.mu.Lock()
	cachedToken, cachedExpiry := t.token, t.expiresAt
	if cachedToken != "" && now.Before(t.refreshDeadline()) {
		t.mu.Unlock()
		return cachedToken, nil
	}
	t.mu.Unlock()

	// A nonce is fetched per attempt rather than cached: it is valid for exactly one Authenticate call,
	// so there is nothing to reuse.
	nonceResp, err := t.Client.IssueNonce(ctx, &servicepb.IssueNonceRequest{})
	if err != nil {
		return "", errors.Wrap(err, "failed to obtain an authentication nonce")
	}
	envelope, err := BuildAuthEnvelope(&AuthEnvelopeParams{
		Signer:      t.Signer,
		ChannelID:   t.ChannelID,
		TLSCertHash: t.TLSCertHash,
		Nonce:       nonceResp.GetNonce(),
	})
	if err != nil {
		return "", err
	}

	resp, err := t.Client.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
		RequestedScope: t.Scope,
	})
	if err != nil {
		if cachedToken != "" && now.Before(cachedExpiry) {
			return cachedToken, nil
		}
		return "", errors.Wrap(err, "failed to authenticate with the auth service")
	}

	t.mu.Lock()
	t.token = resp.GetToken()
	t.issuedAt = now
	t.expiresAt = time.Unix(resp.GetExpiresAt(), 0)
	token := t.token
	t.mu.Unlock()
	return token, nil
}

// refreshDeadline is the instant at which the cached token should be refreshed: tokenRefreshSkew
// before expiry, but never more than half the token's lifetime early, so a token whose TTL is
// shorter than the skew is still cached for roughly half its life instead of refreshed every call.
func (t *TokenSource) refreshDeadline() time.Time {
	skew := tokenRefreshSkew
	if lifetime := t.expiresAt.Sub(t.issuedAt); lifetime > 0 && skew > lifetime/2 {
		skew = lifetime / 2
	}
	return t.expiresAt.Add(-skew)
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
