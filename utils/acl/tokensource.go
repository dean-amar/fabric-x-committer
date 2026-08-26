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
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
)

// tokenRefreshSkew re-authenticates this long before a token actually expires, so an RPC never
// carries a token that lapses between the client attaching it and the resource server checking it.
const tokenRefreshSkew = 30 * time.Second

// TokenSourceConfig configures a TokenSource.
type TokenSourceConfig struct {
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
	// RequireTransportSecurity reports whether the token may travel only over a secure transport.
	RequireTransportSecurity bool
	// Scope optionally requests a least-privilege token limited to these resources.
	Scope []string
}

// TokenSource authenticates once against the AuthService and caches the resulting cert-bound token,
// re-authenticating shortly before it expires. It implements credentials.PerRPCCredentials, so
// attaching it to a client connection injects the token into every RPC's metadata - the client pays
// the signature-verification cost once, not on every call.
type TokenSource struct {
	cfg TokenSourceConfig

	mu        sync.Mutex
	token     string
	issuedAt  time.Time
	expiresAt time.Time
}

var _ credentials.PerRPCCredentials = (*TokenSource)(nil)

// NewTokenSource creates a TokenSource from the given configuration.
func NewTokenSource(cfg TokenSourceConfig) *TokenSource {
	return &TokenSource{cfg: cfg}
}

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
	return t.cfg.RequireTransportSecurity
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

	envelope, err := t.buildEnvelope()
	if err != nil {
		return "", err
	}
	resp, err := t.cfg.Client.Authenticate(ctx, &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
		RequestedScope: t.cfg.Scope,
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

// buildEnvelope creates a fresh signed authentication envelope carrying the client's TLS cert hash.
func (t *TokenSource) buildEnvelope() ([]byte, error) {
	envelope, err := protoutil.CreateSignedEnvelopeWithTLSBinding(
		common.HeaderType_MESSAGE, t.cfg.ChannelID, t.cfg.Signer, &emptypb.Empty{}, 0, 0, t.cfg.TLSCertHash,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build authentication envelope")
	}
	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal authentication envelope")
	}
	return envelopeBytes, nil
}
