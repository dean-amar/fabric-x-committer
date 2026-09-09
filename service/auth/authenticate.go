/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/util"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
)

// authEnvelopeType is the channel-header type an authentication envelope carries. It is the general
// application-message type, which ordinary transactions also use, so the type alone does NOT
// distinguish an authentication request from a replayed transaction. The load-bearing anti-replay
// check is the empty-payload requirement in verifyEnvelope (an auth envelope carries no application
// data; every transaction does), backed by the freshness window and - under mutual TLS - the
// certificate binding, which makes a captured envelope useless to anyone but the original signer.
// The type and channel-id checks are only coarse pre-filters.
const authEnvelopeType = int32(common.HeaderType_MESSAGE)

var (
	// ErrStaleEnvelope is returned when an authentication envelope's timestamp is missing, invalid,
	// or outside the configured freshness window.
	ErrStaleEnvelope = errors.New("authentication envelope is stale")
	// ErrCertBindingMismatch is returned when the envelope's claimed TLS certificate hash does not
	// match the certificate presented on the connection.
	ErrCertBindingMismatch = errors.New("TLS certificate binding mismatch")
	// ErrEnvelopeScope is returned when an envelope is not scoped to authentication for this channel
	// (wrong header type or channel id).
	ErrEnvelopeScope = errors.New("envelope is not an authentication request for this channel")
)

// verifiedIdentity is the outcome of authenticating an envelope: the client's MSP identity
// (re-resolved against the latest configuration at authorization time), its MSP id, and the SHA-256 of
// its TLS certificate (nil when the client connected without a certificate).
type verifiedIdentity struct {
	identity *msppb.Identity
	mspID    string
	certHash []byte
}

// authenticator verifies signed envelopes and issues cert-bound tokens, persisting the resulting
// token-to-identity binding in the identity store. It has no constructor: every field is supplied by
// its single caller, so a keyed struct literal says the same thing without a second type to keep in
// step with this one.
type authenticator struct {
	signer          *tokenSigner
	store           *tokenStore
	nonces          *nonceStore
	freshnessWindow time.Duration
	tokenTTL        time.Duration
}

// authenticate verifies the signed envelope against the bundle, persists the token-to-identity
// binding, and returns a freshly minted cert-bound token. It returns gRPC status errors:
// Unauthenticated when the envelope is invalid, Internal when persistence or signing fails.
func (a *authenticator) authenticate(
	ctx context.Context, req *servicepb.AuthenticateRequest, bundle *channelconfig.Bundle,
) (*servicepb.AuthenticateResponse, error) {
	env := req.GetSignedEnvelope()
	if env == nil {
		return nil, grpcerror.WrapInvalidArgument(errors.New("signed envelope is required"))
	}

	now := time.Now()
	parsed, err := parseSignedEnvelope(env)
	if err != nil {
		logger.Warnf("Authentication failed: %v", err)
		return nil, grpcerror.WrapUnauthenticated(fmt.Errorf("authentication failed: %w", err))
	}

	// Redeem the nonce before verifying the signature: an envelope whose nonce is spent is a replay
	// however well it is signed, and redeeming first denies a replayer the ability to make the service
	// repeat the expensive signature check.
	if err = a.nonces.consume(ctx, parsed.nonce, now); err != nil {
		logger.Warnf("Authentication failed: %v", err)
		return nil, grpcerror.WrapUnauthenticated(fmt.Errorf("authentication failed: %w", err))
	}

	identity, err := a.verifyEnvelope(ctx, parsed, bundle, now)
	if err != nil {
		logger.Warnf("Authentication failed: %v", err)
		return nil, grpcerror.WrapUnauthenticated(fmt.Errorf("authentication failed: %w", err))
	}

	jti, err := newTokenID()
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, grpcerror.WrapInternalError(err)
	}
	rec := &servicepb.TokenRecord{
		Jti:            jti,
		Identity:       identity.identity,
		MspId:          identity.mspID,
		CertHashSha256: identity.certHash,
		Scope:          normalizeScope(req.GetRequestedScope()),
		Namespaces:     normalizeScope(req.GetRequestedNamespaces()),
		IssuedSequence: bundle.ConfigtxValidator().Sequence(),
		ExpiresAt:      now.Add(a.tokenTTL).Unix(),
	}

	// Mint before persisting: if persistence fails the client never receives the token, so no orphan
	// binding is left behind.
	token, err := a.signer.mint(rec, now)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, grpcerror.WrapInternalError(err)
	}
	if err = a.store.put(ctx, rec); err != nil {
		logger.Errorf("%+v", err)
		return nil, grpcerror.WrapInternalError(err)
	}

	logger.Infof("Issued token jti=%s mspID=%s scope=%v seq=%d",
		jti, rec.GetMspId(), rec.GetScope(), rec.GetIssuedSequence())
	return &servicepb.AuthenticateResponse{Token: token, ExpiresAt: rec.GetExpiresAt()}, nil
}

// verifyEnvelope verifies an already-parsed authentication envelope against the given bundle and
// returns the authenticated identity. It performs, in order: envelope scoping, timestamp freshness,
// TLS certificate binding, MSP identity resolution and validation, and signature verification -
// mirroring the envelope-processing steps the committer already uses for config envelopes.
//
// Redeeming the nonce is deliberately not part of this: that is the one stateful step, and keeping it
// in authenticate leaves this a pure check over an already-parsed envelope and the bundle. The envelope
// is parsed once, by the caller, because the caller needs the nonce out of it first.
func (a *authenticator) verifyEnvelope(
	ctx context.Context, parsed *parsedEnvelope, bundle *channelconfig.Bundle, now time.Time,
) (*verifiedIdentity, error) {
	chdr, signedData := parsed.chdr, parsed.signedData
	var err error

	// Scope the envelope to an authentication request for this channel, so an envelope the client
	// signed for another purpose cannot be exchanged for a token within the freshness window. The
	// empty-payload check is the load-bearing one: an authentication envelope carries no application
	// data, whereas every ordinary transaction - which shares this header type and channel - carries a
	// marshaled payload, so requiring an empty payload prevents replaying a committed transaction to
	// mint a token in its signer's name. The type and channel-id checks are coarse pre-filters.
	if chdr.GetType() != authEnvelopeType {
		return nil, errors.Wrapf(ErrEnvelopeScope, "unexpected header type %d", chdr.GetType())
	}
	if expected := bundle.ConfigtxValidator().ChannelID(); chdr.GetChannelId() != expected {
		return nil, errors.Wrapf(ErrEnvelopeScope, "channel %q does not match %q", chdr.GetChannelId(), expected)
	}
	if len(parsed.payloadData) != 0 {
		return nil, errors.Wrapf(ErrEnvelopeScope,
			"authentication envelope must carry an empty payload, got %d bytes", len(parsed.payloadData))
	}

	if err = validateTimestamp(chdr.GetTimestamp(), a.freshnessWindow, now); err != nil {
		return nil, err
	}

	certHash, err := verifyCertBinding(ctx, chdr.GetTlsCertHash())
	if err != nil {
		return nil, err
	}

	identity, err := bundle.MSPManager().DeserializeIdentity(signedData.Identity)
	if err != nil {
		return nil, errors.Wrap(err, "failed to deserialize identity")
	}
	if err = identity.Validate(); err != nil {
		return nil, errors.Wrap(err, "identity is not valid")
	}
	if err = identity.Verify(signedData.Data, signedData.Signature); err != nil {
		return nil, errors.Wrap(err, "signature verification failed")
	}

	// The identity travels on as the message the envelope carried. It is persisted in the token record
	// as a nested message, so nothing here has to serialize it by hand.
	return &verifiedIdentity{
		identity: signedData.Identity,
		mspID:    identity.GetMSPIdentifier(),
		certHash: certHash,
	}, nil
}

// verifyCertBinding checks the envelope's claimed TLS certificate hash against the certificate
// presented on the connection, returning the hash the token is bound to. When the client presented a
// certificate (mutual TLS), the claimed hash must match it. When none is present, the transport TLS
// mode is the security boundary and the token is not certificate-bound.
func verifyCertBinding(ctx context.Context, claimedHash []byte) ([]byte, error) {
	actualHash := util.ExtractCertificateHashFromContext(ctx)
	if len(actualHash) == 0 {
		return nil, nil //nolint:nilnil // an unbound token is the deliberate result without mutual TLS.
	}
	if !bytes.Equal(claimedHash, actualHash) {
		return nil, ErrCertBindingMismatch
	}
	return actualHash, nil
}

// parsedEnvelope holds the pieces of a signed envelope that verifyEnvelope inspects: the channel
// header, the application payload bytes (empty for a genuine authentication envelope), the nonce the
// client claims from the SignatureHeader, and the single signed-data unit (serialized identity,
// signed payload bytes, and signature).
type parsedEnvelope struct {
	chdr        *common.ChannelHeader
	payloadData []byte
	nonce       []byte
	signedData  *protoutil.SignedData
}

// parseSignedEnvelope unpacks an envelope into the pieces verifyEnvelope inspects. The nonce comes from
// the SignatureHeader, which the payload signature covers (the signature is over the whole marshaled
// payload), so a replayer cannot swap in a fresh nonce without invalidating the signature.
//
// The envelope arrives already parsed by gRPC, so only its inner payload is unmarshaled here. The
// signature still covers the exact bytes the client signed: Envelope.payload is itself a bytes field,
// so transporting the envelope as a typed message cannot alter them.
func parseSignedEnvelope(env *common.Envelope) (*parsedEnvelope, error) {
	payload, err := protoutil.UnmarshalPayload(env.Payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal payload")
	}
	if payload.Header == nil {
		return nil, errors.New("envelope payload has no header")
	}
	chdr, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal channel header")
	}
	shdr, err := protoutil.UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal signature header")
	}

	signedData, err := protoutil.EnvelopeAsSignedData(env)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract signed data from envelope")
	}
	if len(signedData) != 1 {
		return nil, errors.Newf("expected exactly one signed-data unit, got %d", len(signedData))
	}
	return &parsedEnvelope{
		chdr:        chdr,
		payloadData: payload.Data,
		nonce:       shdr.GetNonce(),
		signedData:  signedData[0],
	}, nil
}

// validateTimestamp rejects a timestamp that is missing, not representable, or further from now than
// the freshness window in either direction. It compares signed time bounds directly rather than an
// absolute duration difference, so a far-future timestamp cannot overflow the arithmetic and be
// accepted forever.
func validateTimestamp(ts *timestamppb.Timestamp, window time.Duration, now time.Time) error {
	if ts == nil {
		return errors.Wrap(ErrStaleEnvelope, "missing timestamp")
	}
	if err := ts.CheckValid(); err != nil {
		return errors.Wrapf(ErrStaleEnvelope, "invalid timestamp: %v", err)
	}

	t := ts.AsTime()
	if t.Before(now.Add(-window)) || t.After(now.Add(window)) {
		return errors.Wrapf(ErrStaleEnvelope,
			"timestamp %s is outside the freshness window of %s around %s", t, window, now)
	}
	return nil
}

// newTokenID generates a random, opaque token id (the jti claim and the store's row key).
func newTokenID() (string, error) {
	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate token id")
	}
	return id.String(), nil
}
