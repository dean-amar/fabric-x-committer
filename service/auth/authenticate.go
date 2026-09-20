/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"context"
	"crypto/rand"
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

// authEnvelopeType is the header type an authentication envelope carries. Ordinary transactions use it
// too, so it is domain separation, not replay protection - the single-use nonce is what stops replay.
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
	// ErrNoEnvelope is returned when the request carries no signed envelope at all.
	ErrNoEnvelope = errors.New("signed envelope is required")
)

type (
	// authenticator verifies signed envelopes and issues cert-bound tokens. No constructor: its single
	// caller supplies every field, so a keyed literal says the same without a second type to maintain.
	authenticator struct {
		signer                  *tokenSigner
		tokens                  *tokenStore
		nonces                  *nonceStore
		envelopeFreshnessWindow time.Duration
		tokenTTL                time.Duration
	}

	// parsedEnvelope holds the pieces verifyEnvelope inspects. payloadData is empty for a genuine
	// authentication envelope; nonce is what the client claims from the SignatureHeader.
	parsedEnvelope struct {
		chdr        *common.ChannelHeader
		payloadData []byte
		nonce       []byte
		signedData  *protoutil.SignedData
	}

	// verifiedIdentity is the outcome of authenticating an envelope. certHash is nil when the client
	// connected without a certificate.
	verifiedIdentity struct {
		identity *msppb.Identity
		mspID    string
		certHash []byte
	}
)

// authenticate verifies the envelope, persists the token-to-identity binding and returns a fresh
// cert-bound token. Unauthenticated when the envelope is invalid, Internal when signing or storing fails.
func (a *authenticator) authenticate(
	ctx context.Context, authRequest *servicepb.AuthenticateRequest, bundle *channelconfig.Bundle,
) (*servicepb.AuthenticateResponse, error) {
	signedEnvelope := authRequest.GetSignedEnvelope()
	if signedEnvelope == nil {
		return nil, grpcerror.WrapInvalidArgument(ErrNoEnvelope)
	}

	now := time.Now()
	parsedSignedEnvelope, err := parseSignedEnvelope(signedEnvelope)
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(
			errors.Newf("authentication failed: %v", err),
		)
	}

	// Redeem before verifying the signature: a spent nonce is a replay however well signed, and redeeming
	// first stops a replayer from making the service repeat the expensive signature check.
	if err = a.nonces.consume(ctx, parsedSignedEnvelope.nonce, now); err != nil {
		return nil, grpcerror.WrapUnauthenticated(
			errors.Newf("authentication failed: %v", err),
		)
	}

	identity, err := a.verifyEnvelope(ctx, parsedSignedEnvelope, bundle, now)
	if err != nil {
		return nil, grpcerror.WrapUnauthenticated(errors.Newf("authentication failed: %v", err))
	}

	jti, err := newTokenID()
	if err != nil {
		return nil, grpcerror.WrapInternalError(errors.Wrapf(err, "failed to generate token id"))
	}
	rec := &servicepb.TokenRecord{
		Jti:            jti,
		Identity:       identity.identity,
		MspId:          identity.mspID,
		CertHashSha256: identity.certHash,
		Scope:          normalizeScope(authRequest.GetRequestedScope()),
		IssuedSequence: bundle.ConfigtxValidator().Sequence(),
		ExpiresAt:      now.Add(a.tokenTTL).Unix(),
	}

	// Mint before persisting: if persistence fails the client never receives the token, so no orphan
	// binding is left behind.
	token, err := a.signer.mint(rec, now)
	if err != nil {
		return nil, grpcerror.WrapInternalError(errors.Wrapf(err, "failed to mint token"))
	}
	if err = a.tokens.put(ctx, rec); err != nil {
		return nil, grpcerror.WrapInternalError(err)
	}

	logger.Infof("Issued token jti=%s mspID=%s scope=%v seq=%d",
		jti, rec.GetMspId(), rec.GetScope(), rec.GetIssuedSequence())

	return &servicepb.AuthenticateResponse{
		Token:     token,
		ExpiresAt: rec.GetExpiresAt(),
	}, nil
}

// verifyEnvelope checks scoping, freshness, certificate binding, MSP resolution and the signature, then
// returns the identity. Redeeming the nonce stays in authenticate: it is the one stateful step.
func (a *authenticator) verifyEnvelope(
	ctx context.Context, parsed *parsedEnvelope, bundle *channelconfig.Bundle, now time.Time,
) (*verifiedIdentity, error) {
	chdr, signedData := parsed.chdr, parsed.signedData
	var err error

	// The nonce stops replay; these checks are domain separation, and only the empty payload separates:
	// a submitter that signs a caller's tx with a caller-chosen nonce always fills Data, so cannot mint.
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

	if err = validateTimestamp(chdr.GetTimestamp(), a.envelopeFreshnessWindow, now); err != nil {
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

	return &verifiedIdentity{
		identity: signedData.Identity,
		mspID:    identity.GetMSPIdentifier(),
		certHash: certHash,
	}, nil
}

// parseSignedEnvelope unpacks the envelope into the pieces verifyEnvelope inspects. The nonce comes from
// the SignatureHeader, which the signature covers, so a replayer cannot swap in a fresh one.
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
	// if protoutil.EnvelopeAsSignedData didn't fail, the signedData is a slice of length 1.
	signedData, err := protoutil.EnvelopeAsSignedData(env)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract signed data from envelope")
	}
	return &parsedEnvelope{
		chdr:        chdr,
		payloadData: payload.Data,
		nonce:       shdr.GetNonce(),
		signedData:  signedData[0],
	}, nil
}

// verifyCertBinding checks the claimed hash against the certificate on the connection and returns the hash
// the token binds to. Without a client certificate the transport's TLS mode is the boundary.
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

// validateTimestamp rejects a missing, unrepresentable or out-of-window timestamp. It compares signed
// bounds directly, so a far-future timestamp cannot overflow the arithmetic and be accepted forever.
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
