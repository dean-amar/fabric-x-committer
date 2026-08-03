/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"bytes"
	"crypto/sha256"
	"time"

	"github.com/cockroachdb/errors"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/msppb"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"google.golang.org/protobuf/proto"
)

// DefaultEnvelopeFreshnessWindow bounds how far an Authorize envelope's timestamp
// may be from the server's current time. It guards against replay of a captured
// envelope regardless of the TLS mode: a captured envelope goes stale once the
// window elapses. The window is symmetric to tolerate modest clock skew between
// client and server.
const DefaultEnvelopeFreshnessWindow = 5 * time.Minute

// ExtractIdentityFromEnvelope extracts and validates the MSP identity from a signed envelope,
// returning the deserialized identity and its MSP ID.
//
// This performs the cryptographic identity checks (deserialize, validate, verify signature)
// but NOT the replay-prevention checks (timestamp freshness, TLS cert-hash binding). Callers
// that own a connection context should use ValidateAuthEnvelope, which layers those on top.
//
//nolint:ireturn // msp.Identity is an interface by design.
func ExtractIdentityFromEnvelope(
	envelope *cb.Envelope,
	bundle *channelconfig.Bundle,
) (msp.Identity, string, error) {
	if envelope == nil {
		return nil, "", errors.New("nil envelope")
	}

	// 1. Unmarshal payload.
	payload, err := protoutil.UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal payload")
	}
	if payload.Header == nil {
		return nil, "", errors.New("missing payload header")
	}

	// 2. Extract signature header.
	signatureHeader, err := protoutil.UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal signature header")
	}
	if len(signatureHeader.Creator) == 0 {
		return nil, "", errors.New("missing creator in signature header")
	}

	// 3. Unmarshal the identity protobuf from Creator (msppb.Identity).
	identityProto := &msppb.Identity{}
	if err = proto.Unmarshal(signatureHeader.Creator, identityProto); err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal creator identity")
	}

	// 4. Deserialize the identity using the bundle's MSP manager.
	identity, err := bundle.MSPManager().DeserializeIdentity(identityProto)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to deserialize identity")
	}

	// 5. Validate the identity against the channel's MSP definitions.
	if err = identity.Validate(); err != nil {
		return nil, "", errors.Wrap(err, "identity validation failed")
	}

	// 6. Verify the signature over the payload.
	if err = identity.Verify(envelope.Payload, envelope.Signature); err != nil {
		return nil, "", errors.Wrap(err, "signature verification failed")
	}

	return identity, identityProto.GetMspId(), nil
}

// ValidateAuthEnvelope performs the full, replay-resistant validation of an Authorize
// envelope against a connection:
//
//  1. timestamp freshness (always) — a captured envelope goes stale after freshnessWindow;
//  2. TLS cert-hash binding (only when the connection is mutually authenticated) — the
//     envelope's claimed hash must equal the hash of the certificate presented on this
//     connection, so a captured envelope cannot be replayed from another connection;
//  3. the cryptographic identity checks performed by ExtractIdentityFromEnvelope.
//
// It returns the resolved identity and MSP ID on success. now is injected for testability.
//
//nolint:ireturn,revive // msp.Identity is an interface; argument-limit: window and now are distinct.
func ValidateAuthEnvelope(
	envelope *cb.Envelope,
	bundle *channelconfig.Bundle,
	authInfo *MSPAuthInfo,
	freshnessWindow time.Duration,
	now time.Time,
) (msp.Identity, string, error) {
	if envelope == nil {
		return nil, "", errors.New("nil envelope")
	}

	// Parse the channel header first so we can enforce freshness and binding before
	// spending effort on identity deserialization and signature verification.
	payload, err := protoutil.UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal payload")
	}
	if payload.Header == nil {
		return nil, "", errors.New("missing payload header")
	}
	channelHeader, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal channel header")
	}

	// 1. Freshness — guards replay independent of the TLS mode.
	if err = validateTimestamp(channelHeader.GetTimestamp().AsTime(), freshnessWindow, now); err != nil {
		return nil, "", err
	}

	// 2. TLS cert-hash binding — only meaningful under mTLS. When the connection is
	//    mutually authenticated we require the envelope to be bound to its certificate;
	//    without mTLS there is no certificate to bind to and freshness is the only guard.
	if authInfo.HasClientCertificate() {
		if err = VerifyTLSCertBinding(channelHeader.TlsCertHash, authInfo.TLSCertHash); err != nil {
			return nil, "", errors.Wrap(err, "TLS cert-hash binding failed")
		}
	}

	// 3. Cryptographic identity checks.
	return ExtractIdentityFromEnvelope(envelope, bundle)
}

// validateTimestamp checks that ts is within +/- window of now. A zero timestamp is
// rejected, since it carries no freshness information.
func validateTimestamp(ts time.Time, window time.Duration, now time.Time) error {
	if ts.IsZero() {
		return errors.New("envelope is missing a timestamp")
	}
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		return errors.Newf("envelope timestamp is outside the freshness window: skew=%s, window=%s",
			skew, window)
	}
	return nil
}

// VerifyTLSCertBinding verifies that the TLS cert hash claimed in the envelope matches
// the actual TLS certificate hash from the connection.
func VerifyTLSCertBinding(envelopeTLSCertHash, connectionTLSCertHash []byte) error {
	if len(envelopeTLSCertHash) == 0 {
		return errors.New("envelope does not contain a TLS cert hash")
	}
	if len(connectionTLSCertHash) == 0 {
		return errors.New("connection does not have a TLS certificate")
	}
	if !bytes.Equal(envelopeTLSCertHash, connectionTLSCertHash) {
		return errors.Newf("TLS cert hash mismatch: envelope=%x, connection=%x",
			envelopeTLSCertHash, connectionTLSCertHash)
	}
	return nil
}

// ComputeTLSCertHash computes the SHA-256 hash of a certificate's raw DER bytes.
func ComputeTLSCertHash(certRaw []byte) []byte {
	hash := sha256.Sum256(certRaw)
	return hash[:]
}
