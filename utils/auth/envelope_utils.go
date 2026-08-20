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
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DefaultEnvelopeFreshnessWindow bounds how far an envelope's timestamp may be from server
// time. A captured envelope goes stale once the window elapses, guarding replay regardless
// of TLS mode. Symmetric to tolerate modest client/server clock skew.
const DefaultEnvelopeFreshnessWindow = 5 * time.Minute

// BuildAuthEnvelope creates a signed, cert-bound, method-bound envelope for a single RPC.
// The target gRPC full method is carried in the signed Payload.Data (a wrapperspb.StringValue)
// so a captured envelope is usable only for the exact method it was signed for.
func BuildAuthEnvelope(
	signer msp.SigningIdentity, channelID, fullMethod string, tlsCertHash []byte,
) (*cb.Envelope, error) {
	env, err := protoutil.CreateSignedEnvelopeWithTLSBinding(
		cb.HeaderType_MESSAGE,
		channelID,
		signer,
		wrapperspb.String(fullMethod), // signed Payload.Data = bound method name
		0, 0,
		tlsCertHash,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signed auth envelope")
	}
	return env, nil
}

// ValidateAuthEnvelope performs full, replay-resistant validation of a per-request envelope:
//  1. timestamp freshness (always);
//  2. bound method equals expectedMethod;
//  3. TLS cert-hash binding (only when connCertHash is non-empty, i.e. under mTLS);
//  4. cryptographic identity checks (deserialize, validate, verify signature).
//
// Checks are ordered cheapest-first so a wrong-method or stale replay is rejected without
// spending a signature verification. now is injected for testability.
//
// The envelope, bundle, connection cert hash, expected method, freshness window, and clock are
// each independently required by the caller, hence the six parameters.
//
//nolint:ireturn,revive // msp.Identity is an interface by design; argument-limit: see comment above.
func ValidateAuthEnvelope(
	envelope *cb.Envelope,
	bundle *channelconfig.Bundle,
	connCertHash []byte,
	expectedMethod string,
	freshnessWindow time.Duration,
	now time.Time,
) (msp.Identity, string, error) {
	if envelope == nil {
		return nil, "", errors.New("nil envelope")
	}
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

	// 1. Freshness.
	if err = validateTimestamp(channelHeader.GetTimestamp(), freshnessWindow, now); err != nil {
		return nil, "", err
	}

	// 2. Method binding — the signed Payload.Data carries the intended method.
	if err = validateBoundMethod(payload.Data, expectedMethod); err != nil {
		return nil, "", err
	}

	// 3. TLS cert-hash binding — only under mTLS (connCertHash present).
	if len(connCertHash) > 0 {
		if err = verifyTLSCertBinding(channelHeader.TlsCertHash, connCertHash); err != nil {
			return nil, "", errors.Wrap(err, "TLS cert-hash binding failed")
		}
	}

	// 4. Cryptographic identity checks.
	return extractIdentityFromEnvelope(envelope, bundle)
}

// validateBoundMethod checks that the method bound in the signed payload equals the method
// actually being invoked.
func validateBoundMethod(payloadData []byte, expectedMethod string) error {
	bound := &wrapperspb.StringValue{}
	if err := proto.Unmarshal(payloadData, bound); err != nil {
		return errors.Wrap(err, "failed to unmarshal bound method from payload")
	}
	if bound.GetValue() != expectedMethod {
		return errors.Newf("envelope method mismatch: bound=%q, called=%q", bound.GetValue(), expectedMethod)
	}
	return nil
}

//nolint:ireturn // msp.Identity is an interface by design.
func extractIdentityFromEnvelope(
	envelope *cb.Envelope, bundle *channelconfig.Bundle,
) (msp.Identity, string, error) {
	payload, err := protoutil.UnmarshalPayload(envelope.Payload)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal payload")
	}
	signatureHeader, err := protoutil.UnmarshalSignatureHeader(payload.Header.SignatureHeader)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal signature header")
	}
	if len(signatureHeader.Creator) == 0 {
		return nil, "", errors.New("missing creator in signature header")
	}
	identityProto := &msppb.Identity{}
	if err = proto.Unmarshal(signatureHeader.Creator, identityProto); err != nil {
		return nil, "", errors.Wrap(err, "failed to unmarshal creator identity")
	}
	identity, err := bundle.MSPManager().DeserializeIdentity(identityProto)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to deserialize identity")
	}
	if err = identity.Validate(); err != nil {
		return nil, "", errors.Wrap(err, "identity validation failed")
	}
	if err = identity.Verify(envelope.Payload, envelope.Signature); err != nil {
		return nil, "", errors.Wrap(err, "signature verification failed")
	}
	return identity, identityProto.GetMspId(), nil
}

func validateTimestamp(ts *timestamppb.Timestamp, window time.Duration, now time.Time) error {
	if ts == nil {
		return errors.New("envelope is missing a timestamp")
	}
	if err := ts.CheckValid(); err != nil {
		return errors.Wrap(err, "envelope timestamp is invalid")
	}
	skew := now.Sub(ts.AsTime())
	if skew < -window || skew > window {
		return errors.Newf("envelope timestamp is outside the freshness window: skew=%s, window=%s", skew, window)
	}
	return nil
}

func verifyTLSCertBinding(envelopeTLSCertHash, connectionTLSCertHash []byte) error {
	if len(envelopeTLSCertHash) == 0 {
		return errors.New("envelope does not contain a TLS cert hash")
	}
	if !bytes.Equal(envelopeTLSCertHash, connectionTLSCertHash) {
		return errors.Newf("TLS cert hash mismatch: envelope=%x, connection=%x",
			envelopeTLSCertHash, connectionTLSCertHash)
	}
	return nil
}

// ComputeTLSCertHash returns the SHA-256 of a certificate's raw DER bytes.
func ComputeTLSCertHash(certRaw []byte) []byte {
	h := sha256.Sum256(certRaw)
	return h[:]
}
