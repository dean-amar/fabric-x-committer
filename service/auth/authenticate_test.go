/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// testVerifier is an authenticator with only the freshness window set - enough to exercise
// verifyEnvelope without a signer or store.
func testVerifier() *authenticator {
	return &authenticator{freshnessWindow: time.Minute}
}

func TestVerifyEnvelopeSuccess(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	t.Run("no client certificate yields an unbound identity", func(t *testing.T) {
		t.Parallel()
		id, err := testVerifier().verifyEnvelope(
			context.Background(), mustParse(t, env.signedEnvelope(t, nil)), env.bundle, time.Now(),
		)
		require.NoError(t, err)
		require.NotNil(t, id.identity)
		require.NotEmpty(t, id.mspID)
		require.Nil(t, id.certHash)
	})

	t.Run("client certificate binds the identity", func(t *testing.T) {
		t.Parallel()
		ctx, certHash := peerContextWithCert(t)
		id, err := testVerifier().verifyEnvelope(
			ctx, mustParse(t, env.signedEnvelope(t, certHash)), env.bundle, time.Now(),
		)
		require.NoError(t, err)
		require.Equal(t, certHash, id.certHash)
	})
}

func TestVerifyEnvelopeRejectsStaleAndMismatch(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	// Stale: the envelope is stamped ~now, so validating an hour ahead makes it stale.
	_, err := testVerifier().verifyEnvelope(
		context.Background(), mustParse(t, env.signedEnvelope(t, nil)), env.bundle, time.Now().Add(time.Hour),
	)
	require.ErrorIs(t, err, ErrStaleEnvelope)

	// Certificate binding mismatch: the envelope is bound to a different hash than the connection's.
	ctx, _ := peerContextWithCert(t)
	_, err = testVerifier().verifyEnvelope(
		ctx, mustParse(t, env.signedEnvelope(t, []byte{0xDE, 0xAD})), env.bundle, time.Now(),
	)
	require.ErrorIs(t, err, ErrCertBindingMismatch)
}

func TestVerifyEnvelopeRejectsWrongScope(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	// An envelope for a different channel is rejected.
	wrongChannel := env.signedEnvelopeFor(t, common.HeaderType_MESSAGE, "other-channel", nil)
	_, err := testVerifier().verifyEnvelope(context.Background(), mustParse(t, wrongChannel), env.bundle, time.Now())
	require.ErrorIs(t, err, ErrEnvelopeScope)

	// An envelope with a non-authentication header type is rejected, even for the right channel.
	wrongType := env.signedEnvelopeFor(t, common.HeaderType_ENDORSER_TRANSACTION, testChannelID, nil)
	_, err = testVerifier().verifyEnvelope(context.Background(), mustParse(t, wrongType), env.bundle, time.Now())
	require.ErrorIs(t, err, ErrEnvelopeScope)

	// A transaction-shaped envelope - the same header type and channel a real transaction uses, but
	// carrying a non-empty application payload - must be rejected. Any channel reader can observe a
	// committed transaction, so accepting one here would let it be replayed to mint a token in its
	// signer's name.
	txShaped := env.signedEnvelopeWithPayload(
		t, common.HeaderType_MESSAGE, testChannelID, wrapperspb.String("transaction-body"),
	)
	_, err = testVerifier().verifyEnvelope(context.Background(), mustParse(t, txShaped), env.bundle, time.Now())
	require.ErrorIs(t, err, ErrEnvelopeScope)
}

func TestVerifyEnvelopeRejectsForeignIdentity(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	foreign := newAuthTestEnv(t) // a different crypto set, so its identity is not in env's MSP

	// A foreign identity is well-formed, so it parses; it fails when resolved against this MSP manager.
	_, err := testVerifier().verifyEnvelope(
		context.Background(), mustParse(t, foreign.signedEnvelope(t, nil)), env.bundle, time.Now(),
	)
	require.Error(t, err)
}

// TestParseSignedEnvelopeRejectsMalformed covers the layer below verifyEnvelope. The envelope arrives as
// a typed message, so malformed framing is the transport's problem; what parsing must still reject is a
// well-framed envelope whose inner payload is unusable.
func TestParseSignedEnvelopeRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		envelope *common.Envelope
	}{
		{name: "payload is not a marshaled Payload", envelope: &common.Envelope{Payload: []byte("garbage")}},
		{name: "payload has no header", envelope: &common.Envelope{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseSignedEnvelope(tc.envelope)
			require.Error(t, err)
		})
	}
}

// mustParse parses a signed envelope, as authenticate does before handing it to verifyEnvelope.
func mustParse(t *testing.T, envelope *common.Envelope) *parsedEnvelope {
	t.Helper()
	parsed, err := parseSignedEnvelope(envelope)
	require.NoError(t, err)
	return parsed
}

func TestValidateTimestamp(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	window := time.Minute

	for _, tc := range []struct {
		name string
		ts   *timestamppb.Timestamp
		ok   bool
	}{
		{name: "now is fresh", ts: timestamppb.New(now), ok: true},
		{name: "within window past", ts: timestamppb.New(now.Add(-30 * time.Second)), ok: true},
		{name: "within window future", ts: timestamppb.New(now.Add(30 * time.Second)), ok: true},
		{name: "just outside past", ts: timestamppb.New(now.Add(-2 * time.Minute)), ok: false},
		{name: "just outside future", ts: timestamppb.New(now.Add(2 * time.Minute)), ok: false},
		{name: "nil timestamp", ts: nil, ok: false},
		// Regression: a far-future timestamp must be rejected, not accepted forever due to signed
		// duration overflow in an abs-difference comparison.
		{name: "far future does not overflow", ts: timestamppb.New(now.AddDate(300, 0, 0)), ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateTimestamp(tc.ts, window, now)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrStaleEnvelope)
		})
	}
}
