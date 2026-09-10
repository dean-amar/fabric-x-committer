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

// TestVerifyEnvelopeRejects covers every way a well-formed envelope can still fail verification. The
// transaction-shaped case is the notable one: it shares a real transaction's header type and channel and
// differs only by carrying application payload, which is what stops a committed transaction from being
// replayed to mint a token in its signer's name.
func TestVerifyEnvelopeRejects(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	for _, tc := range []struct {
		name string
		// certBound runs the case on a connection that presents a client certificate.
		certBound bool
		envelope  *common.Envelope
		now       time.Time
		wantErr   error
	}{
		{
			name:     "timestamp outside the freshness window",
			envelope: env.signedEnvelope(t, nil),
			now:      time.Now().Add(time.Hour),
			wantErr:  ErrStaleEnvelope,
		},
		{
			name:      "claimed certificate hash does not match the connection",
			certBound: true,
			envelope:  env.signedEnvelope(t, []byte{0xDE, 0xAD}),
			now:       time.Now(),
			wantErr:   ErrCertBindingMismatch,
		},
		{
			name:     "envelope is scoped to another channel",
			envelope: env.signedEnvelopeFor(t, common.HeaderType_MESSAGE, "other-channel", nil),
			now:      time.Now(),
			wantErr:  ErrEnvelopeScope,
		},
		{
			name:     "header type is not an authentication request",
			envelope: env.signedEnvelopeFor(t, common.HeaderType_ENDORSER_TRANSACTION, testChannelID, nil),
			now:      time.Now(),
			wantErr:  ErrEnvelopeScope,
		},
		{
			name: "transaction-shaped envelope carries application payload",
			envelope: env.signedEnvelopeWithPayload(
				t, common.HeaderType_MESSAGE, testChannelID, wrapperspb.String("transaction-body"),
			),
			now:     time.Now(),
			wantErr: ErrEnvelopeScope,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			if tc.certBound {
				ctx, _ = peerContextWithCert(t)
			}
			_, err := testVerifier().verifyEnvelope(ctx, mustParse(t, tc.envelope), env.bundle, tc.now)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestVerifyEnvelopeRejectsForeignIdentity needs a second, independent crypto set, so it cannot share
// the table above: the envelope is perfectly well-formed and signed, and fails only because the identity
// resolves against no MSP in this channel's configuration.
func TestVerifyEnvelopeRejectsForeignIdentity(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	foreign := newAuthTestEnv(t)

	_, err := testVerifier().verifyEnvelope(
		context.Background(), mustParse(t, foreign.signedEnvelope(t, nil)), env.bundle, time.Now(),
	)
	require.ErrorContains(t, err, "failed to deserialize identity")
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
