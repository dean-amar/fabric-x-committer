/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"crypto/sha256"
	"math"
	"testing"
	"time"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateTimestamp(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	window := DefaultEnvelopeFreshnessWindow

	// Success cases: timestamp within the symmetric freshness window.
	for _, tc := range []struct {
		name string
		ts   time.Time
	}{
		{name: "exactly now", ts: now},
		{name: "recent past within window", ts: now.Add(-window + time.Second)},
		{name: "near future within window (clock skew)", ts: now.Add(window - time.Second)},
		{name: "at past boundary", ts: now.Add(-window)},
		{name: "at future boundary", ts: now.Add(window)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, validateTimestamp(timestamppb.New(tc.ts), window, now))
		})
	}

	// Failure cases.
	for _, tc := range []struct {
		name    string
		ts      *timestamppb.Timestamp
		wantErr string
	}{
		{name: "nil timestamp rejected", ts: nil, wantErr: "missing a timestamp"},
		{
			name:    "too old",
			ts:      timestamppb.New(now.Add(-window - time.Second)),
			wantErr: "outside the freshness window",
		},
		{
			name:    "too far in the future",
			ts:      timestamppb.New(now.Add(window + time.Second)),
			wantErr: "outside the freshness window",
		},
		{
			// Regression: a pathological far-future timestamp must not overflow the skew math into
			// a negative value that slips past the window check. now.Sub(farFuture) saturates to
			// math.MinInt64, and negating that stays negative — so the old abs()-then-compare logic
			// accepted it. Such an out-of-range proto timestamp is now rejected up front by
			// CheckValid before any skew arithmetic runs.
			name:    "far-future overflow timestamp rejected",
			ts:      &timestamppb.Timestamp{Seconds: math.MaxInt64 / 2},
			wantErr: "invalid",
		},
		{
			// A proto timestamp at the int64 max is likewise out of the valid range (year 0001–9999).
			name:    "out-of-range proto timestamp rejected",
			ts:      &timestamppb.Timestamp{Seconds: math.MaxInt64},
			wantErr: "invalid",
		},
		{
			// A far-future timestamp that is still within the valid proto range must be rejected by
			// the freshness window itself (not CheckValid), exercising the direct-bounds comparison.
			name:    "in-range far-future timestamp rejected by window",
			ts:      timestamppb.New(now.Add(365 * 24 * time.Hour)),
			wantErr: "outside the freshness window",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorContains(t, validateTimestamp(tc.ts, window, now), tc.wantErr)
		})
	}
}

func TestVerifyTLSCertBinding(t *testing.T) {
	t.Parallel()
	hashA := []byte{0x01, 0x02, 0x03}
	hashB := []byte{0x0a, 0x0b, 0x0c}

	require.NoError(t, VerifyTLSCertBinding(hashA, hashA))

	for _, tc := range []struct {
		name       string
		envelope   []byte
		connection []byte
		wantErr    string
	}{
		{name: "empty envelope hash", envelope: nil, connection: hashA, wantErr: "envelope does not contain"},
		{name: "empty connection hash", envelope: hashA, connection: nil, wantErr: "connection does not have"},
		{name: "mismatch", envelope: hashA, connection: hashB, wantErr: "mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorContains(t, VerifyTLSCertBinding(tc.envelope, tc.connection), tc.wantErr)
		})
	}
}

func TestComputeTLSCertHash(t *testing.T) {
	t.Parallel()
	// Matches a plain SHA-256 over the DER bytes, is length 32, and differs for different input.
	der := []byte("some-der-bytes")
	want := sha256.Sum256(der)
	require.Equal(t, want[:], ComputeTLSCertHash(der))
	require.Len(t, ComputeTLSCertHash(der), 32) // SHA-256
	require.NotEqual(t, ComputeTLSCertHash(der), ComputeTLSCertHash([]byte("other")))
}

func TestExtractIdentityFromEnvelope(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 0)

	t.Run("valid envelope resolves identity and MSP ID", func(t *testing.T) {
		t.Parallel()
		identity, mspID, err := ExtractIdentityFromEnvelope(f.signedEnvelope(t, nil), bundle)
		require.NoError(t, err)
		require.NotNil(t, identity)
		require.Equal(t, f.mspID, mspID)
	})

	// Failure cases.
	for _, tc := range []struct {
		name     string
		envelope *cb.Envelope
		wantErr  string
	}{
		{name: "nil envelope", envelope: nil, wantErr: "nil envelope"},
		{
			name:     "malformed payload",
			envelope: &cb.Envelope{Payload: []byte("not-a-payload")},
			wantErr:  "unmarshal payload",
		},
		{name: "missing header", envelope: envelopeWithNilHeader(t), wantErr: "missing payload header"},
		{name: "empty creator", envelope: envelopeWithEmptyCreator(t), wantErr: "missing creator"},
		{
			name:     "tampered signature",
			envelope: envelopeWithTamperedSignature(t, f),
			wantErr:  "signature verification failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ExtractIdentityFromEnvelope(tc.envelope, bundle)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestValidateAuthEnvelope(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	bundle := f.bundleAt(t, 0)
	now := time.Now()
	certHash := []byte("client-cert-hash")

	window := DefaultEnvelopeFreshnessWindow

	t.Run("non-mTLS: fresh envelope passes without cert binding", func(t *testing.T) {
		t.Parallel()
		info := &MSPAuthInfo{} // no client certificate
		identity, mspID, err := ValidateAuthEnvelope(f.signedEnvelope(t, nil), bundle, info, window, now)
		require.NoError(t, err)
		require.NotNil(t, identity)
		require.Equal(t, f.mspID, mspID)
	})

	t.Run("mTLS: matching cert hash passes", func(t *testing.T) {
		t.Parallel()
		info := &MSPAuthInfo{TLSCertHash: certHash}
		_, _, err := ValidateAuthEnvelope(f.signedEnvelope(t, certHash), bundle, info, window, now)
		require.NoError(t, err)
	})

	// Failure cases.
	for _, tc := range []struct {
		name     string
		envelope *cb.Envelope
		authInfo *MSPAuthInfo
		wantErr  string
	}{
		{
			name:     "nil envelope",
			envelope: nil,
			authInfo: &MSPAuthInfo{},
			wantErr:  "nil envelope",
		},
		{
			name:     "stale timestamp rejected before crypto",
			envelope: f.envelopeWithTimestamp(t, nil, now.Add(-2*DefaultEnvelopeFreshnessWindow)),
			authInfo: &MSPAuthInfo{},
			wantErr:  "freshness window",
		},
		{
			name:     "mTLS: cert hash mismatch",
			envelope: f.signedEnvelope(t, []byte("some-other-hash")),
			authInfo: &MSPAuthInfo{TLSCertHash: certHash},
			wantErr:  "TLS cert-hash binding failed",
		},
		{
			name:     "mTLS: envelope missing cert hash",
			envelope: f.signedEnvelope(t, nil),
			authInfo: &MSPAuthInfo{TLSCertHash: certHash},
			wantErr:  "TLS cert-hash binding failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ValidateAuthEnvelope(tc.envelope, bundle, tc.authInfo, window, now)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// --- helpers -------------------------------------------------------------------------------

func envelopeWithNilHeader(t *testing.T) *cb.Envelope {
	t.Helper()
	return &cb.Envelope{Payload: protoutil.MarshalOrPanic(&cb.Payload{})}
}

func envelopeWithEmptyCreator(t *testing.T) *cb.Envelope {
	t.Helper()
	payload := &cb.Payload{
		Header: &cb.Header{
			ChannelHeader:   protoutil.MarshalOrPanic(&cb.ChannelHeader{}),
			SignatureHeader: protoutil.MarshalOrPanic(&cb.SignatureHeader{}), // no Creator
		},
	}
	return &cb.Envelope{Payload: protoutil.MarshalOrPanic(payload)}
}

func envelopeWithTamperedSignature(t *testing.T, f *bundleFixture) *cb.Envelope {
	t.Helper()
	tampered := cloneProto(t, f.signedEnvelope(t, nil))
	tampered.Signature = append([]byte{0x00}, tampered.Signature...)
	return tampered
}
