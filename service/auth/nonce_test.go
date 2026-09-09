/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

func TestNonceIssueAndConsume(t *testing.T) {
	t.Parallel()
	store := newNonceStoreForTest(t)
	now := time.Now()

	nonce, expiresAt, err := store.issue(t.Context(), now)
	require.NoError(t, err)
	require.Len(t, nonce, nonceLength)
	require.Equal(t, now.Add(time.Minute).Unix(), expiresAt.Unix())

	require.NoError(t, store.consume(t.Context(), nonce, now))
}

// TestNonceIsSingleUse is the property the whole challenge rests on: a nonce redeems exactly once, so
// a captured envelope carrying it is worthless to a replayer.
func TestNonceIsSingleUse(t *testing.T) {
	t.Parallel()
	store := newNonceStoreForTest(t)
	now := time.Now()

	nonce, _, err := store.issue(t.Context(), now)
	require.NoError(t, err)

	require.NoError(t, store.consume(t.Context(), nonce, now))
	require.ErrorIs(t, store.consume(t.Context(), nonce, now), ErrNonceNotFound)
}

// TestNonceIssuesDistinctValues guards against a nonce generator that repeats itself, which would let
// one client's spent challenge be reused by another.
func TestNonceIssuesDistinctValues(t *testing.T) {
	t.Parallel()
	store := newNonceStoreForTest(t)
	now := time.Now()

	seen := make(map[string]struct{})
	for range 20 {
		nonce, _, err := store.issue(t.Context(), now)
		require.NoError(t, err)
		_, duplicate := seen[string(nonce)]
		require.False(t, duplicate, "issued a duplicate nonce")
		seen[string(nonce)] = struct{}{}
	}
}

func TestNonceConsumeRejects(t *testing.T) {
	t.Parallel()
	store := newNonceStoreForTest(t)
	now := time.Now()

	issued, _, err := store.issue(t.Context(), now)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		nonce     []byte
		consumeAt time.Time
	}{
		{name: "never issued", nonce: []byte("invented-nonce-value"), consumeAt: now},
		{name: "empty", nonce: nil, consumeAt: now},
		// The nonce is genuine but redeemed after its TTL, so it is no longer acceptable.
		{name: "expired", nonce: issued, consumeAt: now.Add(2 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, store.consume(t.Context(), tc.nonce, tc.consumeAt), ErrNonceNotFound)
		})
	}
}

// TestNonceSweepRemovesExpired verifies unredeemed nonces do not accumulate: a client that asks for a
// challenge and never authenticates must not leave a row behind for ever.
func TestNonceSweepRemovesExpired(t *testing.T) {
	t.Parallel()
	store := newNonceStoreForTest(t)
	now := time.Now()

	fresh, _, err := store.issue(t.Context(), now)
	require.NoError(t, err)
	stale, _, err := store.issue(t.Context(), now.Add(-2*time.Minute))
	require.NoError(t, err)

	deleted, err := store.sweep(t.Context(), now)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	// The lapsed one is gone; the still-valid one is untouched and remains redeemable.
	require.ErrorIs(t, store.consume(t.Context(), stale, now), ErrNonceNotFound)
	require.NoError(t, store.consume(t.Context(), fresh, now))
}

// newNonceStoreForTest provisions a database and returns a nonce store whose table has been created,
// issuing nonces with the same one-minute TTL the service defaults to.
func newNonceStoreForTest(t *testing.T) *nonceStore {
	t.Helper()
	dbEnv := vc.NewDatabaseTestEnv(t)
	require.NoError(t, SetupTables(t.Context(), dbEnv.DBConf))

	pool, err := statedb.NewPool(t.Context(), dbEnv.DBConf)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return newNonceStore(pool, time.Minute)
}
