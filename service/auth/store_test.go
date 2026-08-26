/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

func TestTokenStorePutAndGet(t *testing.T) {
	t.Parallel()
	store := newTokenStoreForTest(t)
	rec := testRecord("jti-put-get", time.Now().Add(time.Hour))

	require.NoError(t, store.put(t.Context(), rec))

	// Cache hit.
	got, err := store.get(t.Context(), rec.GetJti())
	require.NoError(t, err)
	test.RequireProtoEqual(t, rec, got)

	// Read-through: clearing the cache forces a database read that repopulates it.
	store.cache.Clear()
	require.Equal(t, 0, store.size())
	got, err = store.get(t.Context(), rec.GetJti())
	require.NoError(t, err)
	test.RequireProtoEqual(t, rec, got)
	require.Equal(t, 1, store.size())
}

func TestTokenStoreGetNotFound(t *testing.T) {
	t.Parallel()
	store := newTokenStoreForTest(t)

	_, err := store.get(t.Context(), "does-not-exist")
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestTokenStoreDeleteRevokes(t *testing.T) {
	t.Parallel()
	store := newTokenStoreForTest(t)
	rec := testRecord("jti-delete", time.Now().Add(time.Hour))
	require.NoError(t, store.put(t.Context(), rec))

	require.NoError(t, store.delete(t.Context(), rec.GetJti()))

	// Gone from both the cache and the database (cache cleared to force a database read).
	store.cache.Clear()
	_, err := store.get(t.Context(), rec.GetJti())
	require.ErrorIs(t, err, ErrTokenNotFound)
}

func TestTokenStoreSweepRemovesExpired(t *testing.T) {
	t.Parallel()
	store := newTokenStoreForTest(t)
	now := time.Now()
	expired := testRecord("jti-expired", now.Add(-time.Hour))
	live := testRecord("jti-live", now.Add(time.Hour))
	require.NoError(t, store.put(t.Context(), expired))
	require.NoError(t, store.put(t.Context(), live))

	deleted, err := store.sweep(t.Context(), now)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	// The expired record is gone from cache and database; the live one remains.
	store.cache.Clear()
	_, err = store.get(t.Context(), expired.GetJti())
	require.ErrorIs(t, err, ErrTokenNotFound)
	got, err := store.get(t.Context(), live.GetJti())
	require.NoError(t, err)
	test.RequireProtoEqual(t, live, got)
}

func TestTokenStoreWarmCache(t *testing.T) {
	t.Parallel()
	writer := newTokenStoreForTest(t)
	now := time.Now()
	live1 := testRecord("jti-warm-1", now.Add(time.Hour))
	live2 := testRecord("jti-warm-2", now.Add(2*time.Hour))
	expired := testRecord("jti-warm-expired", now.Add(-time.Hour))
	for _, rec := range []*servicepb.TokenRecord{live1, live2, expired} {
		require.NoError(t, writer.put(t.Context(), rec))
	}

	// A fresh store sharing the same pool starts with an empty cache.
	reader := newTokenStore(writer.pool)
	require.Equal(t, 0, reader.size())

	loaded, err := reader.warmCache(t.Context(), now)
	require.NoError(t, err)
	require.Equal(t, 2, loaded) // only the two unexpired records
	require.Equal(t, 2, reader.size())

	got, err := reader.get(t.Context(), live1.GetJti())
	require.NoError(t, err)
	test.RequireProtoEqual(t, live1, got)
}
