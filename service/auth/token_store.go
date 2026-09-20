/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/yugabyte/pgx/v5"
	"github.com/yugabyte/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils"
)

// ErrTokenNotFound is returned when a token record is absent from the store, meaning the token was
// never issued by this deployment or has expired and been swept.
var ErrTokenNotFound = errors.New("token record not found")

// tokenStore maps a token id to the identity it stands for, in the database so any instance can resolve
// any token, behind a read-through cache bounded by the token's own expiry. Tokens are not revocable.
type tokenStore struct {
	pool *pgxpool.Pool
	// cache is held by value: SyncMap is usable at its zero value, so a tokenStore needs no
	// constructor to be ready.
	cache utils.SyncMap[string, *servicepb.TokenRecord]
}

// warmCache loads all unexpired token records into the cache, so recently issued tokens resolve
// without a database round-trip after a restart or failover. It returns the number of records loaded.
func (s *tokenStore) warmCache(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.pool.Query(ctx, sqlSelectUnexpired, now.Unix())
	if err != nil {
		return 0, errors.Wrap(err, "failed to read token records for cache warm-up")
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var data []byte
		if err = rows.Scan(&data); err != nil {
			return count, errors.Wrap(err, "failed to scan token record")
		}
		rec := &servicepb.TokenRecord{}
		if err = proto.Unmarshal(data, rec); err != nil {
			return count, errors.Wrap(err, "failed to unmarshal token record")
		}
		s.cache.Store(rec.GetJti(), rec)
		count++
	}
	return count, errors.Wrap(rows.Err(), "failed while reading token records")
}

// put persists a token record and caches it.
func (s *tokenStore) put(ctx context.Context, rec *servicepb.TokenRecord) error {
	data, err := proto.Marshal(rec)
	if err != nil {
		return errors.Wrap(err, "failed to marshal token record")
	}
	if _, err = s.pool.Exec(ctx, sqlInsertRecord, rec.GetJti(), data, rec.GetExpiresAt()); err != nil {
		return errors.Wrap(err, "failed to persist token record")
	}
	s.cache.Store(rec.GetJti(), rec)
	return nil
}

// get returns the token record for jti, reading through the cache to the database. It returns
// ErrTokenNotFound when the record is absent (unknown or revoked).
func (s *tokenStore) get(ctx context.Context, jti string) (*servicepb.TokenRecord, error) {
	if rec, ok := s.cache.Load(jti); ok {
		return rec, nil
	}

	var data []byte
	err := s.pool.QueryRow(ctx, sqlSelectRecord, jti).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to read token record")
	}

	rec := &servicepb.TokenRecord{}
	if err = proto.Unmarshal(data, rec); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal token record")
	}
	s.cache.Store(jti, rec)
	return rec, nil
}

// sweep deletes token records that expired before now from the database and evicts them from the
// cache, so neither grows unbounded. It returns the number of rows deleted.
func (s *tokenStore) sweep(ctx context.Context, now time.Time) (int64, error) {
	cutoffSeconds := now.Unix()
	tag, err := s.pool.Exec(ctx, sqlDeleteExpiredTokens, cutoffSeconds)
	if err != nil {
		return 0, errors.Wrap(err, "failed to sweep expired token records")
	}

	for jti, rec := range s.cache.IterItems() {
		if rec.GetExpiresAt() < cutoffSeconds {
			s.cache.Delete(jti)
		}
	}
	return tag.RowsAffected(), nil
}

// size reports the number of cached token records, for the token-store-size metric.
func (s *tokenStore) size() int {
	return s.cache.Count()
}
