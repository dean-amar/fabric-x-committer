/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	_ "embed"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/yugabyte/pgx/v5"
	"github.com/yugabyte/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils"
)

//go:embed auth_tokens.sql
var createTokenTableSQL string

const (
	sqlInsertRecord    = `INSERT INTO auth_tokens (jti, record, expires_at) VALUES ($1, $2, $3)`
	sqlSelectRecord    = `SELECT record FROM auth_tokens WHERE jti = $1`
	sqlDeleteRecord    = `DELETE FROM auth_tokens WHERE jti = $1`
	sqlDeleteExpired   = `DELETE FROM auth_tokens WHERE expires_at < $1`
	sqlSelectUnexpired = `SELECT record FROM auth_tokens WHERE expires_at >= $1`
)

// ErrTokenNotFound is returned when a token record is absent from the store, meaning the token is
// unknown or has been revoked.
var ErrTokenNotFound = errors.New("token record not found")

// tokenStore is the token-to-identity binding store: it maps a token id (jti) to the client's
// resolved MSP identity (plus its certificate binding, scope, and expiry), persisted in the
// dedicated auth_tokens namespace and fronted by an in-memory read-through cache. Authenticate
// writes a binding here; Authorize reads it to recover the identity a token stands for. The database
// is the single source of truth, so any AuthService instance can resolve any token and revocation is
// a row delete. The cache accelerates repeated lookups; a stale cache entry can only be honored until
// the token's own expiry (verified before the store is consulted), which bounds cross-instance
// revocation latency by the token TTL.
type tokenStore struct {
	pool  *pgxpool.Pool
	cache *utils.SyncMap[string, *servicepb.TokenRecord]
}

// newTokenStore creates a token store backed by the given pool.
func newTokenStore(pool *pgxpool.Pool) *tokenStore {
	return &tokenStore{
		pool:  pool,
		cache: &utils.SyncMap[string, *servicepb.TokenRecord]{},
	}
}

// ensureTable creates the token table and its expiry index if absent. Safe to run repeatedly.
func (s *tokenStore) ensureTable(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, createTokenTableSQL); err != nil {
		return errors.Wrap(err, "failed to create auth token table")
	}
	return nil
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

// delete revokes a token by removing its record from the database and the local cache; other
// instances' caches self-heal when the token expires. This is the operational revocation primitive
// the design refers to. It is not yet exposed through a client-facing RPC: revocation is performed
// out of band (an admin/operational path), so a Revoke RPC is intentionally left for a follow-up.
func (s *tokenStore) delete(ctx context.Context, jti string) error {
	if _, err := s.pool.Exec(ctx, sqlDeleteRecord, jti); err != nil {
		return errors.Wrap(err, "failed to delete token record")
	}
	s.cache.Delete(jti)
	return nil
}

// sweep deletes token records that expired before now from the database and evicts them from the
// cache, so neither grows unbounded. It returns the number of rows deleted.
func (s *tokenStore) sweep(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Unix()
	tag, err := s.pool.Exec(ctx, sqlDeleteExpired, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, "failed to sweep expired token records")
	}

	for jti, rec := range s.cache.IterItems() {
		if rec.GetExpiresAt() < cutoff {
			s.cache.Delete(jti)
		}
	}
	return tag.RowsAffected(), nil
}

// size reports the number of cached token records, for the token-store-size metric.
func (s *tokenStore) size() int {
	return s.cache.Count()
}
