/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/yugabyte/pgx/v5/pgxpool"
)

const (
	// nonceLength is the size of an issued nonce.
	nonceLength = 32
)

// errNonceNotFound is returned when a nonce is unknown, already consumed, or expired. The three are
// deliberately indistinguishable to the caller, so a client cannot probe which nonces exist.
var errNonceNotFound = errors.New("authentication nonce is unknown, already used, or expired")

// nonceStore issues and redeems the single-use nonces that make an envelope non-replayable. They live in
// the shared database, not memory: a client behind a load balancer may hit two different instances.
type nonceStore struct {
	pool *pgxpool.Pool
	ttl  time.Duration
}

// issue generates a nonce and records it with its expiry.
func (s *nonceStore) issue(ctx context.Context, now time.Time) ([]byte, time.Time, error) {
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, time.Time{}, errors.Wrap(err, "failed to generate nonce")
	}

	expiresAt := now.Add(s.ttl)
	if _, err := s.pool.Exec(ctx, sqlInsertNonce, nonce, expiresAt.Unix()); err != nil {
		return nil, time.Time{}, errors.Wrap(err, "failed to persist nonce")
	}
	return nonce, expiresAt, nil
}

// consume redeems a nonce, returning errNonceNotFound unless it was present and unexpired.
func (s *nonceStore) consume(ctx context.Context, nonce []byte, now time.Time) error {
	if len(nonce) == 0 {
		return errors.Wrap(errNonceNotFound, "envelope carries no nonce")
	}

	tag, err := s.pool.Exec(ctx, sqlConsumeNonce, nonce, now.Unix())
	if err != nil {
		return errors.Wrap(err, "failed to consume nonce")
	}
	if tag.RowsAffected() == 0 {
		return errNonceNotFound
	}
	return nil
}

// sweep deletes nonces that lapsed before now, so the table does not grow without bound when clients
// request nonces they never redeem. It returns the number of rows deleted.
func (s *nonceStore) sweep(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, sqlDeleteExpiredNonces, now.Unix())
	if err != nil {
		return 0, errors.Wrap(err, "failed to sweep expired nonces")
	}
	return tag.RowsAffected(), nil
}
