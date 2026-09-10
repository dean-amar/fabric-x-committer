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

	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

const (
	// nonceLength is the size of an issued nonce. 32 bytes of CSPRNG output makes collisions and
	// guessing infeasible, matching the entropy of the token ids the service already mints.
	nonceLength = 32

	// The nonce table is created by `init-db` with the rest of the system schema, so these statements
	// name it through statedb's constant rather than a literal of their own.
	sqlInsertNonce         = "INSERT INTO " + statedb.AuthNoncesTableName + " (nonce, expires_at) VALUES ($1, $2)"
	sqlConsumeNonce        = "DELETE FROM " + statedb.AuthNoncesTableName + " WHERE nonce = $1 AND expires_at >= $2"
	sqlDeleteExpiredNonces = "DELETE FROM " + statedb.AuthNoncesTableName + " WHERE expires_at < $1"
)

// ErrNonceNotFound is returned when a nonce is unknown, already consumed, or expired. The three are
// deliberately indistinguishable to the caller, so a client cannot probe which nonces exist.
var ErrNonceNotFound = errors.New("authentication nonce is unknown, already used, or expired")

// nonceStore issues and redeems the single-use nonces that make an authentication envelope
// non-replayable. The server chooses the nonce, so a captured envelope carries a nonce that has
// already been consumed and is worthless to a replayer; the freshness window and certificate binding
// remain as defence in depth. Nonces live in the shared state database rather than in memory, so a
// nonce issued by one instance can be redeemed at another - a client behind a load balancer has no
// guarantee that its IssueNonce and Authenticate calls reach the same instance.
type nonceStore struct {
	pool *pgxpool.Pool
	ttl  time.Duration
}

// issue generates a nonce, records it with its expiry, and returns it with the instant it lapses.
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

// consume redeems a nonce, returning ErrNonceNotFound unless it was present and unexpired. The
// delete is the single-use gate: exactly one row is removed for a valid nonce, and a second attempt
// removes none, so two concurrent redemptions of the same nonce cannot both succeed even across
// instances.
func (s *nonceStore) consume(ctx context.Context, nonce []byte, now time.Time) error {
	if len(nonce) == 0 {
		return errors.Wrap(ErrNonceNotFound, "envelope carries no nonce")
	}

	tag, err := s.pool.Exec(ctx, sqlConsumeNonce, nonce, now.Unix())
	if err != nil {
		return errors.Wrap(err, "failed to consume nonce")
	}
	if tag.RowsAffected() == 0 {
		return ErrNonceNotFound
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
