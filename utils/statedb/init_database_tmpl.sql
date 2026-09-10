/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

-- This SQL is the flow to initiate the DB for the committer.

CREATE TABLE IF NOT EXISTS metadata
(
    key   BYTEA NOT NULL PRIMARY KEY,
    value BYTEA
)${SPLIT_INTO_TABLETS};

INSERT INTO metadata
VALUES ('last committed block number', NULL)
ON CONFLICT DO NOTHING;

INSERT INTO metadata
VALUES ('latest snapshot key', NULL)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS tx_status
(
    tx_id  BYTEA NOT NULL PRIMARY KEY,
    status INTEGER,
    height BYTEA NOT NULL
)${SPLIT_INTO_TABLETS};

CREATE OR REPLACE FUNCTION insert_tx_status(
    IN _tx_ids BYTEA[],
    IN _statuses INTEGER[],
    IN _heights BYTEA[]
) RETURNS BYTEA[]
AS
$$
DECLARE
    violating BYTEA[];
BEGIN
    INSERT INTO tx_status (tx_id, status, height)
    VALUES (unnest(_tx_ids),
            unnest(_statuses),
            unnest(_heights));
    RETURN '{}';
EXCEPTION
    WHEN unique_violation THEN
        SELECT array_agg(t.tx_id)
        INTO violating
        FROM tx_status t
        WHERE t.tx_id = ANY (_tx_ids);
        RETURN COALESCE(violating, '{}');
END;
$$ LANGUAGE plpgsql;

-- The auth service's tables. They hold authentication state, not committer state, so they are plain
-- system tables rather than ns_<id> namespaces: nothing reads them through the namespace machinery,
-- and their rows are short-lived (both are swept once expired).

-- One row per issued token, keyed by its JWT id (jti). The record column stores a proto-marshaled
-- servicepb.TokenRecord; expires_at is duplicated out of it as an indexed column so the sweep does
-- not have to unmarshal every row to find the expired ones.
CREATE TABLE IF NOT EXISTS auth_tokens
(
    jti        TEXT   NOT NULL PRIMARY KEY,
    record     BYTEA  NOT NULL,
    expires_at BIGINT NOT NULL
)${SPLIT_INTO_TABLETS};

CREATE INDEX IF NOT EXISTS auth_tokens_expires_at ON auth_tokens (expires_at);

-- One row per issued authentication nonce. A single row DELETE is what makes a nonce single-use: it
-- removes exactly one row (valid and unused) or none (unknown, already consumed, or expired), so two
-- concurrent redemptions cannot both succeed. The rows live here, in the shared state database,
-- rather than in one instance's memory, so a nonce issued by one AuthService instance is redeemable
-- at any other - a client reaching the service through a load balancer needs that.
CREATE TABLE IF NOT EXISTS auth_nonces
(
    nonce      BYTEA  NOT NULL PRIMARY KEY,
    expires_at BIGINT NOT NULL
)${SPLIT_INTO_TABLETS};

CREATE INDEX IF NOT EXISTS auth_nonces_expires_at ON auth_nonces (expires_at);
