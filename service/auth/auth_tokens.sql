/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
The auth_tokens table holds one row per issued token, keyed by its JWT id (jti). The record
column stores a proto-marshaled servicepb.TokenRecord; expires_at is duplicated from the record
as an indexed column so expired tokens can be swept efficiently. This is auth infrastructure, not
a committer state namespace, so it deliberately does not follow the ns_<id> schema and is created
idempotently by the auth service at startup.
*/

CREATE TABLE IF NOT EXISTS auth_tokens
(
    jti        TEXT   NOT NULL PRIMARY KEY,
    record     BYTEA  NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_tokens_expires_at ON auth_tokens (expires_at);
