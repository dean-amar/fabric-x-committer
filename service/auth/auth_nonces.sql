/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
The auth_nonces table holds one row per issued authentication nonce. A nonce is consumed by the
DELETE in nonceStore.consume, so a single row delete is what makes a nonce single-use: the delete
either removes exactly one row (the nonce was valid and unused) or none (unknown, already consumed,
or expired). Because the row lives in the shared state database rather than in one instance's
memory, a nonce issued by one AuthService instance is redeemable at any other, which is what lets
clients reach the service through load balancing. expires_at is indexed so the periodic sweep can
drop lapsed nonces efficiently.
*/

CREATE TABLE IF NOT EXISTS auth_nonces
(
    nonce      BYTEA  NOT NULL PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_nonces_expires_at ON auth_nonces (expires_at);
