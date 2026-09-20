package auth

import "github.com/hyperledger/fabric-x-committer/utils/statedb"

const (
	// Tables are created by `init-db` with the rest of the system schema,
	// so we reference them via statedb's constants rather than string literals.
	tokens = statedb.AuthTokensTableName
	nonces = statedb.AuthNoncesTableName

	sqlInsertRecord        = "INSERT INTO " + tokens + " (jti, record, expires_at) VALUES ($1, $2, $3)"
	sqlSelectRecord        = "SELECT record FROM " + tokens + " WHERE jti = $1"
	sqlDeleteExpiredTokens = "DELETE FROM " + tokens + " WHERE expires_at < $1"
	sqlSelectUnexpired     = "SELECT record FROM " + tokens + " WHERE expires_at >= $1"

	sqlInsertNonce         = "INSERT INTO " + nonces + " (nonce, expires_at) VALUES ($1, $2)"
	sqlConsumeNonce        = "DELETE FROM " + nonces + " WHERE nonce = $1 AND expires_at >= $2"
	sqlDeleteExpiredNonces = "DELETE FROM " + nonces + " WHERE expires_at < $1"
)
