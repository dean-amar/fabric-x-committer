/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	_ "embed"

	"github.com/cockroachdb/errors"

	"github.com/hyperledger/fabric-x-committer/utils/retry"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
)

var (
	//go:embed auth_tokens.sql
	createTokenTableSQL string
	//go:embed auth_nonces.sql
	createNonceTableSQL string
)

// SetupTables creates the auth service's tables. The `init-db` command calls it, not the running
// service, so a deployed AuthService needs no DDL privileges and instances do not race at startup.
//
// Safe to run repeatedly. DDL goes through the configured retry profile, as the system tables do,
// because it can fail transiently on a cluster electing a leader.
func SetupTables(ctx context.Context, config *statedb.Config) error {
	pool, err := statedb.NewPool(ctx, config)
	if err != nil {
		return errors.Wrap(err, "failed to connect to the database")
	}
	defer pool.Close()

	for _, stmt := range []string{createTokenTableSQL, createNonceTableSQL} {
		if err = retry.ExecuteSQL(ctx, config.Retry, pool, stmt); err != nil {
			return errors.Wrap(err, "failed to create the auth service tables")
		}
	}
	return nil
}
