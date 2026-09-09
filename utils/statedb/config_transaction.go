/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statedb

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/yugabyte/pgx/v5"
)

// selectConfigTransaction reads the committed configuration transaction by its well-known key.
var selectConfigTransaction = fmt.Sprintf(
	"SELECT value, version FROM %s WHERE key = $1", TableName(committerpb.ConfigNamespaceID),
)

// ConfigQuerier is the single read capability ReadConfigTransaction needs. Both a *pgxpool.Pool and a
// transaction satisfy it, so a caller can read the configuration from whichever it already holds.
type ConfigQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ReadConfigTransaction reads the latest committed channel-configuration transaction from the config
// system namespace. It returns a transaction with a nil envelope - not an error - when no
// configuration has been committed yet, which is the expected state during bootstrap.
//
// Every service that needs the committed configuration reads it through here: the query service to
// refresh its TLS roots, the auth service to rebuild its policy-evaluation bundle. Keeping one
// implementation means the two cannot disagree about which row is authoritative.
func ReadConfigTransaction(ctx context.Context, q ConfigQuerier) (*applicationpb.ConfigTransaction, error) {
	rows, err := q.Query(ctx, selectConfigTransaction, []byte(committerpb.ConfigKey))
	if err != nil {
		return nil, errors.Wrap(err, "failed to query the config transaction")
	}
	defer rows.Close()

	configTX := &applicationpb.ConfigTransaction{}
	if rows.Next() {
		if err = rows.Scan(&configTX.Envelope, &configTX.Version); err != nil {
			return nil, errors.Wrap(err, "failed to scan the config transaction")
		}
	}
	return configTX, errors.Wrap(rows.Err(), "failed while reading the config transaction")
}
