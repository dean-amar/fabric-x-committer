/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statedb

import (
	"context"
	"fmt"

	"github.com/Chaguar/common/api/applicationpb"
	"github.com/Chaguar/common/api/committerpb"
	"github.com/cockroachdb/errors"
	"github.com/yugabyte/pgx/v5/pgxpool"
)

// selectConfigTransaction reads the committed configuration transaction by its well-known key.
var selectConfigTransaction = fmt.Sprintf(
	"SELECT value, version FROM %s WHERE key = $1", TableName(committerpb.ConfigNamespaceID),
)

// ConfigVersionTracker reads the committed config transaction and returns it only while its version is newer
// than the last one the caller accepted. Not safe for concurrent use.
type ConfigVersionTracker struct {
	lastVersion uint64
	accepted    bool
}

// ReadIfNewer returns the committed config transaction, or nil when none is committed yet or its version is
// not newer than the last accepted one.
func (t *ConfigVersionTracker) ReadIfNewer(
	ctx context.Context, pool *pgxpool.Pool,
) (*applicationpb.ConfigTransaction, error) {
	configTX, err := ReadConfigTransaction(ctx, pool)
	if err != nil {
		return nil, err
	}
	if len(configTX.GetEnvelope()) == 0 || (t.accepted && configTX.GetVersion() <= t.lastVersion) {
		return nil, nil //nolint:nilnil // nil means there is nothing new to apply.
	}
	return configTX, nil
}

// Accept records configTX as applied. Callers accept only after applying it, so a version that failed to apply
// is read again on the next poll.
func (t *ConfigVersionTracker) Accept(configTX *applicationpb.ConfigTransaction) {
	t.lastVersion = configTX.GetVersion()
	t.accepted = true
}

// ReadConfigTransaction reads the latest committed channel-configuration transaction, returning a nil
// envelope - not an error - during bootstrap. Shared, so no two readers disagree on the authoritative row.
func ReadConfigTransaction(ctx context.Context, pool *pgxpool.Pool) (*applicationpb.ConfigTransaction, error) {
	rows, err := pool.Query(ctx, selectConfigTransaction, []byte(committerpb.ConfigKey))
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
