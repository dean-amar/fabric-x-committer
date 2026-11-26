/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statedb_test

import (
	"testing"

	"github.com/Chaguar/common/api/applicationpb"
	"github.com/Chaguar/common/api/committerpb"
	"github.com/stretchr/testify/require"
	"github.com/yugabyte/pgx/v5/pgxpool"

	"github.com/Chaguar/committer/utils/statedb"
)

// TestConfigVersionTracker walks one tracker through the version sequence both its callers - the query
// service's TLS refresh and the auth service's configuration refresh - rely on.
func TestConfigVersionTracker(t *testing.T) {
	t.Parallel()
	pool := newSnapshotStateTestEnv(t).pool
	var tracker statedb.ConfigVersionTracker

	// Step 1: Nothing is committed during bootstrap.
	t.Log("Step 1: nothing committed")
	requireReadIfNewer(t, &tracker, pool, nil)

	// Step 2: The first version is returned, and again on the next poll while it is not accepted, so a version
	// that failed to apply is retried.
	t.Log("Step 2: version 0 is returned until accepted")
	upsertConfigTransaction(t, pool, "v0", 0)
	requireReadIfNewer(t, &tracker, pool, []byte("v0"))
	configTX := requireReadIfNewer(t, &tracker, pool, []byte("v0"))

	// Step 3: Once accepted, the same version is no longer new.
	t.Log("Step 3: version 0 is skipped once accepted")
	tracker.Accept(configTX)
	requireReadIfNewer(t, &tracker, pool, nil)

	// Step 4: A newer version is returned.
	t.Log("Step 4: version 1 is returned")
	upsertConfigTransaction(t, pool, "v1", 1)
	tracker.Accept(requireReadIfNewer(t, &tracker, pool, []byte("v1")))

	// Step 5: An older version read after a newer one was accepted is ignored.
	t.Log("Step 5: version 0 is ignored after version 1")
	upsertConfigTransaction(t, pool, "v0", 0)
	requireReadIfNewer(t, &tracker, pool, nil)
}

// requireReadIfNewer reads through the tracker and requires the returned envelope, nil meaning nothing new.
func requireReadIfNewer(
	t *testing.T, tracker *statedb.ConfigVersionTracker, pool *pgxpool.Pool, wantEnvelope []byte,
) *applicationpb.ConfigTransaction {
	t.Helper()
	configTX, err := tracker.ReadIfNewer(t.Context(), pool)
	require.NoError(t, err)
	if wantEnvelope == nil {
		require.Nil(t, configTX)
		return nil
	}
	require.NotNil(t, configTX)
	require.Equal(t, wantEnvelope, configTX.GetEnvelope())
	return configTX
}

// upsertConfigTransaction commits envelope as the config transaction at version, as the committer would.
func upsertConfigTransaction(t *testing.T, pool *pgxpool.Pool, envelope string, version uint64) {
	t.Helper()
	_, err := pool.Exec(t.Context(),
		"INSERT INTO "+statedb.TableName(committerpb.ConfigNamespaceID)+" (key, value, version) VALUES ($1, $2, $3) "+
			"ON CONFLICT (key) DO UPDATE SET value = excluded.value, version = excluded.version",
		[]byte(committerpb.ConfigKey), []byte(envelope), version)
	require.NoError(t, err)
}
