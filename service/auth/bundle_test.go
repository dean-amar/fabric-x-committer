/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

func TestConfigProviderUnavailableUntilLoaded(t *testing.T) {
	t.Parallel()
	provider := newConfigProvider(nil, newAuthServiceMetrics())

	_, err := provider.current()
	require.ErrorIs(t, err, ErrConfigUnavailable)

	env := newAuthTestEnv(t)
	provider.bundle.Store(env.bundle)
	got, err := provider.current()
	require.NoError(t, err)
	require.Same(t, env.bundle, got)
}

func TestBuildBundle(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)

	bundle, err := buildBundle(env.configEnvelope)
	require.NoError(t, err)
	app, ok := bundle.ApplicationConfig()
	require.True(t, ok)
	require.NotNil(t, app)

	_, err = buildBundle([]byte("not an envelope"))
	require.Error(t, err)
}

func TestConfigProviderRefresh(t *testing.T) {
	t.Parallel()
	env := newAuthTestEnv(t)
	provider := newConfigProviderForTest(t)

	// Step 1: no configuration committed yet - refresh is a no-op and the bundle stays unavailable.
	t.Log("Step 1: refresh with an empty config namespace")
	require.NoError(t, provider.refresh(t.Context()))
	_, err := provider.current()
	require.ErrorIs(t, err, ErrConfigUnavailable)

	// Step 2: commit a configuration and refresh - the bundle loads.
	t.Log("Step 2: commit config version 0 and refresh")
	insertConfigTx(t, provider.pool, env.configEnvelope, 0)
	require.NoError(t, provider.refresh(t.Context()))
	bundle, err := provider.current()
	require.NoError(t, err)
	require.NotNil(t, bundle)

	// Step 3: a refresh with an unchanged version does not rebuild (same bundle pointer).
	t.Log("Step 3: refresh again with no version change")
	require.NoError(t, provider.refresh(t.Context()))
	again, err := provider.current()
	require.NoError(t, err)
	require.Same(t, bundle, again)

	// Step 4: a stale (older-or-equal) version must never roll the loaded configuration backward.
	t.Log("Step 4: a stale write at an older version is ignored")
	provider.lastVersion = 5
	provider.seen = true
	insertConfigTx(t, provider.pool, env.configEnvelope, 3)
	require.NoError(t, provider.refresh(t.Context()))
	require.Equal(t, uint64(5), provider.lastVersion)

	// The sequence metric reflects the loaded configuration.
	//nolint:gosec // G115: a channel configuration sequence never approaches int overflow.
	test.RequireIntMetricValue(t, int(env.bundle.ConfigtxValidator().Sequence()), provider.metrics.configSequence)
}

func TestConfigProviderRejectsBadEnvelope(t *testing.T) {
	t.Parallel()
	provider := newConfigProviderForTest(t)

	insertConfigTx(t, provider.pool, []byte("garbage envelope"), 0)
	require.Error(t, provider.refresh(t.Context()))
	_, err := provider.current()
	require.ErrorIs(t, err, ErrConfigUnavailable)
}

func newConfigProviderForTest(t *testing.T) *configProvider {
	t.Helper()
	dbEnv := vc.NewDatabaseTestEnv(t)
	pool, err := statedb.NewPool(t.Context(), dbEnv.DBConf)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return newConfigProvider(pool, newAuthServiceMetrics())
}
