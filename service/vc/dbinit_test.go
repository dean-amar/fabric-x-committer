package vc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc/dbtest"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

func Test_DbInit(t *testing.T) {
	env := NewDatabaseTestEnv(t)

	ns := []string{"0", "1", "2", "3"}
	require.NoError(t, initDatabaseTables(t.Context(), &operation{
		pool:         env.DB.pool,
		config:       env.DBConf,
		retryMetrics: nil,
	}, ns))

	_, err := env.DB.pool.Exec(t.Context(), `insert into ns_0 values (UNNEST($1::bytea[]));`, [][]byte{
		[]byte("tx1"), []byte("tx2"), []byte("tx3"), []byte("tx4"),
	})
	require.NoError(t, err)

	// Validate default values
	r, err := env.DB.pool.Query(t.Context(), `select * from ns_0;`)
	require.NoError(t, err)
	defer r.Close()
	for r.Next() {
		var key, value, version []byte
		require.NoError(t, r.Scan(&key, &value, &version))
		t.Logf("key: %s", string(key))
		require.Nil(t, value)
		require.Equal(t, types.VersionNumber(0).Bytes(), version)
	}

	require.NoError(t, clearDatabaseTables(context.Background(), env.DB.pool, ns))
}

func TestRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)
	pool, err := NewDatabasePool(
		ctx,
		&DatabaseConfig{
			Endpoints: []*connection.Endpoint{
				connection.CreateEndpoint(":1234"),
			},
			Username:       "name",
			Password:       "pwd",
			MaxConnections: 5,
		}, nil)
	require.ErrorContains(t, err, "failed making pool")
	require.Nil(t, pool)
}

func TestConcurrentDatabaseTablesInit(t *testing.T) {
	cs := dbtest.PrepareTestEnv(t)

	config := &DatabaseConfig{
		Endpoints:      cs.Endpoints,
		Username:       cs.User,
		Password:       cs.Password,
		Database:       cs.Database,
		MaxConnections: 15,
		MinConnections: 1,
		Retry: &connection.RetryProfile{
			MaxElapsedTime: 3 * time.Minute,
		},
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	t.Cleanup(cancel)

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics := newVCServiceMetrics()
			testDB, dbInitErr := newDatabase(ctx, config, metrics)
			require.NoError(t, dbInitErr)
			t.Cleanup(testDB.close)
		}()
	}
	wg.Wait()
}
