package dbtest

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

const (
	defaultStartTimeout = 5 * time.Minute
	defaultDBPrefix     = "sc_unit_tests_db_%s_%s"

	deploymentLocal     = "local"
	deploymentContainer = "container"

	YugaDBType     = "yugabyte" //nolint:revive
	PostgresDBType = "postgres"

	yugaDBPort     = "5433"
	postgresDBPort = "5432"

	defaultLocalDBPort = "5433"

	deploymentTypeEnv = "DB_DEPLOYMENT"
	databaseTypeEnv   = "DB_TYPE"
)

// randDbName generates random DB name.
func randDbName(t *testing.T) string {
	t.Helper()
	uuidObj, err := uuid.NewRandomFromReader(rand.Reader)
	require.NoError(t, err)
	uuidStr := strings.ReplaceAll(uuidObj.String(), "-", "_")
	return fmt.Sprintf(defaultDBPrefix, getDBTypeFromEnv(), uuidStr)
}

// getDBDeploymentFromEnv get the desired DB deployment type from the environment variable.
func getDBDeploymentFromEnv() string {
	val, found := os.LookupEnv(deploymentTypeEnv)
	if found {
		return strings.ToLower(val)
	}

	return deploymentContainer
}

// getDBTypeFromEnv get the desired DB type from the environment variable.
func getDBTypeFromEnv() string {
	val, found := os.LookupEnv(databaseTypeEnv)
	if found {
		return strings.ToLower(val)
	}
	return YugaDBType
}

// PrepareTestEnv initializes a test environment for an existing or uncontrollable db instance.
func PrepareTestEnv(t *testing.T) *Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultStartTimeout)
	t.Cleanup(cancel)
	return PrepareTestEnvWithConnection(t, StartAndConnect(ctx, t))
}

// PrepareTestEnvWithConnection initializes a test environment given a db connection.
func PrepareTestEnvWithConnection(t *testing.T, conn *Connection) *Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaultStartTimeout)
	t.Cleanup(cancel)
	require.True(t, conn.WaitForReady(ctx), errors.Wrapf(ctx.Err(), "database is not ready"))
	t.Logf("connection nodes details: %s", conn.EndpointsString())

	dbName := randDbName(t)
	require.NoError(t, conn.CreateDB(ctx, dbName))

	t.Cleanup(func() {
		//nolint:usetesting // t.Context is finishing right after the test resulting in context.Deadline error.
		cleanUpCtx, cleanUpCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cleanUpCancel()
		assert.NoError(t, DefaultRetry.Execute(cleanUpCtx, "drop_database", nil, func() error {
			return conn.DropDB(cleanUpCtx, dbName)
		}))
	})
	// We copy the connection and add the database name
	connSettings := *conn
	connSettings.Database = dbName

	return &connSettings
}

// StartAndConnect connects to an existing Yugabyte instance or creates a containerized new one.
func StartAndConnect(ctx context.Context, t *testing.T) *Connection {
	t.Helper()
	dbDeployment := getDBDeploymentFromEnv()

	var connOptions *Connection
	switch dbDeployment {
	case deploymentContainer:
		container := DatabaseContainer{
			DatabaseType: getDBTypeFromEnv(),
		}
		container.StartContainer(ctx, t)
		connOptions = container.getConnectionOptions(ctx, t)
	case deploymentLocal:
		connOptions = NewConnection(connection.CreateEndpointHP("localhost", defaultLocalDBPort))
	default:
		t.Logf("unknown db deployment type: %s", dbDeployment)
		return nil
	}
	t.Logf("connection endpoints: %+v", connOptions.Endpoints)
	return connOptions
}
