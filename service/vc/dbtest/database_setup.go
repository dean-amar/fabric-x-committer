/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dbtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

const (
	defaultStartTimeout = 5 * time.Minute
	defaultDBPrefix     = "sc_test_"

	deploymentLocal     = "local"
	deploymentContainer = "container"

	YugaDBType     = "yugabyte" //nolint:revive
	PostgresDBType = "postgres"

	yugaDBPort     = "5433"
	postgresDBPort = "5432"

	defaultLocalDBPort = "5433"

	DeploymentTypeEnv = "DB_DEPLOYMENT"
	DatabaseTypeEnv   = "DB_TYPE"
)

// randDbName generates random DB name.
// It digests the current time, the test name, and a random string to a base32 string.
func randDbName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 1024)
	_, err := rand.Read(b)
	require.NoError(t, err)
	b, err = time.Now().AppendBinary(b)
	require.NoError(t, err)
	s := sha256.New()
	s.Write([]byte(t.Name()))
	s.Write(b)
	uuidStr := strings.ToLower(strings.Trim(base32.StdEncoding.EncodeToString(s.Sum(nil)), "="))
	return defaultDBPrefix + uuidStr
}

// getDBDeploymentFromEnv get the desired DB deployment type from the environment variable.
func getDBDeploymentFromEnv() string {
	val, found := os.LookupEnv(DeploymentTypeEnv)
	if found {
		return strings.ToLower(val)
	}

	return deploymentContainer
}

// getDBTypeFromEnv get the desired DB type from the environment variable.
func getDBTypeFromEnv() string {
	val, found := os.LookupEnv(DatabaseTypeEnv)
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

	require.True(t, conn.waitForReady(ctx), errors.Wrapf(ctx.Err(), "database is not ready"))
	t.Logf("connection nodes details: %s", conn.endpointsString())

	dbName := randDbName(t)
	t.Logf("[%s] db name: %s", t.Name(), dbName)
	require.NoError(t, conn.execute(ctx, fmt.Sprintf(createDBSQLTempl, dbName)))

	// we copy the connection for later usage.
	dropConn := *conn
	t.Cleanup(func() {
		//nolint:usetesting // t.Context is finishing right after the test resulting in context.Deadline error.
		cleanUpCtx, cleanUpCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cleanUpCancel()
		logger.WarnStackTrace(dropConn.execute(cleanUpCtx, fmt.Sprintf(dropDBSQLTempl, dbName)))
	})
	conn.Database = dbName
	return conn
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

// CreateAndStartSecuredDatabaseNode creates a containerized Yugabyte or PostgreSQL database instance in a secure mode.
// This function shouldn't be called number of times in parallel
// due to the need of Yugabyte's secure node credentials path convention.
func CreateAndStartSecuredDatabaseNode(ctx context.Context, t *testing.T, dbType string) *Connection {
	t.Helper()

	node := &DatabaseContainer{
		DatabaseType: dbType,
		UseTLS:       true,
	}

	switch node.DatabaseType {
	case YugaDBType:
		node.User = "root"
	case PostgresDBType:
		node.User = "postgres"
	default:
		t.Fatalf("Unsupported database type: %s", node.DatabaseType)
	}

	node.StartContainer(ctx, t)
	conn := node.getConnectionOptions(ctx, t)

	if node.UseTLS {
		conn.Creds = connection.DatabaseCreds{
			CAPaths:    []string{node.Creds.CACertPath},
			ServerName: node.Creds.ServerName,
		}
		switch node.DatabaseType {
		case YugaDBType:
			require.NoError(t, node.fixCertificatePermissionsYuga(t))
			require.NoError(t, node.EnsureNodeReadiness(t, YugabyteReadinessOutput))
			conn.Password = node.readPasswordFromContainer(t, ContainerPathForYugabytePassword)
		case PostgresDBType:
			require.NoError(t, node.fixCertificatePermissions(t))
			require.NoError(t, node.EnsureNodeReadiness(t, PostgresReadinessOutput))
			node.ExecuteCommand(t, enforcePostgresSSLScript)
			node.ExecuteCommand(t, reloadPostgresConfigScript)
		default:
			t.Fatalf("Unsupported database type: %s", node.DatabaseType)
		}
	}

	t.Cleanup(
		func() {
			node.StopAndRemoveContainer(t)
		})

	return conn
}
