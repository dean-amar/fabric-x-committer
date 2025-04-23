package dbtest

import (
	"context"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/yugabyte/pgx/v4/pgxpool"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/logging"
)

var logger = logging.New("db connection")

const (
	defaultUsername = "yugabyte"
	defaultPassword = "yugabyte"

	stmtTemplateCreateDb       = "CREATE DATABASE %s;"
	stmtTemplateDropDbIfExists = "DROP DATABASE IF EXISTS %s WITH (FORCE);"
)

// DefaultRetry is used for tests.
var DefaultRetry = &connection.RetryProfile{
	// MaxElapsedTime is the duration allocated for the retry mechanism during the database initialization process.
	MaxElapsedTime: 3 * time.Minute,
	// InitialInterval is the starting wait time interval that increases every retry attempt.
	InitialInterval: 100 * time.Millisecond,
}

// Connection facilities connecting to a YugabyteDB instance.
type Connection struct {
	Endpoints []*connection.Endpoint
	User      string
	Password  string
	Database  string
}

// NewConnection returns a connection parameters with the specified host:port, and the default values
// for the other parameters.
func NewConnection(endpoints ...*connection.Endpoint) *Connection {
	return &Connection{
		Endpoints: endpoints,
		User:      defaultUsername,
		Password:  defaultPassword,
	}
}

// DataSourceName returns the dataSourceName to be used by the database/sql package.
func (y *Connection) DataSourceName() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		y.User, y.Password, y.EndpointsString(), y.Database)
}

// EndpointsString returns the address:port as a string with comma as a separator between endpoints.
func (y *Connection) EndpointsString() string {
	return connection.AddressString(y.Endpoints...)
}

// Open opens a connection pool to the database.
func (y *Connection) Open(ctx context.Context) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(y.DataSourceName())
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing datasource: %s", y.EndpointsString())
	}

	poolConfig.MaxConns = 1
	poolConfig.MinConns = 1

	var pool *pgxpool.Pool
	if retryErr := DefaultRetry.Execute(ctx, "pool_creation_test", nil, func() error {
		pool, err = pgxpool.ConnectConfig(ctx, poolConfig)
		return err
	}); retryErr != nil {
		return nil, errors.Wrapf(err, "error making pool: %s", y.EndpointsString())
	}
	return pool, nil
}

// WaitForReady repeatably checks readiness until positive response arrives.
func (y *Connection) WaitForReady(ctx context.Context) bool {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for !y.IsEndpointReady(ctx) {
		select {
		case <-ctx.Done():
			// Stop trying if the context cancelled
			return false
		case <-ticker.C:
		}
	}

	return true
}

// IsEndpointReady attempts to ping the database and returns true if successful.
func (y *Connection) IsEndpointReady(ctx context.Context) bool {
	conn, err := y.Open(ctx)
	if err != nil {
		logger.Debugf("[%s] error opening connection: %s", y.EndpointsString(), err)
		return false
	}
	defer conn.Close()

	if err = conn.Ping(ctx); err != nil {
		logger.Debugf("[%s] error pinging connection: %s", y.EndpointsString(), err)
		return false
	}
	logger.Infof("[%s] Connected to database", y.EndpointsString())
	return true
}

// CreateDB creates the database.
func (y *Connection) CreateDB(ctx context.Context, dbName string) error {
	pool, err := y.Open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err = execDropIfExitsDB(ctx, pool, dbName); err != nil {
		return err
	}

	return execCreateDB(ctx, pool, dbName)
}

// DropDB clears the database.
func (y *Connection) DropDB(ctx context.Context, dbName string) error {
	pool, err := y.Open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	return execDropIfExitsDB(ctx, pool, dbName)
}

// execCreateDB creates a DB if exists given an existing pool.
func execCreateDB(ctx context.Context, pool *pgxpool.Pool, dbName string) error {
	logger.Infof("Creating database: %s", dbName)
	if execErr := PoolExecOperation(ctx, pool, fmt.Sprintf(stmtTemplateCreateDb, dbName)); execErr != nil {
		return execErr
	}
	logger.Infof("Database created: %s", dbName)
	return nil
}

// execDropIfExitsDB drops a DB if exists given an existing pool.
func execDropIfExitsDB(ctx context.Context, pool *pgxpool.Pool, dbName string) error {
	logger.Infof("Dropping database if exists: %s", dbName)
	if execErr := PoolExecOperation(ctx, pool, fmt.Sprintf(stmtTemplateDropDbIfExists, dbName)); execErr != nil {
		return execErr
	}
	logger.Infof("Database dropped: %s", dbName)
	return nil
}

func PoolExecOperation(ctx context.Context, pool *pgxpool.Pool, stmt string, args ...any) error {
	return DefaultRetry.Execute(ctx, "pool_exec", nil, func() error {
		_, err := pool.Exec(ctx, stmt, args...)
		return errors.Wrapf(err, "db exec failed: %s", stmt)
	})
}
