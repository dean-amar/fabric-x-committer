package vc

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yugabyte/pgx/v4/pgxpool"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

const (
	// system tables and function names.
	txStatusTableName      = "tx_status"
	metadataTableName      = "metadata"
	insertTxStatusFuncName = "insert_tx_status"

	// namespace table and function names prefix.
	nsTableNamePrefix               = "ns_"
	validateReadsOnNsFuncNamePrefix = "validate_reads_"
	updateNsStatesFuncNamePrefix    = "update_"
	insertNsStatesFuncNamePrefix    = "insert_"

	createTxStatusTableSQLStmt = `
		CREATE TABLE IF NOT EXISTS ` + txStatusTableName + `(
				tx_id BYTEA NOT NULL PRIMARY KEY,
				status INTEGER,
				height BYTEA NOT NULL
		);
	`

	createMetadataTableSQLStmt = `
		CREATE TABLE IF NOT EXISTS ` + metadataTableName + `(
				key BYTEA NOT NULL PRIMARY KEY,
				value BYTEA
		);
	`
	createNsTableSQLTempl = `
		CREATE TABLE IF NOT EXISTS %[1]s (
				key BYTEA NOT NULL PRIMARY KEY,
				value BYTEA DEFAULT NULL,
				version BYTEA DEFAULT '\x00'::BYTEA
		);
	`

	initializeMetadataPrepSQLStmt = "INSERT INTO " + metadataTableName + " VALUES ($1, $2) ON CONFLICT DO NOTHING;"
	setMetadataPrepSQLStmt        = "UPDATE " + metadataTableName + " SET value = $2 WHERE key = $1;"
	getMetadataPrepSQLStmt        = "SELECT value FROM " + metadataTableName + " WHERE key = $1;"
	queryTxIDsStatusPrepSQLStmt   = "SELECT tx_id, status, height FROM " + txStatusTableName + " WHERE tx_id = ANY($1);"

	lastCommittedBlockNumberKey = "last committed block number"

	createInsertTxStatusFuncSQLStmt = `
CREATE OR REPLACE FUNCTION ` + insertTxStatusFuncName + `(
    IN _tx_ids BYTEA [],
    IN _statuses INTEGER [],
    IN _heights BYTEA [],
    OUT result TEXT,
    OUT violating BYTEA []
)
AS $$
BEGIN
    result := 'success';
    violating := NULL;

    INSERT INTO ` + txStatusTableName + ` (tx_id, status, height)
    VALUES (
        unnest(_tx_ids),
        unnest(_statuses),
        unnest(_heights)
    );

EXCEPTION
    WHEN unique_violation THEN
        SELECT array_agg(t.tx_id)
        INTO violating
        FROM ` + txStatusTableName + ` t
        WHERE t.tx_id = ANY(_tx_ids);

        IF cardinality(violating) < cardinality(_tx_ids) THEN
            result := cardinality(violating)::text || '-unique-violation';
        ELSE
            violating := NULL;
            result := 'all-unique-violation';
        END IF;
END;
$$ LANGUAGE plpgsql;
`

	createValidateReadsOnNsStatesFuncSQLTempl = `
CREATE OR REPLACE FUNCTION ` + validateReadsOnNsFuncNamePrefix + `%[1]s(
    keys BYTEA [],
    versions BYTEA []
)
RETURNS TABLE (key_mismatched BYTEA, version_mismatched BYTEA)
AS $$
BEGIN
	RETURN QUERY
	SELECT
		reads.keys AS key_mismatched,
		reads.versions AS version_mismatched
	FROM
		unnest(keys, versions) WITH ORDINALITY AS reads(keys, versions, ord_keys)
	LEFT JOIN
		%[1]s ON reads.keys = %[1]s.key
	WHERE
		/* if the key does not exist in the committed state but read version is not null,
		we found a mismatch */
		(%[1]s.key IS NULL AND reads.versions IS NOT NULL)
		OR
		/* if the key exists in the committed state but read version is null, we found a mismatch */
		(reads.versions IS NULL AND %[1]s.key is NOT NULL)
		OR
		/* if the committed version of a key is different from the read version, we found a mismatch */
		reads.versions <> %[1]s.version;
END;
$$ LANGUAGE plpgsql;
`

	createUpdateNsStatesFuncSQLTempl = `
CREATE OR REPLACE FUNCTION ` + updateNsStatesFuncNamePrefix + `%[1]s(
    IN _keys BYTEA [],
    IN _values BYTEA [],
    IN _versions BYTEA []
)
RETURNS VOID
AS $$
BEGIN
    UPDATE %[1]s
    SET
        value = t.value,
        version = t.version
    FROM (
        SELECT *
        FROM unnest(_keys, _values, _versions) AS t(key, value, version)
    ) AS t
    WHERE
        %[1]s.key = t.key;
END;
$$ LANGUAGE plpgsql;
`

	createInsertNsStatesFuncSQLTempl = `
CREATE OR REPLACE FUNCTION ` + insertNsStatesFuncNamePrefix + `%[1]s(
    IN _keys BYTEA [],
    IN _values BYTEA [],
    OUT result TEXT,
    OUT violating BYTEA []
)
AS $$
BEGIN
    result := 'success';
    violating := NULL;

    INSERT INTO %[1]s (key, value)
    SELECT k, v
    FROM unnest(_keys, _values) AS t(k, v);

EXCEPTION
    WHEN unique_violation THEN
        SELECT array_agg(t_existing.key)
        INTO violating
        FROM %[1]s t_existing
        WHERE t_existing.key = ANY (_keys);

        IF cardinality(violating) < cardinality(_keys) THEN
            result := cardinality(violating)::text || '-unique-violation';
        ELSE
            violating := NULL;
            result := 'all-unique-violation';
        END IF;
END;
$$ LANGUAGE plpgsql;
`
)

var (
	systemNamespaces = []string{types.MetaNamespaceID, types.ConfigNamespaceID}

	createSystemTablesAndFuncsStmts = []string{
		createTxStatusTableSQLStmt,
		createInsertTxStatusFuncSQLStmt,
		createMetadataTableSQLStmt,
	}

	createNsTablesAndFuncsTemplates = []string{
		createNsTableSQLTempl,
		createValidateReadsOnNsStatesFuncSQLTempl,
		createUpdateNsStatesFuncSQLTempl,
		createInsertNsStatesFuncSQLTempl,
	}
)

// NewDatabasePool creates a new pool from a database config.
func NewDatabasePool(ctx context.Context,
	config *DatabaseConfig,
	retryMetrics *prometheus.CounterVec,
) (*pgxpool.Pool, error) {
	logger.Infof("DB source: %s", config.DataSourceName())
	poolConfig, err := pgxpool.ParseConfig(config.DataSourceName())
	if err != nil {
		return nil, errors.Wrapf(err, "failed parsing datasource")
	}

	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections

	var pool *pgxpool.Pool
	if retryErr := config.Retry.Execute(ctx, "pool_creation", retryMetrics, func() error {
		pool, err = pgxpool.ConnectConfig(ctx, poolConfig)
		return errors.Wrap(err, "failed to create a connection pool")
	}); retryErr != nil {
		return nil, retryErr
	}

	logger.Info("DB pool created")
	return pool, nil
}

// TODO: merge this file with database.go.
func (db *database) setupSystemTablesAndNamespaces(ctx context.Context) error {
	executeSQL := func(operationName, sqlStmt string, args ...any) error {
		return db.retry.ExecuteSQL(ctx, &connection.SQLExecutionBundle{
			OperationName: operationName,
			Stmt:          sqlStmt,
			Pool:          db.pool,
			RetryMetrics:  db.metrics.failedRetriesCounter,
		}, args...)
	}

	for _, stmt := range createSystemTablesAndFuncsStmts {
		if err := executeSQL("database_init_statement", stmt); err != nil {
			return fmt.Errorf("failed to create system tables and functions: %w", err)
		}
	}
	logger.Info("Created tx status table, metadata table, and its methods.")

	if err := executeSQL("metadata_table_initialization",
		initializeMetadataPrepSQLStmt,
		[]byte(lastCommittedBlockNumberKey), nil); err != nil {
		return fmt.Errorf("failed to initialize metadata table: %w", err)
	}

	for _, nsID := range systemNamespaces {
		tableName := TableName(nsID)
		for _, stmt := range createNsTablesAndFuncsTemplates {
			if err := executeSQL(fmt.Sprintf("creating_table_and_its_methods_for%s", nsID),
				fmt.Sprintf(stmt, tableName)); err != nil {
				return fmt.Errorf("failed to create tables and functions for system namespaces: %w", err)
			}
		}
		logger.Infof("namespace %s: created table '%s' and its methods.", nsID, tableName)
	}
	return nil
}
