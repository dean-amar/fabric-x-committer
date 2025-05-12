package vc

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/cockroachdb/errors"
	"github.com/yugabyte/pgx/v4/pgxpool"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
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
)

var (

	//go:embed create_insert_tx_status_func.sql
	createInsertTxStatusFuncSQLStmt string
	//go:embed create_validate_func_templ.sql
	createValidateReadsOnNsStatesFuncSQLTempl string
	//go:embed create_update_ns_states_func_templ.sql
	createUpdateNsStatesFuncSQLTempl string
	//go:embed create_insert_ns_states_func_templ.sql
	createInsertNsStatesFuncSQLTempl string

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
func NewDatabasePool(ctx context.Context, config *DatabaseConfig) (*pgxpool.Pool, error) {
	logger.Infof("DB source: %s", config.DataSourceName())
	poolConfig, err := pgxpool.ParseConfig(config.DataSourceName())
	if err != nil {
		return nil, errors.Wrapf(err, "failed parsing datasource")
	}

	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections

	var pool *pgxpool.Pool
	if retryErr := config.Retry.Execute(ctx, func() error {
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
	for _, stmt := range createSystemTablesAndFuncsStmts {
		if execErr := db.retry.ExecuteSQL(ctx, db.pool, stmt); execErr != nil {
			return fmt.Errorf("failed to create system tables and functions: %w", execErr)
		}
	}
	logger.Info("Created tx status table, metadata table, and its methods.")
	if execErr := db.retry.ExecuteSQL(
		ctx, db.pool, initializeMetadataPrepSQLStmt, []byte(lastCommittedBlockNumberKey), nil); execErr != nil {
		return fmt.Errorf("failed to initialize metadata table: %w", execErr)
	}

	for _, nsID := range systemNamespaces {
		tableName := TableName(nsID)
		for _, stmt := range createNsTablesAndFuncsTemplates {
			if execErr := db.retry.ExecuteSQL(ctx, db.pool, fmt.Sprintf(stmt, tableName)); execErr != nil {
				return fmt.Errorf("failed to create tables and functions for system namespaces: %w", execErr)
			}
		}
		logger.Infof("namespace %s: created table '%s' and its methods.", nsID, tableName)
	}
	return nil
}
