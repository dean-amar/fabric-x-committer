package vc

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/jackc/pgtype"
	"github.com/yugabyte/pgx/v4"
	"github.com/yugabyte/pgx/v4/pgxpool"
	"go.uber.org/zap/zapcore"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoblocktx"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring/promutil"
)

const (
	// tableNameTemplate is the template for the table name for each namespace.
	tableNameTemplate = "ns_%s"

	// validateReadsSQLTemplate template for validating reads for each namespace.
	validateReadsSQLTemplate = "SELECT * FROM validate_reads_ns_%s($1::bytea[], $2::bytea[]);"
	// queryVersionsSQLTemplate template for the querying versions for given keys for each namespace.
	queryVersionsSQLTemplate = "SELECT key, version FROM %s WHERE key = ANY($1);"
	// commitTxStatusSQLTemplate template for committing transaction's status for each TX.
	commitTxStatusSQLTemplate = "SELECT commit_tx_status($1::bytea[], $2::integer[], $3::bytea[]);"
	// commitUpdateWritesSQLTemplate template for the committing updates for each namespace.
	commitUpdateWritesSQLTemplate = "SELECT commit_update_ns_%s($1::bytea[], $2::bytea[], $3::bytea[]);"
	// commitNewWritesSQLTemplate template for committing new keys for each namespace.
	commitNewWritesSQLTemplate = "SELECT commit_new_ns_%s($1::bytea[], $2::bytea[]);"
)

var (
	queryPolicies = fmt.Sprintf("SELECT key, value from ns_%s;", types.MetaNamespaceID)
	queryConfig   = fmt.Sprintf("SELECT key, value from ns_%s;", types.ConfigNamespaceID)
)

// ErrMetadataEmpty indicates that a requested metadata value is empty or not found.
var ErrMetadataEmpty = errors.New("metadata value is empty")

type (
	// database handles the database operations.
	database struct {
		pool    *pgxpool.Pool
		metrics *perfMetrics
		retry   *connection.RetryProfile
	}

	// keyToVersion is a map from key to version.
	keyToVersion map[string][]byte

	statesToBeCommitted struct {
		updateWrites namespaceToWrites
		newWrites    namespaceToWrites
		batchStatus  *protoblocktx.TransactionsStatus
		txIDToHeight transactionIDToHeight
	}
)

func (s *statesToBeCommitted) Debug() {
	if logger.Level() > zapcore.DebugLevel {
		return
	}
	logger.Debugf("total states: %d\n\tupdate: %d\n\twrites: %d\n\tbatch status: %d",
		len(s.updateWrites)+len(s.newWrites)+len(s.batchStatus.Status),
		len(s.updateWrites), len(s.newWrites), len(s.batchStatus.Status))
}

// newDatabase creates a new database.
func newDatabase(ctx context.Context, config *DatabaseConfig, metrics *perfMetrics) (*database, error) {
	retryCounterPerOp := metrics.databaseRetryCounterByOperation

	pool, err := NewDatabasePool(ctx, config, retryCounterPerOp)
	if err != nil {
		return nil, err
	}

	logger.Infof("validator persister connected to database at %s", config.EndpointsString())

	defer func() {
		if err != nil {
			pool.Close()
		}
	}()

	if err = initDatabaseTables(ctx, pool, config, retryCounterPerOp, nil); err != nil {
		return nil, err
	}

	return &database{
		pool:    pool,
		metrics: metrics,
		retry:   config.Retry,
	}, nil
}

func (db *database) close() {
	logger.Info("closing database connection")
	db.pool.Close()
}

// validateNamespaceReads validates the reads for a given namespace.
func (db *database) validateNamespaceReads(
	ctx context.Context,
	nsID string,
	r *reads,
) (*reads /* mismatching reads */, error) {
	// For each namespace nsID, we use the validate_reads_ns_<nsID> function to validate
	// the reads. This function returns the keys and versions of the mismatching reads.
	// Note that we have a table per namespace.
	// We have a validate function per namespace so that we can use the static SQL
	// to avoid parsing, planning and optimizing the query for each invoke. If we use
	// a common function for all namespace, we need to pass the table name as a parameter
	// which makes the query dynamic and hence we lose the benefits of static SQL.
	start := time.Now()
	query := fmt.Sprintf(validateReadsSQLTemplate, nsID)

	keys, values, err := db.retryQueryAndReadRows(ctx, query, r.keys, r.versions)
	if err != nil {
		return nil, fmt.Errorf("failed reading key and version: %w", err) //nolint:wrapcheck
	}

	mismatchingReads := &reads{}
	mismatchingReads.appendMany(keys, values)
	promutil.Observe(db.metrics.databaseTxBatchValidationLatencySeconds, time.Since(start))

	return mismatchingReads, nil
}

// queryVersionsIfPresent queries the versions for the given keys if they exist.
func (db *database) queryVersionsIfPresent(ctx context.Context, nsID string, queryKeys [][]byte) (keyToVersion, error) {
	start := time.Now()
	query := fmt.Sprintf(queryVersionsSQLTemplate, TableName(nsID))

	foundKeys, foundVersions, err := db.retryQueryAndReadRows(ctx, query, queryKeys)
	if err != nil {
		return nil, fmt.Errorf("failed reading key and version: %w", err) //nolint:wrapcheck
	}

	kToV := make(keyToVersion)
	for i, key := range foundKeys {
		kToV[string(key)] = foundVersions[i]
	}
	promutil.Observe(db.metrics.databaseTxBatchQueryVersionLatencySeconds, time.Since(start))

	return kToV, nil
}

func (db *database) getLastCommittedBlockNumber(ctx context.Context) (*protoblocktx.BlockInfo, error) {
	blkInfo, err := db.getBlockInfoMetadata(ctx, lastCommittedBlockNumberKey)
	if err != nil {
		return blkInfo, fmt.Errorf("failed to get the last committed block number: %w", err) //nolint:wrapcheck
	}
	return blkInfo, nil
}

func (db *database) getBlockInfoMetadata(ctx context.Context, key string) (*protoblocktx.BlockInfo, error) {
	var r pgx.Row
	var value []byte
	if retryErr := db.retry.Execute(ctx,
		"get_block_info_metadata",
		db.metrics.databaseRetryCounterByOperation, func() error {
			r = db.pool.QueryRow(ctx, getMetadataPrepStmt, []byte(key))
			return r.Scan(&value)
		}); retryErr != nil {
		return nil, errors.Wrap(retryErr, "failed to query key "+key+" from metadata table")
	}
	if len(value) == 0 {
		return nil, ErrMetadataEmpty
	}

	return &protoblocktx.BlockInfo{Number: binary.BigEndian.Uint64(value)}, nil
}

func (db *database) setLastCommittedBlockNumber(ctx context.Context, bInfo *protoblocktx.BlockInfo) error {
	// NOTE: We can actually batch this transaction with regular user transactions and perform
	//       a single commit. However, we need to implement special logic to handle cases
	//       when there are no waiting user transactions. Hence, for simplicity, we are not
	//       batching this transaction with regular user transactions. After performance
	//       benchmarking, if there is a significant benefit in performing the batching,
	//       we will implement further optimizations.

	// NOTE: As we store an integer and allow comparisons, we must ensure consistent byte representation.
	//       This means using the same length value and big-endian byte ordering for all stored integers.
	//       Both PostgreSQL and YugabyteDB support comparison of big-endian bytes through the BYTEA data type
	//       and standard comparison operators.
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, bInfo.Number)
	return db.retry.Execute(ctx,
		"set_last_committed_block_number",
		db.metrics.databaseRetryCounterByOperation, func() error {
			_, err := db.pool.Exec(ctx, setMetadataPrepStmt, []byte(lastCommittedBlockNumberKey), v)
			return errors.Wrapf(err, "failed to set the last committed block number")
		})
}

// commit commits the writes to the database.
func (db *database) commit(ctx context.Context, states *statesToBeCommitted) (namespaceToReads, []TxID, error) {
	start := time.Now()
	if states.empty() {
		return nil, nil, nil
	}

	// We want to commit all the writes to all namespaces or none at all,
	// so we use a database transaction. Otherwise, the failure and recovery
	// logic will be very complicated.
	tx, rollBackFunc, err := db.beginTx(ctx)
	if err != nil {
		return nil, nil, err
	}

	// This will be executed if an error occurs. If transaction is committed, this will be a no-op.
	defer rollBackFunc()

	mismatched, duplicated, err := db.commitStatesByGroup(ctx, tx, states)
	if err != nil {
		return nil, nil, fmt.Errorf("failed tx commitInner: %w", err) //nolint:wrapcheck
	}
	if !mismatched.empty() || len(duplicated) > 0 {
		// rollback
		return mismatched, duplicated, nil
	}

	err = tx.Commit(ctx)
	promutil.Observe(db.metrics.databaseTxBatchCommitLatencySeconds, time.Since(start))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed tx commit")
	}

	return nil, nil, nil
}

func (db *database) commitStatesByGroup(
	ctx context.Context,
	tx pgx.Tx,
	states *statesToBeCommitted,
) (namespaceToReads, []TxID, error) {
	// Because the coordinator might submit duplicate transactions during connection issues,
	// we must commit transaction IDs first. This allows us to detect conflicts early,
	// as another vcservice instance might have already committed the same transaction.
	// If we don't commit transaction IDs first, there are other consequences. These
	// could be mitigated by adding writes with a null version present in BlindWrites
	// to the readToTxIDs map, but committing the IDs upfront is a cleaner solution.
	duplicated, err := db.commitTxStatus(ctx, tx, states)
	if err != nil {
		return nil, nil, fmt.Errorf("failed tx execCommitTxStatus: %w", err) //nolint:wrapcheck
	}

	if len(duplicated) > 0 {
		// Since a duplicate ID causes a rollback, we fail fast.
		logger.Debugf("%d duplicated keys were found", len(duplicated))
		return nil, duplicated, nil
	}

	mismatched, err := db.commitNewKeys(tx, states.newWrites)
	if err != nil {
		return nil, nil, fmt.Errorf("failed tx commitNewKeys: %w", err) //nolint:wrapcheck
	}

	if !mismatched.empty() {
		// Since a mismatch causes a rollback, we fail fast.
		logger.Debugf("%d mismatched were found", len(mismatched))
		return mismatched, nil, nil
	}

	// Updates cannot have a mismatch because their versions are validated beforehand.
	if err = db.commitUpdates(ctx, tx, states.updateWrites); err != nil {
		return nil, nil, fmt.Errorf("failed tx execCommitUpdate: %w", err) //nolint:wrapcheck
	}

	return nil, nil, nil
}

func (db *database) commitTxStatus(
	ctx context.Context,
	tx pgx.Tx,
	states *statesToBeCommitted,
) ([]TxID /* duplicated */, error) {
	start := time.Now()
	if states.batchStatus == nil || len(states.batchStatus.Status) == 0 {
		return nil, nil
	}

	numEntries := len(states.batchStatus.Status)
	ids := make([][]byte, 0, numEntries)
	statues := make([]int, 0, numEntries)
	heights := make([][]byte, 0, numEntries)
	for tID, status := range states.batchStatus.Status {
		// We cannot commit a "duplicated ID" status since we already have a status entry with this ID.
		if status.Code == protoblocktx.Status_ABORTED_DUPLICATE_TXID {
			continue
		}
		ids = append(ids, []byte(tID))
		statues = append(statues, int(status.Code))
		blkAndTxNum, ok := states.txIDToHeight[TxID(tID)]
		if !ok {
			return nil, errors.Newf("block and tx number is not passed for txID %s", tID)
		}
		heights = append(heights, blkAndTxNum.ToBytes())
	}

	ret := tx.QueryRow(ctx, commitTxStatusSQLTemplate, ids, statues, heights)
	duplicated, err := readInsertResult(ret, ids)
	if err != nil {
		return nil, fmt.Errorf("failed fetching results from query: %w", err) //nolint:wrapcheck
	}
	if len(duplicated) == 0 {
		promutil.Observe(db.metrics.databaseTxBatchCommitTxsStatusLatencySeconds, time.Since(start))
		return nil, nil
	}

	duplicatedTx := make([]TxID, len(duplicated))
	for i, v := range duplicated {
		duplicatedTx[i] = TxID(v)
	}
	logger.Debugf("Total number of duplicated txs: %v", len(duplicatedTx))
	promutil.Observe(db.metrics.databaseTxBatchCommitTxsStatusLatencySeconds, time.Since(start))
	return duplicatedTx, nil
}

func (db *database) commitNewKeys(
	tx pgx.Tx, nsToWrites namespaceToWrites,
) (namespaceToReads /* mismatched */, error) {
	start := time.Now()
	defer func() {
		promutil.Observe(
			db.metrics.databaseTxBatchCommitInsertNewKeyWithValueLatencySeconds,
			time.Since(start),
		)
	}()

	mismatch := make(namespaceToReads)
	for nsID, writes := range nsToWrites {
		if writes.empty() {
			continue
		}

		q := fmt.Sprintf(commitNewWritesSQLTemplate, nsID)
		ret := tx.QueryRow(context.Background(), q, writes.keys, writes.values)
		violating, err := readInsertResult(ret, writes.keys)
		if err != nil {
			return nil, fmt.Errorf("namespace "+nsID+": failed fetching results from query: %w", err) //nolint:wrapcheck
		}

		if len(violating) > 0 {
			// We can use arbitrary versions from the list of writes since they are all 'nil'.
			logger.Debugf("Total number of mismatch: %v for namespace %s", len(mismatch), nsID)
			mismatch.getOrCreate(nsID).appendMany(violating, writes.versions[:len(violating)])
		}
	}

	if len(mismatch) > 0 {
		logger.Debugf("For all namespaces: Total number of mismatch: %v", len(mismatch))
		return mismatch, nil
	}

	return nil, db.createTablesAndFunctionsForNamespace(tx, nsToWrites[types.MetaNamespaceID])
}

func (db *database) commitUpdates(ctx context.Context, tx pgx.Tx, nsToWrites namespaceToWrites) error {
	start := time.Now()
	for nsID, writes := range nsToWrites {
		if writes.empty() {
			continue
		}

		query := fmt.Sprintf(commitUpdateWritesSQLTemplate, nsID)
		_, err := tx.Exec(ctx, query, writes.keys, writes.values, writes.versions)
		if err != nil {
			return errors.Wrap(err, "namespace "+nsID+": failed tx exec")
		}
	}
	promutil.Observe(db.metrics.databaseTxBatchCommitUpdateLatencySeconds, time.Since(start))

	return nil
}

func (db *database) createTablesAndFunctionsForNamespace(tx pgx.Tx, newNs *namespaceWrites) error {
	if newNs == nil {
		return nil
	}

	for _, ns := range newNs.keys {
		nsID := string(ns)

		tableName := TableName(nsID)
		logger.Debugf("Creating table %s for namespace %s", tableName, ns)
		for _, stmt := range initStatementsWithTemplate {
			if _, err := tx.Exec(context.Background(), fmt.Sprintf(stmt, tableName)); err != nil {
				return err
			}
		}
	}

	return nil
}

func (db *database) beginTx(ctx context.Context) (pgx.Tx, func(), error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed tx begin")
	}

	return tx, func() {
		rollbackErr := tx.Rollback(context.Background())
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			logger.Warn("failed rolling-back transaction: ", rollbackErr)
		}
	}, nil
}

func (s *statesToBeCommitted) empty() bool {
	return s.updateWrites.empty() && s.newWrites.empty() && (s.batchStatus == nil || len(s.batchStatus.Status) == 0)
}

// readKeysAndValues reads the keys and values from the given rows.
func readKeysAndValues[K, V any](r pgx.Rows) ([]K, []V, error) {
	var keys []K
	var values []V

	for r.Next() {
		var key K
		var value V
		if err := r.Scan(&key, &value); err != nil {
			return nil, nil, errors.Wrap(err, "failed while scaning a row")
		}
		keys = append(keys, key)
		values = append(values, value)
	}

	return keys, values, errors.Wrap(r.Err(), "failed while reading from rows")
}

func readInsertResult(r pgx.Row, allKeys [][]byte) ([][]byte, error) {
	var res []pgtype.Value
	if err := r.Scan(&res); err != nil {
		return nil, errors.Wrap(err, "failed to read value from the current row")
	}

	var result string
	if err := res[0].AssignTo(&result); err != nil {
		return nil, errors.Wrap(err, "failed reading result")
	}
	switch result {
	case "success":
		return nil, nil
	case "all-unique-violation":
		return allKeys, nil
	default:
	}

	var violating [][]byte
	if err := res[1].AssignTo(&violating); err != nil {
		return nil, errors.Wrap(err, "failed reading violating")
	}

	return violating, nil
}

// TableName returns the table name for the given namespace.
func TableName(nsID string) string {
	return fmt.Sprintf(tableNameTemplate, nsID)
}

func (db *database) readStatusWithHeight(
	ctx context.Context,
	txIDs [][]byte,
) (map[string]*protoblocktx.StatusWithHeight, error) {
	var rows map[string]*protoblocktx.StatusWithHeight
	retryErr := db.retry.Execute(ctx, "read_status_with_height", db.metrics.databaseRetryCounterByOperation, func() error {
		r, err := db.pool.Query(ctx, queryTxIDsStatus, txIDs)
		if err != nil {
			return errors.Wrap(err, "failed to query txIDs from the tx_status table")
		}
		defer r.Close()

		// reset map every retry
		rows = make(map[string]*protoblocktx.StatusWithHeight)
		for r.Next() {
			var id []byte
			var status int32
			var height []byte

			if err = r.Scan(&id, &status, &height); err != nil {
				return errors.Wrap(err, "failed to read rows from the query result")
			}

			ht, _, err := types.NewHeightFromBytes(height)
			if err != nil {
				return fmt.Errorf("failed to create height from encoded bytes [%v]: %w", height, err)
			}

			rows[string(id)] = types.CreateStatusWithHeight(protoblocktx.Status(status), ht.BlockNum, int(ht.TxNum))
		}
		return r.Err()
	})

	return rows, errors.Wrap(retryErr, "error occurred while reading")
}

func (db *database) readNamespacePolicies(ctx context.Context) (*protoblocktx.NamespacePolicies, error) {
	keys, values, err := db.retryQueryAndReadRows(ctx, queryPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to read from rows of meta namespace: %w", err) //nolint:wrapcheck
	}
	policy := &protoblocktx.NamespacePolicies{
		Policies: make([]*protoblocktx.PolicyItem, len(keys)),
	}
	for i, key := range keys {
		policy.Policies[i] = &protoblocktx.PolicyItem{
			Namespace: string(key),
			Policy:    values[i],
		}
		logger.Debugf("Policy of namespace %v is %v", key, values[i])
	}
	return policy, nil
}

func (db *database) readConfigTX(ctx context.Context) (*protoblocktx.ConfigTransaction, error) {
	_, values, err := db.retryQueryAndReadRows(ctx, queryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read from rows of meta namespace: %w", err) //nolint:wrapcheck
	}
	configTX := &protoblocktx.ConfigTransaction{}
	for _, v := range values {
		configTX.Envelope = v
	}
	return configTX, nil
}

func (db *database) retryQueryAndReadRows(
	ctx context.Context, query string, args ...any,
) (rows [][]byte,
	metadata [][]byte,
	err error,
) {
	var (
		values [][]byte
		keys   [][]byte
	)
	retryErr := db.retry.Execute(ctx, "query_and_read_rows", db.metrics.databaseRetryCounterByOperation, func() error {
		rows, err := db.pool.Query(ctx, query, args...)
		if err != nil {
			return errors.Wrap(err, "failed to query rows")
		}
		defer rows.Close()
		keys, values, err = readKeysAndValues[[]byte, []byte](rows)
		return err
	})

	if retryErr != nil {
		return keys, values, fmt.Errorf("error reading rows: %w", retryErr) //nolint:wrapcheck
	}
	return keys, values, retryErr //nolint:wrapcheck
}
