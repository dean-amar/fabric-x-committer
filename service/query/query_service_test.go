package query

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yugabyte/pgx/v4/pgxpool"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/protoqueryservice"
	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/adapters"
	"github.ibm.com/decentralized-trust-research/scalable-committer/loadgen/workload"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/vc"
	"github.ibm.com/decentralized-trust-research/scalable-committer/service/verifier/policy"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/monitoring"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/signature"
	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/test"
)

type queryServiceTestEnv struct {
	config        *Config
	ctx           context.Context
	qs            *Service
	ns            []string
	clientConn    *grpc.ClientConn
	pool          *pgxpool.Pool
	disabledViews []string
}

func TestQuery(t *testing.T) {
	t.Parallel()
	env := newQueryServiceTestEnv(t)

	requiredItems := make([]*items, len(env.ns))
	for i, ns := range env.ns {
		requiredItems[i] = &items{
			ns:       ns,
			keys:     strToBytes("item1", "item2", "item3", "item4"),
			values:   strToBytes("value1", "value2", "value3", "value4"),
			versions: verToBytes(0, 1, 2, 3),
		}
		env.insert(t, requiredItems[i])
	}

	query := &protoqueryservice.Query{}
	querySize := 0
	keyCount := 0
	for _, item := range requiredItems {
		keyCount += len(item.keys)
		qNs := item.asQuery()
		query.Namespaces = append(query.Namespaces, qNs)
		querySize += len(qNs.Keys)
	}

	csParams := &protoqueryservice.ViewParameters{
		IsoLevel:            protoqueryservice.IsoLevel_RepeatableRead,
		NonDeferrable:       false,
		TimeoutMilliseconds: uint64(time.Minute.Milliseconds()), // nolint:gosec
	}

	for i, qNs := range query.Namespaces {
		t.Run(fmt.Sprintf("Query internal NS %s", qNs.NsId), func(t *testing.T) {
			ret, err := unsafeQueryRows(env.ctx, env.qs.batcher.pool, qNs.NsId, qNs.Keys)
			require.NoError(t, err)
			requireRow(t, requiredItems[i], &protoqueryservice.RowsNamespace{
				NsId: qNs.NsId,
				Rows: ret,
			})
		})
	}

	expectedMetricsSize := 0

	t.Run("Query GetRows interface", func(t *testing.T) {
		ret, err := env.qs.GetRows(env.ctx, query)
		require.NoError(t, err)
		expectedMetricsSize++
		requireResults(t, requiredItems, ret.Namespaces)
	})

	t.Run("Query GetRows client", func(t *testing.T) {
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)
		ret, err := client.GetRows(env.ctx, query)
		require.NoError(t, err)
		expectedMetricsSize++
		requireResults(t, requiredItems, ret.Namespaces)
	})

	t.Run("Query GetRows client with consistentView", func(t *testing.T) {
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)
		ret, err := client.GetRows(env.ctx, &protoqueryservice.Query{
			View:       env.beginView(t, client, csParams),
			Namespaces: query.Namespaces,
		})
		require.NoError(t, err)
		expectedMetricsSize++
		requireResults(t, requiredItems, ret.Namespaces)

		requireMapSize(t, 1, &env.qs.batcher.viewIDToViewHolder)
		requireIntVecMetricValue(t, 1, env.qs.metrics.requests.MetricVec, grpcBeginView)
		requireIntMetricValue(t, 1, env.qs.metrics.processingSessions.WithLabelValues(sessionViews))
		requireIntMetricValue(t, 1, env.qs.metrics.processingSessions.WithLabelValues(sessionTransactions))
	})

	requireMapSize(t, 0, &env.qs.batcher.viewIDToViewHolder)
	requireIntVecMetricValue(t, expectedMetricsSize, env.qs.metrics.requests.MetricVec, grpcGetRows)
	requireIntMetricValue(t, expectedMetricsSize*querySize, env.qs.metrics.keysRequested)
	requireIntMetricValue(t, expectedMetricsSize*keyCount, env.qs.metrics.keysResponded)

	t.Run("Consistency with repeated GetRows", func(t *testing.T) {
		// This test will query key1, then update key2.
		// We expect that the updated key2 will not be visible to GetRows() with the initial view.
		// But it will be visible to a new view.
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)

		t1 := requiredItems[0]
		testItem1 := items{"0", t1.keys[:1], t1.values[:1], t1.versions[:1]}

		view := env.beginView(t, client, csParams)
		ret, err := client.GetRows(env.ctx, &protoqueryservice.Query{
			View: view,
			Namespaces: []*protoqueryservice.QueryNamespace{{
				NsId: testItem1.ns,
				Keys: testItem1.keys,
			}},
		})
		require.NoError(t, err)

		requireResults(t, []*items{&testItem1}, ret.Namespaces)

		testItem2 := items{testItem1.ns, t1.keys[1:2], t1.values[1:2], t1.versions[1:2]}
		testItem2Mod := testItem2
		testItem2Mod.values = strToBytes("value2.1")
		testItem2Mod.versions = verToBytes(2)
		env.update(t, &testItem2Mod)

		key2Query := &protoqueryservice.Query{
			View: view,
			Namespaces: []*protoqueryservice.QueryNamespace{{
				NsId: testItem2.ns,
				Keys: testItem2.keys,
			}},
		}
		ret2, err := client.GetRows(env.ctx, key2Query)
		require.NoError(t, err)
		// This is the same view, so we expect the old version of item 2.
		requireResults(t, []*items{&testItem2}, ret2.Namespaces)

		view2 := env.beginView(t, client, csParams)
		key2Query.View = view2
		ret3, err := client.GetRows(env.ctx, key2Query)
		require.NoError(t, err)
		// This is a new view, but it should be aggregated with the previous one.
		// So we expect the old version of item 2.
		requireResults(t, []*items{&testItem2}, ret3.Namespaces)

		env.endView(t, client, view)
		env.endView(t, client, view2)

		view3 := env.beginView(t, client, csParams)
		key2Query.View = view3
		ret4, err := client.GetRows(env.ctx, key2Query)
		require.NoError(t, err)
		// After we cancelled the other views, a new view should create
		// a new transactions. So we expect the new version of item 2.
		requireResults(t, []*items{&testItem2Mod}, ret4.Namespaces)
	})

	t.Run("Nil view parameters", func(t *testing.T) {
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)
		env.beginView(t, client, nil)
	})

	t.Run("Bad view ID", func(t *testing.T) {
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)
		_, err := client.EndView(env.ctx, &protoqueryservice.View{Id: "bad"})
		require.Equal(t, ErrInvalidOrStaleView.Error(), status.Convert(err).Message())
	})

	t.Run("Cancelled view ID", func(t *testing.T) {
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)
		view, err := client.BeginView(env.ctx, csParams)
		require.NoError(t, err)
		_, err = client.EndView(env.ctx, view)
		require.NoError(t, err)
		_, err = client.EndView(env.ctx, view)
		require.Equal(t, ErrInvalidOrStaleView.Error(), status.Convert(err).Message())
	})

	t.Run("Expired view ID", func(t *testing.T) {
		client := protoqueryservice.NewQueryServiceClient(env.clientConn)
		params := &protoqueryservice.ViewParameters{
			IsoLevel:            csParams.IsoLevel,
			NonDeferrable:       csParams.NonDeferrable,
			TimeoutMilliseconds: 100,
		}
		view, err := client.BeginView(env.ctx, params)
		require.NoError(t, err)
		time.Sleep(150 * time.Millisecond)
		_, err = client.EndView(env.ctx, view)
		require.ErrorContains(t, err, status.Convert(err).Message())
	})

	// Check view and transaction's life cycle.
	// We sleep to allow all the context's after functions to fire.
	time.Sleep(time.Millisecond)
	requireMapSize(t, 0, &env.qs.batcher.viewIDToViewHolder)
	requireIntMetricValue(t, 0, env.qs.metrics.processingSessions.WithLabelValues(sessionViews))
	requireIntMetricValue(t, 0, env.qs.metrics.processingSessions.WithLabelValues(sessionTransactions))
}

func TestQueryPolicies(t *testing.T) {
	t.Parallel()
	env := newQueryServiceTestEnv(t)

	client := protoqueryservice.NewQueryServiceClient(env.clientConn)
	policies, err := client.GetNamespacePolicies(env.ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, policies)
	require.Len(t, policies.Policies, len(env.ns))

	expectedNamespaces := make(map[string]any, len(env.ns))
	for _, ns := range env.ns {
		expectedNamespaces[ns] = nil
	}

	for _, p := range policies.Policies {
		_, ok := expectedNamespaces[p.Namespace]
		require.True(t, ok)
		delete(expectedNamespaces, p.Namespace)
		item, parseErr := policy.ParseNamespacePolicyItem(p)
		require.NoError(t, parseErr)
		require.Equal(t, signature.Ecdsa, item.Scheme)
	}

	configTX, err := client.GetConfigTransaction(env.ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, configTX)
	require.NotEmpty(t, configTX.Envelope)
}

func requireMapSize(t *testing.T, expectedSize int, m *sync.Map) {
	t.Helper()
	n := 0
	m.Range(func(_, _ any) bool {
		n++
		return true
	})
	require.Equal(t, expectedSize, n)
}

func strToBytes(str ...string) [][]byte {
	ret := make([][]byte, len(str))
	for i, s := range str {
		ret[i] = []byte(s)
	}
	return ret
}

func verToBytes(ver ...int) [][]byte {
	ret := make([][]byte, len(ver))
	for i, v := range ver {
		ret[i] = types.VersionNumber(v).Bytes() //nolint:gosec
	}
	return ret
}

func newQueryServiceTestEnv(t *testing.T) *queryServiceTestEnv {
	t.Helper()
	t.Log("generating config and namespaces")
	namespacesToTest := []string{"0", "1", "2"}
	dbConf := generateNamespacesUnderTest(t, namespacesToTest)

	config := &Config{
		MinBatchKeys:          5,
		MaxBatchWait:          time.Second,
		ViewAggregationWindow: time.Minute,
		MaxViewTimeout:        time.Minute,
		MaxAggregatedViews:    5,
		Server: &connection.ServerConfig{
			Endpoint: connection.Endpoint{
				Host: "localhost",
				Port: 0,
			},
		},
		Database: dbConf,
		Monitoring: monitoring.Config{
			Server: connection.NewLocalHostServer(),
		},
	}

	qs := NewQueryService(config)
	sConfig := &connection.ServerConfig{
		Endpoint: connection.Endpoint{Host: "localhost", Port: 0},
	}
	test.RunServiceAndGrpcForTest(t.Context(), t, qs, sConfig, func(server *grpc.Server) {
		protoqueryservice.RegisterQueryServiceServer(server, qs)
	})

	clientConn, err := connection.Connect(connection.NewDialConfig(&sConfig.Endpoint))
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, clientConn.Close())
	})

	// We set a default context with timeout to make sure the test never halts progress.
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute*10)
	t.Cleanup(cancel)

	pool, err := vc.NewDatabasePool(ctx, config.Database, qs.metrics.databaseRetryCounterByOperation)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return &queryServiceTestEnv{
		config:     config,
		ctx:        ctx,
		qs:         qs,
		ns:         namespacesToTest,
		clientConn: clientConn,
		pool:       pool,
	}
}

func generateNamespacesUnderTest(t *testing.T, namespaces []string) *vc.DatabaseConfig {
	t.Helper()
	env := vc.NewValidatorAndCommitServiceTestEnv(t, 1)

	clientConf := loadgen.DefaultClientConf()
	clientConf.Adapter.VCClient = &adapters.VCClientConfig{
		Endpoints: env.Endpoints,
	}
	policies := &workload.PolicyProfile{
		NamespacePolicies: make(map[string]*workload.Policy, len(namespaces)),
	}
	for i, ns := range append(namespaces, types.MetaNamespaceID) {
		policies.NamespacePolicies[ns] = &workload.Policy{
			Scheme: signature.Ecdsa,
			Seed:   int64(i),
		}
	}
	clientConf.LoadProfile.Transaction.Policy = policies
	clientConf.Generate = adapters.Phases{Config: true, Namespaces: true}
	client, err := loadgen.NewLoadGenClient(clientConf)
	require.NoError(t, err)
	err = client.Run(t.Context())
	require.NoError(t, connection.FilterStreamRPCError(err))
	return env.DBEnv.DBConf
}

type items struct {
	ns                     string
	keys, values, versions [][]byte
}

func (it *items) asRows() []*protoqueryservice.Row {
	rows := make([]*protoqueryservice.Row, len(it.keys))
	for i, k := range it.keys {
		rows[i] = &protoqueryservice.Row{
			Key:     k,
			Value:   it.values[i],
			Version: it.versions[i],
		}
	}
	return rows
}

func (it *items) asQuery() *protoqueryservice.QueryNamespace {
	q := &protoqueryservice.QueryNamespace{
		NsId: it.ns,
		// Add additional item that does not exist.
		Keys: append(it.keys, strToBytes("non-tx")...),
	}
	return q
}

func (q *queryServiceTestEnv) insert(t *testing.T, i *items) {
	t.Helper()
	query := fmt.Sprintf(
		`insert into %s values (
			UNNEST($1::bytea[]), UNNEST($2::bytea[]), UNNEST($3::bytea[])
		);`,
		vc.TableName(i.ns),
	)
	_, err := q.pool.Exec(q.ctx, query, i.keys, i.values, i.versions)
	require.NoError(t, err)
}

func (q *queryServiceTestEnv) update(t *testing.T, i *items) {
	t.Helper()
	query := fmt.Sprintf(`
		UPDATE %[1]s
			SET value = t.value,
				version = t.version
		FROM (
			SELECT * FROM UNNEST($1::bytea[], $2::bytea[], $3::bytea[]) AS t(key, value, version)
		) AS t
		WHERE %[1]s.key = t.key;
		`,
		vc.TableName(i.ns),
	)
	_, err := q.pool.Exec(q.ctx, query, i.keys, i.values, i.versions)
	require.NoError(t, err)
}

func requireResults(
	t *testing.T,
	expected []*items,
	ret []*protoqueryservice.RowsNamespace,
) {
	t.Helper()
	require.Len(t, ret, len(expected))
	for i, item := range expected {
		requireRow(t, item, ret[i])
	}
}

func requireRow(
	t *testing.T,
	expected *items,
	ret *protoqueryservice.RowsNamespace,
) {
	t.Helper()
	require.Equal(t, expected.ns, ret.NsId)
	require.ElementsMatch(t, expected.asRows(), ret.Rows)
}

func requireIntMetricValue(t *testing.T, expected int, m prometheus.Metric) {
	require.Equal(t, expected, int(test.GetMetricValue(t, m)))
}

func requireIntVecMetricValue(t *testing.T, expected int, mv *prometheus.MetricVec, lvs ...string) {
	t.Helper()
	m, err := mv.GetMetricWithLabelValues(lvs...)
	require.NoError(t, err)
	requireIntMetricValue(t, expected, m)
}

func (q *queryServiceTestEnv) beginView(
	t *testing.T,
	client protoqueryservice.QueryServiceClient,
	params *protoqueryservice.ViewParameters,
) *protoqueryservice.View {
	t.Helper()
	view, err := client.BeginView(q.ctx, params)
	require.NoError(t, err)
	require.NotNil(t, view)
	require.NotEmpty(t, view.Id)
	t.Cleanup(func() {
		if slices.Contains(q.disabledViews, view.Id) {
			return
		}
		_, err = client.EndView(q.ctx, view)
		require.NoError(t, err)
	})
	return view
}

func (q *queryServiceTestEnv) endView(
	t *testing.T,
	client protoqueryservice.QueryServiceClient,
	view *protoqueryservice.View,
) {
	t.Helper()
	_, err := client.EndView(q.ctx, view)
	require.NoError(t, err)
	q.disabledViews = append(q.disabledViews, view.Id)
}
