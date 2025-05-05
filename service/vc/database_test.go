package vc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
)

const (
	ns1 = "1"
	ns2 = "2"
)

var (
	v0 = types.VersionNumber(0).Bytes()
	v1 = types.VersionNumber(1).Bytes()
)

func newDatabaseTestEnvWithTablesSetup(t *testing.T) *DatabaseTestEnv {
	t.Helper()
	env := NewDatabaseTestEnv(t)
	ctx, _ := createContext(t)
	require.NoError(t, env.DB.setupSystemTablesAndNamespaces(ctx))
	return env
}

func TestValidateNamespaceReads(t *testing.T) {
	t.Parallel()
	env := newDatabaseTestEnvWithTablesSetup(t)

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")
	k6 := []byte("key6")
	k7 := []byte("key7")
	k8 := []byte("key8")
	k9 := []byte("key9")

	env.populateData(
		t,
		[]string{ns1, ns2},
		namespaceToWrites{
			ns1: {
				keys:     [][]byte{k1, k2, k3},
				values:   [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")},
				versions: [][]byte{v0, v0, v0},
			},
			ns2: {
				keys:     [][]byte{k4, k5, k6},
				values:   [][]byte{[]byte("value4"), []byte("value5"), []byte("value6")},
				versions: [][]byte{v1, v1, v1},
			},
		},
		nil,
		nil,
	)

	tests := []struct {
		name                  string
		nsID                  string
		r                     *reads
		expectedReadConflicts *reads
	}{
		{
			name:                  "empty reads",
			nsID:                  ns1,
			r:                     &reads{},
			expectedReadConflicts: &reads{},
		},
		{
			name: "reads of only non-existing keys and all matching versions",
			nsID: ns1,
			r: &reads{
				keys:     [][]byte{k4, k5, k6},
				versions: [][]byte{nil, nil, nil},
			},
			expectedReadConflicts: &reads{},
		},
		{
			name: "reads of only non-existing keys and some mismatching versions",
			nsID: ns2,
			r: &reads{
				keys:     [][]byte{k7, k8, k9},
				versions: [][]byte{nil, v0, nil},
			},
			expectedReadConflicts: &reads{
				keys:     [][]byte{k8},
				versions: [][]byte{v0},
			},
		},
		{
			name: "reads of only non-existing keys and all mismatching versions",
			nsID: ns2,
			r: &reads{
				keys:     [][]byte{k7, k8, k9},
				versions: [][]byte{v1, v0, v1},
			},
			expectedReadConflicts: &reads{
				keys:     [][]byte{k7, k8, k9},
				versions: [][]byte{v1, v0, v1},
			},
		},
		{
			name: "reads of existing keys and all matching versions",
			nsID: ns1,
			r: &reads{
				keys:     [][]byte{k1, k2, k3},
				versions: [][]byte{v0, v0, v0},
			},
			expectedReadConflicts: &reads{},
		},
		{
			name: "reads of existing keys and some mismatching versions",
			nsID: ns1,
			r: &reads{
				keys:     [][]byte{k1, k2, k3},
				versions: [][]byte{v1, v0, v1},
			},
			expectedReadConflicts: &reads{
				keys:     [][]byte{k1, k3},
				versions: [][]byte{v1, v1},
			},
		},
		{
			name: "reads of existing keys and all mismatching versions",
			nsID: ns2,
			r: &reads{
				keys:     [][]byte{k4, k5, k6},
				versions: [][]byte{v0, v0, v0},
			},
			expectedReadConflicts: &reads{
				keys:     [][]byte{k4, k5, k6},
				versions: [][]byte{v0, v0, v0},
			},
		},
		{
			name: "reads of existing and non-existing keys and some mismatching versions",
			nsID: ns2,
			r: &reads{
				keys:     [][]byte{k4, k5, k6, k7, k8, k9},
				versions: [][]byte{v1, v0, v1, nil, v0, nil},
			},
			expectedReadConflicts: &reads{
				keys:     [][]byte{k5, k8},
				versions: [][]byte{v0, v0},
			},
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			readConflicts, err := env.DB.validateNamespaceReads(t.Context(), tt.nsID, tt.r)
			require.NoError(t, err)
			require.ElementsMatch(t, toComparableReads(tt.expectedReadConflicts), toComparableReads(readConflicts))
		})
	}
}

func TestDBCommit(t *testing.T) {
	t.Parallel()
	dbEnv := newDatabaseTestEnvWithTablesSetup(t)

	require.Equal(t, dbEnv.DBConf.Retry, dbEnv.DB.retry)

	dbEnv.populateData(
		t,
		[]string{ns1, ns2},
		nil,
		nil,
		nil,
	)

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")
	k6 := []byte("key6")

	nsToWrites := namespaceToWrites{
		ns1: {
			keys:     [][]byte{k1, k2, k3},
			values:   [][]byte{[]byte("value1"), []byte("value2"), []byte("value3")},
			versions: [][]byte{v0, v0, v0},
		},
		ns2: {
			keys:     [][]byte{k4, k5, k6},
			values:   [][]byte{[]byte("value4"), []byte("value5"), []byte("value6")},
			versions: [][]byte{v1, v1, v1},
		},
		types.MetaNamespaceID: {
			keys:     [][]byte{[]byte("3"), []byte("4")},
			values:   [][]byte{[]byte("value7"), []byte("value8")},
			versions: [][]byte{v0, v0, v0},
		},
	}

	commit(t, dbEnv, &statesToBeCommitted{newWrites: nsToWrites})
	commit(t, dbEnv, &statesToBeCommitted{updateWrites: nsToWrites})
	dbEnv.rowExists(t, ns1, *nsToWrites[ns1])
	dbEnv.rowExists(t, ns2, *nsToWrites[ns2])
	dbEnv.rowExists(t, types.MetaNamespaceID, *nsToWrites[types.MetaNamespaceID])
	dbEnv.tableExists(t, "3")
	dbEnv.tableExists(t, "4")

	nsToWrites = namespaceToWrites{
		"3": {
			keys:     [][]byte{k1, k2},
			values:   [][]byte{[]byte("value1"), []byte("value2")},
			versions: [][]byte{v0, v0},
		},
		"4": {
			keys:     [][]byte{k4, k5},
			values:   [][]byte{[]byte("value4"), []byte("value5")},
			versions: [][]byte{v0, v0},
		},
	}

	commit(t, dbEnv, &statesToBeCommitted{newWrites: nsToWrites})
	dbEnv.rowExists(t, "3", *nsToWrites["3"])
	dbEnv.rowExists(t, "4", *nsToWrites["4"])
}

func commit(t *testing.T, dbEnv *DatabaseTestEnv, states *statesToBeCommitted) {
	t.Helper()
	require.NoError(t, dbEnv.DBConf.Retry.Execute(
		t.Context(),
		"test_commit",
		dbEnv.DB.metrics.failedRetriesCounter, func() error {
			_, _, err := dbEnv.DB.commit(t.Context(), states)
			return err
		}))
}

func toComparableReads(r *reads) []comparableRead {
	if r == nil || len(r.keys) == 0 {
		return nil
	}

	compReads := make([]comparableRead, len(r.keys))
	for i := range r.keys {
		compReads[i] = comparableRead{
			key:     string(r.keys[i]),
			version: string(r.versions[i]),
		}
	}
	return compReads
}
