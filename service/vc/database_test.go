package vc

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.ibm.com/decentralized-trust-research/scalable-committer/api/types"
)

// TODO: all the statement templates will be moved to a different package once we decide on the
//	     chaincode deployment model.

const (
	ns1 = "1"
	ns2 = "2"
)

var (
	v0 = types.VersionNumber(0).Bytes()
	v1 = types.VersionNumber(1).Bytes()
)

func TestValidateNamespaceReads(t *testing.T) {
	env := NewDatabaseTestEnv(t)

	k1 := []byte("key1")
	k2 := []byte("key2")
	k3 := []byte("key3")
	k4 := []byte("key4")
	k5 := []byte("key5")
	k6 := []byte("key6")
	k7 := []byte("key7")
	k8 := []byte("key8")
	k9 := []byte("key9")

	env.populateDataWithCleanup(
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
		name                    string
		nsID                    string
		r                       *reads
		expectedMismatchedReads *reads
	}{
		{
			name:                    "empty reads",
			nsID:                    ns1,
			r:                       &reads{},
			expectedMismatchedReads: &reads{},
		},
		{
			name: "reads of only non-existing keys and all matching versions",
			nsID: ns1,
			r: &reads{
				keys:     [][]byte{k4, k5, k6},
				versions: [][]byte{nil, nil, nil},
			},
			expectedMismatchedReads: &reads{},
		},
		{
			name: "reads of only non-existing keys and some mismatching versions",
			nsID: ns2,
			r: &reads{
				keys:     [][]byte{k7, k8, k9},
				versions: [][]byte{nil, v0, nil},
			},
			expectedMismatchedReads: &reads{
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
			expectedMismatchedReads: &reads{
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
			expectedMismatchedReads: &reads{},
		},
		{
			name: "reads of existing keys and some mismatching versions",
			nsID: ns1,
			r: &reads{
				keys:     [][]byte{k1, k2, k3},
				versions: [][]byte{v1, v0, v1},
			},
			expectedMismatchedReads: &reads{
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
			expectedMismatchedReads: &reads{
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
			expectedMismatchedReads: &reads{
				keys:     [][]byte{k5, k8},
				versions: [][]byte{v0, v0},
			},
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mismatchingReads, err := env.DB.validateNamespaceReads(t.Context(), tt.nsID, tt.r)
			require.NoError(t, err)
			requireReadsMatch(t, tt.expectedMismatchedReads, mismatchingReads)
		})
	}
}

// requireReadsMatch asserts that the specified readA is equal to specified
// readB ignoring the order of the elements. If there are duplicate elements,
// the number of appearances of each of them in both lists should match.
func requireReadsMatch(t *testing.T, readA, readB *reads, msgAndArgs ...any) {
	// the implementation is inspired the `require.ElementsMatch` function
	// https://github.com/stretchr/testify/blob/master/require/require.go#L95
	// https://github.com/stretchr/testify/blob/master/assert/assertions.go#L1052

	// is empty?
	if readA.empty() && readB.empty() {
		return
	}

	// create diff
	extraA, extraB := diffReads(readA, readB)
	if extraA.empty() && extraB.empty() {
		return
	}

	require.Fail(t,
		fmt.Sprintf("reads differ: extra elements in A=%v and extra elements in B=%v", extraA, extraB),
		msgAndArgs...)
}

// diffReads diffs two reads and returns reads that are only in A and only in B.
// If some key/version pair is present multiple times, each instance is counted separately (e.g. if something is 2x in A
// and 5x in B, it will be 0x in extraA and 3x in extraB). The order of items in both reads is ignored.
func diffReads(readA, readB *reads) (extraA, extraB *reads) {
	// the implementation is inspired on `diffLists` used in `require.ElementsMatch` function
	// https://github.com/stretchr/testify/blob/master/assert/assertions.go#L1086

	extraA = &reads{}
	extraB = &reads{}

	aLen := len(readA.keys)
	bLen := len(readB.keys)

	// Mark indexes in bValue that we already used
	visited := make([]bool, bLen)
	for i := range aLen {
		key, version := readA.keys[i], readA.versions[i]
		found := false
		for j := range bLen {
			if visited[j] {
				continue
			}

			if bytes.Equal(readB.keys[j], key) && bytes.Equal(readB.versions[j], version) {
				visited[j] = true
				found = true
				break
			}
		}
		if !found {
			extraA.append(key, version)
		}
	}

	for j := range bLen {
		if visited[j] {
			continue
		}
		extraB.append(readB.keys[j], readB.versions[j])
	}

	return extraA, extraB
}

func TestDBCommit(t *testing.T) {
	dbEnv := NewDatabaseTestEnv(t)

	require.Equal(t, dbEnv.DBConf.Retry, dbEnv.DB.retry)

	dbEnv.populateDataWithCleanup(
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
		dbEnv.DB.metrics.databaseRetryCounterByOperation, func() error {
			_, _, err := dbEnv.DB.commit(t.Context(), states)
			return err
		}))
}
