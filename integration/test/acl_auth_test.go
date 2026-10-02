/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

const aclNamespace = "1"

// TestACLQuery walks the mechanism end to end against a live system with two AuthService instances, so
// nonces and tokens cross them: a row committed through the ordinary transaction path is readable with a
// token, refused without one, and a scoped token reaches only the RPCs it names.
func TestACLQuery(t *testing.T) {
	t.Parallel()
	c := newACLRuntime(t, 2)
	ctx := t.Context()

	// Step 1: Commit a transaction through the normal path, so the query has something real to find.
	t.Log("Step 1: commit a row through the orderer")
	txIDs := c.MakeAndSendTransactionsToOrderer(t, [][]*applicationpb.TxNamespace{{{
		NsId:        aclNamespace,
		BlindWrites: []*applicationpb.Write{{Key: []byte("k1"), Value: []byte("v1")}},
	}}}, []committerpb.Status{committerpb.Status_COMMITTED})
	require.Len(t, txIDs, 1)

	// Step 2: The query service authorizes every RPC against the AuthService, so this proves the whole
	// chain: nonce -> envelope -> token -> interceptor -> Authorize -> handler.
	t.Log("Step 2: query the committed row with a token")
	rows, err := getRows(acl.ContextWithToken(ctx, c.AuthEnv.IssueToken(t)), c)
	require.NoError(t, err)
	test.RequireProtoElementsMatch(t, []*committerpb.RowsNamespace{{
		NsId: aclNamespace,
		Rows: []*committerpb.Row{{Key: []byte("k1"), Value: []byte("v1")}},
	}}, rows.GetNamespaces())

	// Step 3: The same query without a token is refused before the handler. The runtime's client carries
	// no token of its own; it only ever sends what the context holds.
	t.Log("Step 3: the same query without a token is refused")
	_, err = getRows(ctx, c)
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))

	// Step 4: A token scoped to GetRows reaches GetRows and nothing else, even where the caller's policy
	// would allow more - which also proves the interceptor authorizes by the gRPC full-method name.
	t.Log("Step 4: a token scoped to GetRows is denied any other RPC")
	scopedParams := *c.AuthEnv.IssueParams
	scopedParams.Scope = []string{committerpb.QueryService_GetRows_FullMethodName}
	scoped, err := acl.IssueToken(ctx, &scopedParams)
	require.NoError(t, err)
	scopedCtx := acl.ContextWithToken(ctx, scoped.GetToken())
	_, err = getRows(scopedCtx, c)
	require.NoError(t, err)
	_, err = c.QueryServiceClient.GetTransactionStatus(scopedCtx, &committerpb.TxStatusQuery{TxIds: txIDs})
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
}

// TestACLAuthServiceRestart verifies an AuthService restart is invisible to its clients: a token issued before
// it still authorizes after it, because tokens live in the database.
func TestACLAuthServiceRestart(t *testing.T) {
	t.Parallel()
	c := newACLRuntime(t, 1)
	t.Log("Step 1: issue a token and query with it")
	tokenCtx := acl.ContextWithToken(t.Context(), c.AuthEnv.IssueToken(t))
	_, err := getRows(tokenCtx, c)
	require.NoError(t, err)

	t.Log("Step 2: stop the auth service")
	c.AuthService[0].Stop(t)
	downCtx, cancel := context.WithTimeout(tokenCtx, 30*time.Second)
	t.Cleanup(cancel)
	_, err = getRows(downCtx, c)
	require.Error(t, err)

	t.Log("Step 3: restart the auth service and require it to serve as before")
	c.AuthService[0].Restart(t)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := getRows(tokenCtx, c)
		require.NoError(ct, err)
	}, 2*time.Minute, time.Second)
}

// TestACLSurvivesAuthServiceFailure verifies that losing one of two AuthService
// instances leaves the system serving.
func TestACLSurvivesAuthServiceFailure(t *testing.T) {
	t.Parallel()
	c := newACLRuntime(t, 2)

	// Step 1: Issue while both instances serve; the token may come from either.
	t.Log("Step 1: issue a token and query with it while both instances serve")
	tokenCtx := acl.ContextWithToken(t.Context(), c.AuthEnv.IssueToken(t))
	_, err := getRows(tokenCtx, c)
	require.NoError(t, err)

	t.Log("Step 2: stop one of the two auth service instances")
	c.AuthService[0].Stop(t)

	t.Log("Step 3: require the surviving instance to serve everything")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := getRows(tokenCtx, c)
		require.NoError(ct, err)
	}, 2*time.Minute, time.Second)
}

// newACLRuntime starts a full committer whose query service enforces ACL against the given number of live
// AuthService instances. The runtime's auth client balances across them, as the query service does.
func newACLRuntime(t *testing.T, authInstances int) *runner.CommitterRuntime {
	t.Helper()
	c := runner.NewRuntime(t, &runner.Config{
		BlockTimeout:   2 * time.Second,
		NumAuthService: authInstances,
	})
	c.Start(t, runner.FullTxPathWithQuery)
	c.CreateNamespacesAndCommit(t, aclNamespace)
	return c
}

// getRows reads key k1 of the ACL test namespace, with whatever token ctx carries.
func getRows(ctx context.Context, c *runner.CommitterRuntime) (*committerpb.Rows, error) {
	return c.QueryServiceClient.GetRows(ctx, &committerpb.Query{
		Namespaces: []*committerpb.QueryNamespace{{NsId: aclNamespace, Keys: [][]byte{[]byte("k1")}}},
	})
}
