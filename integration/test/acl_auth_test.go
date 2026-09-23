/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/service/auth"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

const (
	aclNamespace      = "1"
	aclOtherNamespace = "2"
)

// aclEnv is a running committer plus the client side of its AuthService, which auth.TestEnv already is.
type aclEnv struct {
	*auth.TestEnv
	c *runner.CommitterRuntime
}

// TestACLQueryWithAuthenticatedClient walks the mechanism end to end against a live system: nonce ->
// signed envelope -> token -> a query for a row committed through the ordinary transaction path.
func TestACLQueryWithAuthenticatedClient(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	// Step 1: Commit a transaction through the normal path, so the query has something real to find.
	t.Log("Step 1: commit a transaction through the orderer")
	env.commitRow(t, []byte("k1"), []byte("v1"))
	env.WaitForEnforcement(t)

	// Step 2: Obtain a single-use nonce - the mandatory pre-step of authentication.
	t.Log("Step 2: obtain a nonce from the auth service")
	nonce := env.Nonce(t)
	t.Logf("got nonce %s", nonce)
	require.NotEmpty(t, nonce)

	// Step 3: Sign the nonce into an envelope and exchange it for a cert-bound token.
	t.Log("Step 3: authenticate with the signed envelope carrying the nonce")
	token := env.Authenticate(t, env.Envelope(t, nonce))
	require.NotEmpty(t, token)

	// Step 4: Query with the token. The query service authorizes every RPC against the AuthService, so
	// this proves the whole chain: nonce -> envelope -> token -> interceptor -> Authorize -> handler.
	t.Log("Step 4: query the committed row with the token")
	rows, err := env.c.QueryServiceClient.GetRows(acl.ContextWithToken(t.Context(), token), &committerpb.Query{
		Namespaces: []*committerpb.QueryNamespace{
			{NsId: aclNamespace, Keys: [][]byte{[]byte("k1")}},
		},
	})
	require.NoError(t, err)

	test.RequireProtoElementsMatch(t, []*committerpb.RowsNamespace{{
		NsId: aclNamespace,
		Rows: []*committerpb.Row{{Key: []byte("k1"), Value: []byte("v1"), Version: 0}},
	}}, rows.GetNamespaces())
}

// TestACLQueryRejectedWithoutToken verifies enforcement is on: the same query without a token is refused
// before the handler. It dials its own bare client, since the runtime's carries a token by design.
func TestACLQueryRejectedWithoutToken(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	client := committerpb.NewQueryServiceClient(test.NewSecuredConnection(
		t, env.c.SystemConfig.Services.Query.GrpcEndpoint, env.c.SystemConfig.ClientTLS,
	))
	_, err := client.GetRows(t.Context(), &committerpb.Query{
		Namespaces: []*committerpb.QueryNamespace{
			{NsId: aclNamespace, Keys: [][]byte{[]byte("k1")}},
		},
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
}

// TestACLAuthenticateRejectsMissingNonce verifies an envelope with no nonce at all is refused, naming
// the missing nonce so an operator can tell it apart from a signature or policy failure.
func TestACLAuthenticateRejectsMissingNonce(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)
	env.WaitForEnforcement(t)

	_, err := env.Client.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: env.Envelope(t, nil),
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "envelope carries no nonce")
}

// TestACLAuthenticateRejectsForgedNonce verifies a client cannot invent its own challenge: only a
// nonce the server issued and still holds is redeemable.
func TestACLAuthenticateRejectsForgedNonce(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)
	env.WaitForEnforcement(t)

	_, err := env.Client.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: env.Envelope(t, []byte("a-nonce-the-server-never-issued")),
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "unknown, already used, or expired")
}

// TestACLAuthenticateRejectsReplayedEnvelope is the property the nonce exists for: a captured envelope
// cannot be redeemed twice, though it is byte-identical, correctly signed and still fresh.
func TestACLAuthenticateRejectsReplayedEnvelope(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	env.WaitForEnforcement(t)

	// Step 1: A first authentication succeeds and consumes the nonce.
	t.Log("Step 1: authenticate once, consuming the nonce")
	envelope := env.Envelope(t, env.Nonce(t))
	token := env.Authenticate(t, envelope)
	require.NotEmpty(t, token)

	// Step 2: Replay the very same envelope, as an attacker who captured it would.
	t.Log("Step 2: replay the identical envelope")
	_, err := env.Client.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "already used")
}

// newACLEnv starts a full committer whose query service enforces ACL against a live AuthService, and
// returns the pieces a client needs to authenticate against it.
func newACLEnv(t *testing.T) *aclEnv {
	t.Helper()

	c := runner.NewRuntime(t, &runner.Config{
		BlockTimeout: 2 * time.Second,
	})
	c.Start(t, runner.FullTxPathWithQuery)
	c.CreateNamespacesAndCommit(t, aclNamespace, aclOtherNamespace)

	return &aclEnv{
		c: c,
		TestEnv: &auth.TestEnv{
			Client: servicepb.NewAuthServiceClient(
				test.NewSecuredConnection(t, c.SystemConfig.Services.Auth.GrpcEndpoint, c.SystemConfig.ClientTLS),
			),
			Signer:        auth.LoadTestSigner(t, c.OrdererEnv.ArtifactsPath),
			ChannelID:     runner.TestChannelName,
			ArtifactsPath: c.OrdererEnv.ArtifactsPath,
		},
	}
}

// commitRow commits the key and value into both test namespaces through the ordering service.
func (e *aclEnv) commitRow(t *testing.T, key, value []byte) {
	t.Helper()
	txIDs := e.c.MakeAndSendTransactionsToOrderer(
		t,
		[][]*applicationpb.TxNamespace{{{
			NsId:      aclNamespace,
			NsVersion: 0,
			BlindWrites: []*applicationpb.Write{
				{Key: key, Value: value},
			},
		}}, {{
			NsId:      aclOtherNamespace,
			NsVersion: 0,
			BlindWrites: []*applicationpb.Write{
				{Key: key, Value: value},
			},
		}}},
		[]committerpb.Status{committerpb.Status_COMMITTED, committerpb.Status_COMMITTED},
	)
	require.Len(t, txIDs, 2)
}
