/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/applicationpb"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

const (
	aclNamespace      = "1"
	aclOtherNamespace = "2"
)

// aclEnv is a running committer plus what a client needs to authenticate against it: an AuthService client
// and an MSP signing identity belonging to the bootstrapped channel.
type aclEnv struct {
	c          *runner.CommitterRuntime
	authClient servicepb.AuthServiceClient
	signer     msp.SigningIdentity
}

// TestACLQueryWithAuthenticatedClient walks the mechanism end to end against a live system: nonce ->
// signed envelope -> token -> a query for a row committed through the ordinary transaction path.
func TestACLQueryWithAuthenticatedClient(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	// Step 1: Commit a transaction through the normal path, so the query has something real to find.
	t.Log("Step 1: commit a transaction through the orderer")
	env.commitRow(t, []byte("k1"), []byte("v1"))
	env.waitForEnforcement(t)

	// Step 2: Obtain a single-use nonce - the mandatory pre-step of authentication.
	t.Log("Step 2: obtain a nonce from the auth service")
	nonce := env.nonce(t)
	t.Logf("got nonce %s", nonce)
	require.NotEmpty(t, nonce)

	// Step 3: Sign the nonce into an envelope and exchange it for a cert-bound token.
	t.Log("Step 3: authenticate with the signed envelope carrying the nonce")
	token := env.authenticate(t, env.envelope(t, nonce))
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
	env.waitForEnforcement(t)

	_, err := env.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: env.envelope(t, nil),
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "envelope carries no nonce")
}

// TestACLAuthenticateRejectsForgedNonce verifies a client cannot invent its own challenge: only a
// nonce the server issued and still holds is redeemable.
func TestACLAuthenticateRejectsForgedNonce(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)
	env.waitForEnforcement(t)

	_, err := env.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: env.envelope(t, []byte("a-nonce-the-server-never-issued")),
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "unknown, already used, or expired")
}

// TestACLAuthenticateRejectsReplayedEnvelope is the property the nonce exists for: a captured envelope
// cannot be redeemed twice, though it is byte-identical, correctly signed and still fresh.
func TestACLAuthenticateRejectsReplayedEnvelope(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	env.waitForEnforcement(t)

	// Step 1: A first authentication succeeds and consumes the nonce.
	t.Log("Step 1: authenticate once, consuming the nonce")
	envelope := env.envelope(t, env.nonce(t))
	token := env.authenticate(t, envelope)
	require.NotEmpty(t, token)

	// Step 2: Replay the very same envelope, as an attacker who captured it would.
	t.Log("Step 2: replay the identical envelope")
	_, err := env.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
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

	// The signing identity must belong to the channel the system was bootstrapped with, so it is loaded
	// from the same crypto material the genesis config block was built from.
	identities, err := testcrypto.GetPeersIdentities(c.OrdererEnv.ArtifactsPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)

	return &aclEnv{
		c: c,
		authClient: servicepb.NewAuthServiceClient(
			test.NewSecuredConnection(t, c.SystemConfig.Services.Auth.GrpcEndpoint, c.SystemConfig.ClientTLS),
		),
		signer: identities[0],
	}
}

// nonce obtains a single-use challenge from the AuthService.
func (e *aclEnv) nonce(t *testing.T) []byte {
	t.Helper()
	resp, err := e.authClient.IssueNonce(t.Context(), &servicepb.IssueNonceRequest{})
	require.NoError(t, err)
	return resp.GetNonce()
}

// envelope builds a signed authentication envelope carrying the given nonce. A nil nonce produces an
// envelope with no challenge at all, which is what the missing-nonce case needs.
func (e *aclEnv) envelope(t *testing.T, nonce []byte) *common.Envelope {
	t.Helper()
	envelope, err := acl.BuildAuthEnvelope(&acl.AuthEnvelopeParams{
		Signer:    e.signer,
		ChannelID: runner.TestChannelName,
		Nonce:     nonce,
	})
	require.NoError(t, err)
	return envelope
}

// authenticate exchanges an envelope for a token in exactly one attempt: waitForEnforcement owns the
// bootstrap wait, and retrying would only replay a challenge the service has already rejected.
func (e *aclEnv) authenticate(t *testing.T, envelope *common.Envelope) string {
	t.Helper()
	resp, err := e.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
	})
	require.NoError(t, err)
	return resp.GetToken()
}

// waitForEnforcement blocks until the AuthService has a bundle and answers on the merits, so a test
// asserting a specific rejection cannot mistake the bootstrap window's Unavailable for it.
func (e *aclEnv) waitForEnforcement(t *testing.T) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := e.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
			SignedEnvelope: e.envelope(t, e.nonce(t)),
		})
		require.NoError(ct, err)
	}, 2*time.Minute, 250*time.Millisecond)
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
