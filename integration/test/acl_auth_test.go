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
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

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

// aclEnv is a running committer with ACL enforcement on the query service, plus everything a client
// needs to authenticate against it: a client to the AuthService and an MSP signing identity that
// belongs to the channel the system was bootstrapped with.
type aclEnv struct {
	c          *runner.CommitterRuntime
	authClient servicepb.AuthServiceClient
	signer     msp.SigningIdentity
}

// TestACLQueryWithAuthenticatedClient walks the whole mechanism end to end against a live system: a
// client obtains a nonce, signs it into an authentication envelope, exchanges that for a token, and
// uses the token to read back a row committed through the ordinary transaction path.
func TestACLQueryWithAuthenticatedClient(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	// Step 1: Commit a transaction through the normal path, so the query has something real to find.
	t.Log("Step 1: commit a transaction through the orderer")
	env.commitRow(t, []byte("k1"), []byte("v1"))

	// Step 2: Obtain a single-use nonce - the mandatory pre-step of authentication.
	t.Log("Step 2: obtain a nonce from the auth service")
	nonce := env.nonce(t)
	require.NotEmpty(t, nonce)

	// Step 3: Sign the nonce into an envelope and exchange it for a cert-bound token.
	t.Log("Step 3: authenticate with the signed envelope carrying the nonce")
	token := env.authenticate(t, env.envelope(t, nonce), nil)
	require.NotEmpty(t, token)

	// Step 4: Query with the token. The query service authorizes every RPC against the AuthService, so
	// this proves the whole chain: nonce -> envelope -> token -> interceptor -> Authorize -> handler.
	t.Log("Step 4: query the committed row with the token")
	rows, err := env.c.QueryServiceClient.GetRows(env.tokenContext(t, token), &committerpb.Query{
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

// TestACLQueryRejectedWithoutToken verifies enforcement is actually on: the same query without a token
// is refused before the handler runs.
func TestACLQueryRejectedWithoutToken(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	_, err := env.c.QueryServiceClient.GetRows(t.Context(), &committerpb.Query{
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
// cannot be redeemed a second time, even though it is byte-identical, correctly signed, and still well
// inside the freshness window.
func TestACLAuthenticateRejectsReplayedEnvelope(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	// Step 1: A first authentication succeeds and consumes the nonce.
	t.Log("Step 1: authenticate once, consuming the nonce")
	envelope := env.envelope(t, env.nonce(t))
	token := env.authenticate(t, envelope, nil)
	require.NotEmpty(t, token)

	// Step 2: Replay the very same envelope, as an attacker who captured it would.
	t.Log("Step 2: replay the identical envelope")
	_, err := env.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
		SignedEnvelope: envelope,
	})
	require.Equal(t, codes.Unauthenticated, grpcerror.GetCode(err))
	require.ErrorContains(t, err, "already used")
}

// TestACLQueryDeniedOutsideTokenNamespaceScope verifies a token that carries authority for one
// namespace cannot read another. The decision is the AuthService's: the query service's interceptor
// forwards the namespaces the request names, and the AuthService checks them against the token's scope.
func TestACLQueryDeniedOutsideTokenNamespaceScope(t *testing.T) {
	t.Parallel()
	env := newACLEnv(t)

	// Step 1: Commit rows in both namespaces, so a denial cannot be confused with an empty result.
	t.Log("Step 1: commit a row in each namespace")
	env.commitRow(t, []byte("k1"), []byte("v1"))

	// Step 2: Obtain a token restricted to the other namespace.
	t.Log("Step 2: authenticate with a token scoped to a single namespace")
	token := env.authenticate(t, env.envelope(t, env.nonce(t)), []string{aclOtherNamespace})

	// Step 3: The scoped token may read the namespace it was issued for.
	t.Log("Step 3: the in-scope namespace is readable")
	_, err := env.c.QueryServiceClient.GetRows(env.tokenContext(t, token), &committerpb.Query{
		Namespaces: []*committerpb.QueryNamespace{
			{NsId: aclOtherNamespace, Keys: [][]byte{[]byte("k1")}},
		},
	})
	require.NoError(t, err)

	// Step 4: The same token is denied on a namespace outside its scope, even though the identity's
	// channel policy would allow the read and the row exists.
	t.Log("Step 4: the out-of-scope namespace is denied")
	_, err = env.c.QueryServiceClient.GetRows(env.tokenContext(t, token), &committerpb.Query{
		Namespaces: []*committerpb.QueryNamespace{
			{NsId: aclNamespace, Keys: [][]byte{[]byte("k1")}},
		},
	})
	require.Equal(t, codes.PermissionDenied, grpcerror.GetCode(err))
}

// newACLEnv starts a full committer whose query service enforces ACL against a live AuthService, and
// returns the pieces a client needs to authenticate against it.
func newACLEnv(t *testing.T) *aclEnv {
	t.Helper()

	c := runner.NewRuntime(t, &runner.Config{
		BlockTimeout: 2 * time.Second,
		EnableACL:    true,
	})
	c.Start(t, runner.FullTxPathWithAuth)
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
	resp, err := e.authClient.GetNonce(t.Context(), &servicepb.GetNonceRequest{})
	require.NoError(t, err)
	return resp.GetNonce()
}

// envelope builds a signed authentication envelope carrying the given nonce. A nil nonce produces an
// envelope with no challenge at all, which is what the missing-nonce case needs.
func (e *aclEnv) envelope(t *testing.T, nonce []byte) []byte {
	t.Helper()
	envelope, err := acl.BuildAuthEnvelopeForTest(&acl.AuthEnvelopeParams{
		Signer:    e.signer,
		ChannelID: runner.TestChannelName,
		Nonce:     nonce,
	})
	require.NoError(t, err)
	return envelope
}

// authenticate exchanges an envelope for a token, optionally requesting a namespace-restricted one.
//
// It retries while the AuthService reports Unavailable, which it does until the genesis configuration
// block has been committed and observed - the documented bootstrap window. Every other outcome,
// including a rejection, is returned on the first attempt so a negative test fails fast rather than
// retrying a denial for the full timeout.
func (e *aclEnv) authenticate(t *testing.T, envelope []byte, namespaces []string) string {
	t.Helper()

	var token string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := e.authClient.Authenticate(t.Context(), &servicepb.AuthenticateRequest{
			SignedEnvelope:      envelope,
			RequestedNamespaces: namespaces,
		})
		require.NoError(ct, err)
		token = resp.GetToken()
	}, 2*time.Minute, 250*time.Millisecond)
	return token
}

// waitForEnforcement blocks until the AuthService has loaded a configuration bundle and is answering
// authentication attempts on their merits. A test that asserts on a specific rejection needs this
// first, so it cannot mistake the bootstrap window's Unavailable for the denial it is checking.
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
	txIDs := e.c.MakeAndSendTransactionsToOrderer(t,
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

// tokenContext returns a context carrying the token in the metadata key the enforcer reads.
func (*aclEnv) tokenContext(t *testing.T, token string) context.Context {
	t.Helper()
	return metadata.AppendToOutgoingContext(t.Context(), acl.TokenMetadataKey, token)
}
