/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-committer/utils/testdb"
)

// TestEnvChannelID is the channel NewAuthTestEnv builds its configuration for.
const TestEnvChannelID = "ch1"

type (
	// TestEnv is the client side of an AuthService: a client to reach it with and an identity its channel's
	// policy accepts. NewAuthTestEnv also starts the service; a test that already has one running - an
	// integration topology, say - fills these fields in directly instead.
	TestEnv struct {
		AuthService *Service
		// Client reaches the AuthService.
		Client servicepb.AuthServiceClient
		// Signer is an MSP identity belonging to ChannelID, which is what makes a token mintable.
		Signer msp.SigningIdentity
		// ChannelID scopes every envelope this environment signs.
		ChannelID string
		// Config reaches the service NewAuthTestEnv started; hand it to a resource server's
		// acl.Client. It is empty when the environment was attached to an already-running service.
		Config *connection.ClientConfig
		// ArtifactsPath holds the crypto the channel configuration was built from.
		ArtifactsPath string
	}

	// ACLTestEnvParams tunes the environment. A nil value, or a zero field, takes the default.
	ACLTestEnvParams struct {
		// TokenTTL is how long a minted token lives. A short one lets a test watch an established stream
		// lapse, since a resource server keeps the token's expiry as its local hard bound.
		TokenTTL time.Duration
	}
)

// NewAuthTestEnv starts an AuthService over a provisioned database and waits until it can authenticate.
func NewAuthTestEnv(t *testing.T, params *ACLTestEnvParams) *TestEnv {
	t.Helper()
	if params == nil {
		params = &ACLTestEnvParams{}
	}
	if params.TokenTTL <= 0 {
		params.TokenTTL = 15 * time.Minute
	}

	env := &TestEnv{
		ChannelID:     TestEnvChannelID,
		ArtifactsPath: t.TempDir(),
	}
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(env.ArtifactsPath, &testcrypto.ConfigBlock{
		ChannelID:             env.ChannelID,
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)
	env.Signer = LoadTestSigner(t, env.ArtifactsPath)

	dbConf := newTestDBConfig(t)
	seedConfigTransaction(t, dbConf, block)

	serverConfig := test.NewLocalHostServiceConfig(test.InsecureTLSConfig)

	env.AuthService = NewAuthService(&Config{
		Database:                dbConf,
		TokenTTL:                params.TokenTTL,
		NonceTTL:                time.Minute,
		EnvelopeFreshnessWindow: 5 * time.Minute,
		ConfigRefreshInterval:   100 * time.Millisecond,
		TokenCleanupInterval:    time.Minute,
	})
	test.RunServiceAndServeForTest(t.Context(), t, env.AuthService, serverConfig)

	env.Config = test.NewInsecureClientConfig(&serverConfig.GRPC.Endpoint)
	conn, err := connection.NewSingleConnection(env.Config)
	require.NoError(t, err)
	t.Cleanup(func() { connection.CloseConnectionsLog(conn) })
	env.Client = servicepb.NewAuthServiceClient(conn)

	env.WaitForEnforcement(t)
	return env
}

// WaitForEnforcement blocks until the AuthService answers on the merits. Readiness is signalled before the
// configuration provider's first refresh, so until then it has no bundle to judge an envelope against - and
// a test asserting a specific rejection would otherwise mistake that window's failure for it.
func (e *TestEnv) WaitForEnforcement(t *testing.T) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := e.mintToken(t.Context())
		assert.NoError(ct, err)
	}, 2*time.Minute, 250*time.Millisecond, "the auth service never loaded a channel configuration")
}

// MintToken authenticates and returns a token the resource servers will accept.
func (e *TestEnv) MintToken(t *testing.T) string {
	t.Helper()
	token, err := e.mintToken(t.Context())
	require.NoError(t, err)
	return token
}

func (e *TestEnv) mintToken(ctx context.Context) (string, error) {
	return acl.MintToken(ctx, &acl.MintParams{
		Client:    e.Client,
		Signer:    e.Signer,
		ChannelID: e.ChannelID,
	})
}

// ACLClient is the auth section a resource server under test should be configured with.
func (e *TestEnv) ACLClient(reAuthorizeInterval time.Duration) *acl.Client {
	return &acl.Client{
		Config:                    e.Config,
		StreamReAuthorizeInterval: reAuthorizeInterval,
	}
}

// Nonce obtains a single-use challenge from the AuthService.
func (e *TestEnv) Nonce(t *testing.T) []byte {
	t.Helper()
	resp, err := e.Client.IssueNonce(t.Context(), &servicepb.IssueNonceRequest{})
	require.NoError(t, err)
	return resp.GetNonce()
}

// Envelope signs an authentication envelope carrying the given nonce. A nil nonce produces an envelope with
// no challenge at all, which is what a test of the missing-nonce rejection needs.
func (e *TestEnv) Envelope(t *testing.T, nonce []byte) *common.Envelope {
	t.Helper()
	envelope, err := acl.BuildAuthEnvelope(&acl.AuthEnvelopeParams{
		Signer:    e.Signer,
		ChannelID: e.ChannelID,
		Nonce:     nonce,
	})
	require.NoError(t, err)
	return envelope
}

// Authenticate exchanges an envelope for a token in exactly one attempt: WaitForEnforcement owns the
// bootstrap wait, and retrying would only replay a challenge the service has already rejected.
func (e *TestEnv) Authenticate(t *testing.T, envelope *common.Envelope) string {
	t.Helper()
	resp, err := e.Client.Authenticate(t.Context(), &servicepb.AuthenticateRequest{SignedEnvelope: envelope})
	require.NoError(t, err)
	return resp.GetToken()
}

// LoadTestSigner returns a signing identity from generated crypto material. The identity must belong to the
// channel the AuthService judges against, so it comes from what that channel's config block was built from.
//
//nolint:ireturn // returning the MSP identity interface is intentional for test purpose.
func LoadTestSigner(t *testing.T, artifactsPath string) msp.SigningIdentity {
	t.Helper()
	identities, err := testcrypto.GetPeersIdentities(artifactsPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)
	return identities[0]
}

// newTestDBConfig provisions a database carrying the system schema, which includes the auth tables.
func newTestDBConfig(t *testing.T) *statedb.Config {
	t.Helper()
	cs := testdb.PrepareTestEnv(t)
	config := &statedb.Config{
		Endpoints:      cs.Endpoints,
		Username:       cs.User,
		Password:       cs.Password,
		Database:       cs.Database,
		MaxConnections: 10,
		MinConnections: 1,
		TLS:            cs.TLS,
		Retry:          testdb.DefaultRetry,
	}
	require.NoError(t, statedb.SetupSystemTablesAndNamespaces(t.Context(), config))
	return config
}

// seedConfigTransaction writes the block's configuration envelope where the service reads it, standing in
// for the committer that would otherwise have to commit it first.
func seedConfigTransaction(t *testing.T, dbConf *statedb.Config, block *common.Block) {
	t.Helper()
	envelope, err := protoutil.ExtractEnvelope(block, 0)
	require.NoError(t, err)
	envelopeBytes, err := proto.Marshal(envelope)
	require.NoError(t, err)

	pool, err := statedb.NewPool(t.Context(), dbConf)
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(t.Context(),
		"INSERT INTO "+statedb.TableName(committerpb.ConfigNamespaceID)+" (key, value, version) "+
			"VALUES ($1, $2, 0) "+
			"ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, version = EXCLUDED.version",
		[]byte(committerpb.ConfigKey), envelopeBytes)
	require.NoError(t, err)
}
