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
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-committer/utils/testdb"
)

// TestEnvChannelID is the channel the test environment's configuration is built for.
const TestEnvChannelID = "ch1"

type (
	// TestEnv is a running AuthService with everything a resource server and its clients need: an
	// endpoint to point an acl.Client at, and an identity the channel's policy accepts. The configuration
	// is seeded straight into the database, so no committer pipeline is needed to put one there.
	TestEnv struct {
		// ClientConfig reaches the service; hand it to an acl.Client on the resource server under test.
		ClientConfig *connection.ClientConfig
		// ArtifactsPath holds the crypto the channel configuration was built from.
		ArtifactsPath string

		signer msp.SigningIdentity
		client servicepb.AuthServiceClient
	}

	// ACLTestEnvParams tunes the environment. A nil value, or a zero field, takes the default.
	ACLTestEnvParams struct {
		// TokenTTL is how long a minted token lives. A short one lets a test watch an established stream
		// lapse, since a resource server keeps the token's expiry as its local hard bound.
		TokenTTL time.Duration
	}
)

// NewServiceTestEnv starts an AuthService over a provisioned database and waits until it can authenticate.
func NewServiceTestEnv(t *testing.T, params *ACLTestEnvParams) *TestEnv {
	t.Helper()
	if params == nil {
		params = &ACLTestEnvParams{}
	}
	if params.TokenTTL <= 0 {
		params.TokenTTL = 5 * time.Minute
	}

	env := &TestEnv{ArtifactsPath: t.TempDir()}
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(env.ArtifactsPath, &testcrypto.ConfigBlock{
		ChannelID:             TestEnvChannelID,
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	identities, err := testcrypto.GetPeersIdentities(env.ArtifactsPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)
	env.signer = identities[0]

	dbConf := newTestDBConfig(t)
	seedConfigTransaction(t, dbConf, block)

	serverConfig := test.NewLocalHostServiceConfig(test.InsecureTLSConfig)
	test.RunServiceAndServeForTest(t.Context(), t, NewAuthService(&Config{
		Database:                   dbConf,
		TokenTTL:                   params.TokenTTL,
		NonceTTL:                   time.Minute,
		EnvelopeFreshnessWindow:    5 * time.Minute,
		ConfigRefreshInterval:      100 * time.Millisecond,
		TokenCleanupInterval:       time.Minute,
		ChallengeRequestsPerSecond: 0, // Unthrottled: a test is not a denial-of-service risk.
	}), serverConfig)

	env.ClientConfig = test.NewInsecureClientConfig(&serverConfig.GRPC.Endpoint)
	conn, err := connection.NewSingleConnection(env.ClientConfig)
	require.NoError(t, err)
	t.Cleanup(func() { connection.CloseConnectionsLog(conn) })
	env.client = servicepb.NewAuthServiceClient(conn)

	// Readiness is signalled before the configuration provider's first refresh, so the service can be
	// serving with no bundle yet. Minting proves it has one; bounded, because the client retries an
	// unavailable service for far longer than a test should wait to learn the environment is broken.
	mintCtx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	_, err = env.mintToken(mintCtx)
	require.NoError(t, err, "the auth service never loaded a channel configuration")
	return env
}

// MintToken authenticates and returns a token the resource servers will accept.
func (e *TestEnv) MintToken(t *testing.T) string {
	t.Helper()
	creds, err := e.mintToken(t.Context())
	require.NoError(t, err)
	return creds.Token
}

// ACLClient is the auth section a resource server under test should be configured with.
func (e *TestEnv) ACLClient(reAuthorizeInterval time.Duration) *acl.Client {
	return &acl.Client{Config: e.ClientConfig, StreamReAuthorizeInterval: reAuthorizeInterval}
}

func (e *TestEnv) mintToken(ctx context.Context) (*acl.Credentials, error) {
	return acl.MintToken(ctx, &acl.MintParams{
		Client:    e.client,
		Signer:    e.signer,
		ChannelID: TestEnvChannelID,
	})
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
