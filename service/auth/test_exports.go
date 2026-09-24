/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"path"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/tools/cryptogen"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/acl"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/serve"
	"github.com/hyperledger/fabric-x-committer/utils/statedb"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-committer/utils/testdb"
)

// defaultTestChannelID is the channel NewAuthTestEnv builds a configuration for when it creates one.
const defaultTestChannelID = "mychannel"

type (
	// TestEnv is the client side of an AuthService: a client to reach it with and an identity its channel's
	// policy accepts. NewAuthTestEnv also starts the service; a test that already has one running - an
	// integration topology, say - fills these fields in directly instead.
	TestEnv struct {
		AuthService   *Service
		Client        servicepb.AuthServiceClient
		Signer        msp.SigningIdentity
		ChannelID     string
		ArtifactsPath string
		ServerConfig  *serve.Config
		Config        *connection.ClientConfig
		TLSCertHash   []byte
	}

	// ACLTestEnvParams describes the AuthService NewAuthTestEnv should start. ArtifactsPath may be shared
	// with another env that already generated crypto and a config block there; the channel then comes from
	// that block rather than from ChannelID.
	ACLTestEnvParams struct {
		ServerTLS     connection.TLSConfig
		ClientTLS     connection.TLSConfig
		TokenTTL      time.Duration
		ArtifactsPath string
		ChannelID     string
	}
)

// NewAuthTestEnv starts an AuthService test environment.
func NewAuthTestEnv(t *testing.T, params *ACLTestEnvParams) *TestEnv {
	t.Helper()
	if params == nil {
		params = &ACLTestEnvParams{}
	}
	if params.TokenTTL <= 0 {
		params.TokenTTL = 30 * time.Minute
	}
	if params.ArtifactsPath == "" {
		params.ArtifactsPath = t.TempDir()
	}
	env := &TestEnv{ArtifactsPath: params.ArtifactsPath}

	// The artifacts path may already belong to another env - an orderer test env, say - whose config block
	// carries state this one cannot reconstruct, notably the orderer endpoints its sidecar dials. Extending
	// that block drops them silently, so an existing block is read and never rewritten.
	blockPath := path.Join(env.ArtifactsPath, cryptogen.ConfigBlockFileName)
	configBlock, readErr := protoutil.ReadBlockFromFile(blockPath)
	if readErr != nil {
		if params.ChannelID == "" {
			params.ChannelID = defaultTestChannelID
		}
		var createErr error
		configBlock, createErr = testcrypto.CreateOrExtendConfigBlockWithCrypto(
			env.ArtifactsPath,
			&testcrypto.ConfigBlock{ChannelID: params.ChannelID, PeerOrganizationCount: 1},
		)
		require.NoError(t, createErr)
	}

	// The block is the authority on its own channel, so the env cannot be pointed at one channel's
	// configuration while it signs envelopes for another.
	channelID, err := protoutil.GetChannelIDFromBlock(configBlock)
	require.NoError(t, err)
	if params.ChannelID != "" {
		require.Equal(t, channelID, params.ChannelID,
			"ChannelID does not match the channel of the config block already at ArtifactsPath")
	}
	env.ChannelID = channelID

	identities, err := testcrypto.GetPeersIdentities(env.ArtifactsPath)
	require.NoError(t, err)
	require.NotEmpty(t, identities)
	env.Signer = identities[0]

	cs := testdb.PrepareTestEnv(t)
	dbConf := &statedb.Config{
		Endpoints:      cs.Endpoints,
		Username:       cs.User,
		Password:       cs.Password,
		Database:       cs.Database,
		MaxConnections: 10,
		MinConnections: 1,
		TLS:            cs.TLS,
		Retry:          testdb.DefaultRetry,
	}
	require.NoError(t, statedb.SetupSystemTablesAndNamespaces(t.Context(), dbConf))
	seedConfigTransaction(t, dbConf, configBlock)

	env.ServerConfig = test.NewLocalHostServiceConfig(params.ServerTLS)
	env.AuthService = NewAuthService(&Config{
		Database:                      dbConf,
		TokenTTL:                      params.TokenTTL,
		NonceTTL:                      5 * time.Minute,
		EnvelopeFreshnessWindow:       5 * time.Minute,
		ConfigRefreshInterval:         100 * time.Millisecond,
		TokenAndNoncesCleanupInterval: time.Minute,
	})
	test.RunServiceAndServeForTest(t.Context(), t, env.AuthService, env.ServerConfig)
	env.Config = test.NewTLSClientConfig(params.ClientTLS, &env.ServerConfig.GRPC.Endpoint)
	conn, err := connection.NewSingleConnection(env.Config)
	require.NoError(t, err)
	t.Cleanup(func() { connection.CloseConnectionsLog(conn) })
	env.Client = createAuthClientWithTLS(t, &env.ServerConfig.GRPC.Endpoint, params.ClientTLS)
	env.TLSCertHash = clientCertHash(t, params.ClientTLS)

	env.WaitForEnforcement(t)
	return env
}

// WaitForEnforcement blocks until the AuthService accepts a token request,
// which implies it has loaded the channel configuration and is enforcing ACLs.
func (e *TestEnv) WaitForEnforcement(t *testing.T) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := acl.MintToken(t.Context(), &acl.MintParams{
			Client:      e.Client,
			Signer:      e.Signer,
			ChannelID:   e.ChannelID,
			TLSCertHash: e.TLSCertHash,
		})
		assert.NoError(ct, err)
	}, 2*time.Minute, 250*time.Millisecond, "the auth service never loaded a channel configuration")
}

// MintToken authenticates and returns a token the resource servers will accept.
func (e *TestEnv) MintToken(t *testing.T) string {
	t.Helper()
	token, err := acl.MintToken(t.Context(), &acl.MintParams{
		Client:      e.Client,
		Signer:      e.Signer,
		ChannelID:   e.ChannelID,
		TLSCertHash: e.TLSCertHash,
	})
	require.NoError(t, err)
	return token
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

func createAuthClientWithTLS(
	t *testing.T,
	ep *connection.Endpoint,
	tlsCfg connection.TLSConfig,
) servicepb.AuthServiceClient {
	t.Helper()
	return test.CreateClientWithTLS(t, ep, tlsCfg, servicepb.NewAuthServiceClient)
}

// clientCertHash returns the SHA-256 of the client certificate tlsCfg will present, or nil when the mode is
// not mutual TLS and so no certificate can bind a token. The AuthService takes the binding from the
// certificate on the Authenticate connection, so a mint that omits this over mutual TLS is rejected with a
// binding mismatch rather than simply issuing an unbound token.
func clientCertHash(t *testing.T, tlsCfg connection.TLSConfig) []byte {
	t.Helper()
	creds, err := connection.NewClientTLSCredentials(tlsCfg)
	require.NoError(t, err)
	if creds.Mode != connection.MutualTLSMode {
		return nil
	}
	hash, err := protoutil.HashTLSCertificate(creds.Cert)
	require.NoError(t, err)
	return hash
}
