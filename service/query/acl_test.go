/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package query

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/service/acl"
	"github.com/hyperledger/fabric-x-committer/service/vc"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/retry"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-committer/utils/testcrypto"
	"github.com/hyperledger/fabric-x-committer/utils/testdb"
)

// TestQueryServiceACLEnforcement tests ACL enforcement for query service operations.
func TestQueryServiceACLEnforcement(t *testing.T) {
	t.Parallel()

	// Use the same channel ID as the loadgen default
	channelID := "channel"

	// Create initial config block with peer organizations
	// Use 3 peer orgs to match loadgen's default configuration
	cryptoMaterialsPath := t.TempDir()
	configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
		cryptoMaterialsPath,
		&testcrypto.ConfigBlock{
			ChannelID:             channelID,
			PeerOrganizationCount: 3,
		},
	)
	require.NoError(t, err)

	// Create ACL provider
	bundleManager := acl.NewBundleManager()
	aclProvider := acl.NewProvider(bundleManager)
	err = aclProvider.UpdateFromConfigBlock(configBlock)
	require.NoError(t, err)

	// Load peer identities for signing
	peerIdentities, err := testcrypto.GetPeersIdentities(cryptoMaterialsPath)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(peerIdentities), 2, "need at least 2 peer organizations")

	// WORKAROUND: Fix MSP name mismatch between config block and crypto material.
	// The config block uses "peer-org-0" while crypto material uses "peer-org-0.com".
	// This should be fixed in utils/testcrypto/gen_crypto.go by setting Name equal to Domain.
	// TODO: Remove this workaround after fixing the root cause.
	for i := range peerIdentities {
		mspDirs := testcrypto.GetPeersMspDirs(cryptoMaterialsPath)
		mspDirs[i].MspName = strings.TrimSuffix(mspDirs[i].MspName, ".com")
		localMsp, err := msp.LoadLocalMspDir(*mspDirs[i])
		require.NoError(t, err)
		peerIdentities[i], err = localMsp.GetDefaultSigningIdentity()
		require.NoError(t, err)
	}

	env := newQueryServiceTestEnvWithACLAndConfigBlock(t, &queryServiceTestOpts{
		serverTLS: test.InsecureTLSConfig,
		clientTLS: test.InsecureTLSConfig,
	}, aclProvider, nil, configBlock)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	// Insert test data
	requiredItems := env.insertSampleKeysValueItems(t)
	query, _, _ := makeQuery(requiredItems)
	txIDs := env.insertSampleTxsStatus(t)

	t.Run("GetRows with signed envelope succeeds", func(t *testing.T) {
		t.Parallel()
		signedEnv := createSignedEnvelope(t, channelID, peerIdentities[0], query)
		ret, err := env.clientConn.GetRows(ctx, signedEnv)
		require.NoError(t, err)
		require.NotNil(t, ret)
		requireResults(t, requiredItems, ret.Namespaces)
	})

	t.Run("GetRows with unsigned envelope fails", func(t *testing.T) {
		t.Parallel()
		unsignedEnv := acl.CreateUnsignedEnvelope(t, channelID)
		_, err := env.clientConn.GetRows(ctx, unsignedEnv)
		require.Error(t, err)
		st := status.Convert(err)
		require.Equal(t, codes.Internal, st.Code())
		require.Contains(t, st.Message(), "access denied")
	})

	t.Run("GetTransactionStatus with signed envelope succeeds", func(t *testing.T) {
		t.Parallel()
		txQuery := &committerpb.TxStatusQuery{TxIds: txIDs}
		signedEnv := createSignedEnvelope(t, channelID, peerIdentities[0], txQuery)
		ret, err := env.clientConn.GetTransactionStatus(ctx, signedEnv)
		require.NoError(t, err)
		require.NotNil(t, ret)
		require.Len(t, ret.Statuses, len(txIDs))
	})

	t.Run("GetTransactionStatus with unsigned envelope fails", func(t *testing.T) {
		t.Parallel()
		unsignedEnv := acl.CreateUnsignedEnvelope(t, channelID)
		_, err := env.clientConn.GetTransactionStatus(ctx, unsignedEnv)
		require.Error(t, err)
		st := status.Convert(err)
		require.Equal(t, codes.Internal, st.Code())
		require.Contains(t, st.Message(), "access denied")
	})

	t.Run("BeginView with signed envelope succeeds", func(t *testing.T) {
		t.Parallel()
		viewParams := defaultViewParams(time.Minute)
		signedEnv := createSignedEnvelope(t, channelID, peerIdentities[0], viewParams)
		view, err := env.clientConn.BeginView(ctx, signedEnv)
		require.NoError(t, err)
		require.NotNil(t, view)
		require.NotEmpty(t, view.Id)

		// Clean up
		endEnv := createSignedEnvelope(t, channelID, peerIdentities[0], view)
		_, err = env.clientConn.EndView(ctx, endEnv)
		require.NoError(t, err)
	})

	t.Run("BeginView with unsigned envelope fails", func(t *testing.T) {
		t.Parallel()
		unsignedEnv := acl.CreateUnsignedEnvelope(t, channelID)
		_, err := env.clientConn.BeginView(ctx, unsignedEnv)
		require.Error(t, err)
		st := status.Convert(err)
		require.Equal(t, codes.Internal, st.Code())
		require.Contains(t, st.Message(), "access denied")
	})
}

// createSignedEnvelope creates a signed envelope for testing.
func createSignedEnvelope(t *testing.T, channelID string, signer msp.SigningIdentity, request proto.Message) *common.Envelope {
	t.Helper()

	env, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_MESSAGE,
		channelID,
		signer,
		request, // Pass the proto message directly, CreateSignedEnvelope handles marshaling
		0,       // msgVersion
		0,       // epoch
	)
	require.NoError(t, err)
	return env
}

// newQueryServiceTestEnvWithACLAndConfigBlock creates a test environment with ACL provider and a specific config block.
// This ensures the config block in the database matches the one used for ACL setup, which is critical for
// ACL enforcement to work correctly. The query service reads the config block from the database on startup
// and periodically refreshes it, so we must ensure the database contains the same config block used to
// initialize the ACL provider.
func newQueryServiceTestEnvWithACLAndConfigBlock(
	t *testing.T,
	opts *queryServiceTestOpts,
	aclProvider acl.Provider,
	tlsUpdater connection.TLSCertUpdater,
	configBlock *common.Block,
) *queryServiceTestEnv {
	t.Helper()
	if opts == nil {
		opts = &queryServiceTestOpts{}
	}

	t.Log("generating config and namespaces")
	namespacesToTest := []string{"0", "1", "2"}
	dbConf := generateNamespacesUnderTest(t, namespacesToTest)

	// Update the database with our config block before starting the query service
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	pool, err := vc.NewDatabasePool(ctx, dbConf)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// Extract and store the config block in the database
	envelope, err := protoutil.ExtractEnvelope(configBlock, 0)
	require.NoError(t, err)
	envelopeBytes, err := proto.Marshal(envelope)
	require.NoError(t, err)

	// Update config in database - use version 1 to ensure it's newer than the default
	require.NoError(t, retry.ExecuteSQL(ctx, testdb.DefaultRetry, pool,
		fmt.Sprintf("UPDATE ns_%s SET value = $1, version = $2 WHERE key = $3", committerpb.ConfigNamespaceID),
		envelopeBytes, uint64(1), []byte(committerpb.ConfigNamespaceID)))

	// Now create the query service - it will read our config block on startup
	config := &Config{
		MinBatchKeys:          5,
		MaxBatchWait:          time.Second,
		ViewAggregationWindow: time.Minute,
		MaxViewTimeout:        time.Minute,
		MaxAggregatedViews:    5,
		MaxActiveViews:        opts.maxActiveViews,
		Server:                test.NewLocalHostServer(opts.serverTLS),
		MaxRequestKeys:        opts.maxRequestKeys,
		Database:              dbConf,
		Monitoring:            test.NewLocalHostServer(test.InsecureTLSConfig),
		TLSRefreshInterval:    5 * time.Second,
	}

	qs := NewQueryService(config, aclProvider, tlsUpdater)
	test.RunServiceAndGrpcForTest(t.Context(), t, qs, qs.config.Server)
	clientConn := createQueryClientWithTLS(t, &qs.config.Server.Endpoint, opts.clientTLS)

	return &queryServiceTestEnv{
		config:     config,
		qs:         qs,
		ns:         namespacesToTest,
		clientConn: clientConn,
		pool:       pool,
	}
}
