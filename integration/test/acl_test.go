/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/integration/runner"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/grpcerror"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	"github.com/hyperledger/fabric-x-committer/utils/testcrypto"
)

// TestACLEnforcement verifies that the sidecar and query service enforce ACL policies
// based on the /Channel/Application/Readers policy from channel configuration.
// It tests that authorized peer organizations can access services while unauthorized
// organizations are rejected, and that ACL policies update dynamically with config blocks.
func TestACLEnforcement(t *testing.T) {
	t.Parallel()
	gomega.RegisterTestingT(t)

	c := runner.NewRuntime(t, &runner.Config{
		TLSMode:                 connection.MutualTLSMode,
		PeerOrganizationCount:   3,
		BlockTimeout:            2 * time.Second,
		QueryTLSRefreshInterval: 5 * time.Second,
		CrashTest:               true,
	})
	// Start orderer servers in-process so SubmitConfigBlock can write directly
	// to the orderer's block channel (separate-process orderers don't share memory).
	c.OrdererEnv.StartServers(t)
	c.Start(t, runner.CommitterTxPath|runner.QueryService)

	serverCACertPaths := c.SystemConfig.ClientTLS.CACertPaths
	sidecarEndpoint := c.SystemConfig.Services.Sidecar.GrpcEndpoint
	queryEndpoint := c.SystemConfig.Services.Query.GrpcEndpoint

	// Load signing identities for each peer organization.
	// These will be used to create signed envelopes for ACL checks.
	peerIdentities, err := testcrypto.GetPeersIdentities(c.OrdererEnv.ArtifactsPath)
	require.NoError(t, err, "failed to load peer identities")
	require.GreaterOrEqual(t, len(peerIdentities), 3, "need at least 3 peer organizations")

	// Per-org mTLS configs for transport-level authentication.
	// Crypto artifacts don't change across config block updates,
	// so these remain valid throughout the test.
	orgTLS := [3]connection.TLSConfig{}
	for i := range orgTLS {
		orgTLS[i] = test.OrgClientTLSConfig(c.OrdererEnv.ArtifactsPath, i, serverCACertPaths)
	}

	// Step 1: Assert all three peer orgs can access services with proper signed envelopes.
	// The sidecar updates ACL immediately when processing the genesis config block.
	// The query service polls the DB periodically, so we use Eventually for it.
	t.Log("Step 1: Initial access - all three orgs should be authorized")
	for orgIdx := range orgTLS {
		// Test query service
		require.NoError(t, tryQueryServiceRPC(queryEndpoint, orgTLS[orgIdx], peerIdentities[orgIdx]),
			"query: peer-org-%d should be authorized", orgIdx)

		// Test sidecar block query
		require.NoError(t, trySidecarBlockQueryRPC(sidecarEndpoint, orgTLS[orgIdx], peerIdentities[orgIdx]),
			"sidecar block query: peer-org-%d should be authorized", orgIdx)

		// Test sidecar notification service
		require.NoError(t, trySidecarNotificationRPC(sidecarEndpoint, orgTLS[orgIdx], peerIdentities[orgIdx]),
			"sidecar notification: peer-org-%d should be authorized", orgIdx)
	}

	// Step 2: Submit config block removing peer-org-2 (keep only peer-org-0 and peer-org-1).
	// CreateOrExtendConfigBlockWithCrypto retains existing crypto on disk, so peer-org-2's
	// certs remain available for reconnection in Step 4.
	t.Log("Step 2: Dynamic removal - submit config with 2 peer orgs")
	c.OrdererEnv.SubmitConfigBlock(t, &testcrypto.ConfigBlock{
		OrdererEndpoints:      c.OrdererEnv.AllEndpoints,
		PeerOrganizationCount: 2,
	})
	c.ValidateExpectedResultsInCommittedBlock(t, &runner.ExpectedStatusInBlock{
		Statuses: []committerpb.Status{committerpb.Status_COMMITTED},
	})

	// Step 3: Verify peer-org-2 is rejected and peer-org-0 remains authorized.
	t.Log("Step 3: Negative assertion - peer-org-2 rejected, peer-org-0 authorized")

	// Sidecar updates immediately from config block processing.
	require.NoError(t, tryQueryServiceRPC(queryEndpoint, orgTLS[0], peerIdentities[0]),
		"query: peer-org-0 should be authorized")
	require.NoError(t, trySidecarBlockQueryRPC(sidecarEndpoint, orgTLS[0], peerIdentities[0]),
		"sidecar block query: peer-org-0 should be authorized")
	require.NoError(t, trySidecarNotificationRPC(sidecarEndpoint, orgTLS[0], peerIdentities[0]),
		"sidecar notification: peer-org-0 should be authorized")

	// peer-org-2 should be rejected immediately by sidecar
	requirePermissionDenied(t, tryQueryServiceRPC(queryEndpoint, orgTLS[2], peerIdentities[2]),
		"query: peer-org-2 should be rejected")
	requirePermissionDenied(t, trySidecarBlockQueryRPC(sidecarEndpoint, orgTLS[2], peerIdentities[2]),
		"sidecar block query: peer-org-2 should be rejected")
	requirePermissionDenied(t, trySidecarNotificationRPC(sidecarEndpoint, orgTLS[2], peerIdentities[2]),
		"sidecar notification: peer-org-2 should be rejected")

	// Query service polls the DB; wait for the ACL refresh (up to 15s).
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		requirePermissionDenied(ct, tryQueryServiceRPC(queryEndpoint, orgTLS[2], peerIdentities[2]),
			"query service should reject peer-org-2 after ACL refresh")
	}, 15*time.Second, time.Second)

	// Step 4: Restore peer-org-2.
	t.Log("Step 4: Restoration - add peer-org-2 back")
	c.OrdererEnv.SubmitConfigBlock(t, &testcrypto.ConfigBlock{
		OrdererEndpoints:      c.OrdererEnv.AllEndpoints,
		PeerOrganizationCount: 3,
	})
	c.ValidateExpectedResultsInCommittedBlock(t, &runner.ExpectedStatusInBlock{
		Statuses: []committerpb.Status{committerpb.Status_COMMITTED},
	})

	// Sidecar: peer-org-2 can access immediately.
	require.NoError(t, trySidecarBlockQueryRPC(sidecarEndpoint, orgTLS[2], peerIdentities[2]),
		"sidecar block query: peer-org-2 should be authorized")
	require.NoError(t, trySidecarNotificationRPC(sidecarEndpoint, orgTLS[2], peerIdentities[2]),
		"sidecar notification: peer-org-2 should be authorized")

	// Query service: wait for ACL refresh.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.NoError(ct, tryQueryServiceRPC(queryEndpoint, orgTLS[2], peerIdentities[2]),
			"query: peer-org-2 should be authorized")
	}, 15*time.Second, time.Second)

	// Step 5: Test with unsigned envelope (should always be rejected).
	t.Log("Step 5: Unsigned envelope - should be rejected by all services")
	requirePermissionDenied(t, tryQueryServiceWithUnsignedEnvelope(queryEndpoint, orgTLS[0]),
		"query: unsigned envelope should be rejected")
	requirePermissionDenied(t, trySidecarBlockQueryWithUnsignedEnvelope(sidecarEndpoint, orgTLS[0]),
		"sidecar block query: unsigned envelope should be rejected")
	requirePermissionDenied(t, trySidecarNotificationWithUnsignedEnvelope(sidecarEndpoint, orgTLS[0]),
		"sidecar notification: unsigned envelope should be rejected")

	// Step 6: Restart sidecar and query service, then verify all clients can reconnect.
	// This ensures that ACL initialization from persisted config blocks works correctly.
	t.Log("Step 6: Service restart - all clients should reconnect with persisted ACL config")

	// Stop and restart sidecar and query service.
	// The restart reuses the same config, so endpoints don't change.
	c.Sidecar.Restart(t)
	c.QueryService.Restart(t)

	// Brief pause to allow old sockets to clear TIME_WAIT; prevents bind failure.
	time.Sleep(2 * time.Second)

	// Wait for services to be ready. Poll frequently to minimize latency.
	t.Log("Waiting for services to be ready after restart...")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.NoError(ct, trySidecarBlockQueryRPC(sidecarEndpoint, orgTLS[0], peerIdentities[0]),
			"sidecar should be ready after restart")
	}, 60*time.Second, 100*time.Millisecond)

	// All orgs should now be authorized (ACL was loaded from persisted config during startup).
	for orgIdx := range orgTLS {
		require.NoError(t, trySidecarBlockQueryRPC(sidecarEndpoint, orgTLS[orgIdx], peerIdentities[orgIdx]),
			"sidecar block query after restart: peer-org-%d should be authorized", orgIdx)
		require.NoError(t, trySidecarNotificationRPC(sidecarEndpoint, orgTLS[orgIdx], peerIdentities[orgIdx]),
			"sidecar notification after restart: peer-org-%d should be authorized", orgIdx)
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			require.NoError(ct, tryQueryServiceRPC(queryEndpoint, orgTLS[orgIdx], peerIdentities[orgIdx]),
				"query after restart: peer-org-%d should be authorized", orgIdx)
		}, 15*time.Second, time.Second)
	}
}

// tryQueryServiceRPC attempts a query service RPC with a signed envelope.
// Returns an error only if the ACL check fails or the connection fails.
// Application-level gRPC errors (InvalidArgument, NotFound, etc.) indicate
// a successful ACL check and are treated as success.
func tryQueryServiceRPC(endpoint connection.WithAddress, tlsConfig connection.TLSConfig, signer msp.SigningIdentity) error {
	creds, err := tlsConfig.ClientCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint.Address(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := committerpb.NewQueryServiceClient(conn)

	// Create a signed envelope for GetTransactionStatus
	txStatusQuery := &committerpb.TxStatusQuery{
		TxIds: []string{"test-tx-id"},
	}
	envelope, err := createSignedEnvelope(runner.TestChannelName, signer, txStatusQuery)
	if err != nil {
		return err
	}

	_, err = client.GetTransactionStatus(ctx, envelope)
	// FilterUnavailableErrorCode returns nil for transient connectivity errors
	// (Unavailable, DeadlineExceeded) and passes through application-level errors.
	// An application-level error means ACL succeeded, so we invert: if the filter
	// passes through an error, the ACL check worked.
	if grpcerror.FilterUnavailableErrorCode(err) != nil {
		return nil
	}
	return err
}

// trySidecarBlockQueryRPC attempts a sidecar block query RPC with a signed envelope.
func trySidecarBlockQueryRPC(endpoint connection.WithAddress, tlsConfig connection.TLSConfig, signer msp.SigningIdentity) error {
	creds, err := tlsConfig.ClientCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint.Address(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := committerpb.NewBlockQueryServiceClient(conn)

	// Create a signed envelope for GetBlockchainInfo (empty request body)
	envelope, err := createSignedEnvelope(runner.TestChannelName, signer, &committerpb.TxStatusQuery{})
	if err != nil {
		return err
	}

	_, err = client.GetBlockchainInfo(ctx, envelope)
	if grpcerror.FilterUnavailableErrorCode(err) != nil {
		return nil
	}
	return err
}

// trySidecarNotificationRPC attempts to open a notification stream with a signed envelope.
func trySidecarNotificationRPC(endpoint connection.WithAddress, tlsConfig connection.TLSConfig, signer msp.SigningIdentity) error {
	creds, err := tlsConfig.ClientCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint.Address(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := committerpb.NewNotifierClient(conn)
	stream, err := client.OpenNotificationStream(ctx)
	if err != nil {
		return err
	}

	// Create a signed envelope for NotificationRequest
	notificationReq := &committerpb.NotificationRequest{
		TxStatusRequest: &committerpb.TxIDsBatch{
			TxIds: []string{"test-tx-id"},
		},
	}
	envelope, err := createSignedEnvelope(runner.TestChannelName, signer, notificationReq)
	if err != nil {
		return err
	}

	// Send the envelope
	if err := stream.Send(envelope); err != nil {
		return err
	}

	// Try to receive a response (or error)
	_, err = stream.Recv()
	if grpcerror.FilterUnavailableErrorCode(err) != nil {
		return nil
	}
	return err
}

// tryQueryServiceWithUnsignedEnvelope attempts a query service RPC with an unsigned envelope.
func tryQueryServiceWithUnsignedEnvelope(endpoint connection.WithAddress, tlsConfig connection.TLSConfig) error {
	creds, err := tlsConfig.ClientCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint.Address(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := committerpb.NewQueryServiceClient(conn)

	// Create an unsigned envelope
	envelope, err := createUnsignedEnvelope(runner.TestChannelName)
	if err != nil {
		return err
	}

	_, err = client.GetTransactionStatus(ctx, envelope)
	return err
}

// trySidecarBlockQueryWithUnsignedEnvelope attempts a sidecar block query RPC with an unsigned envelope.
func trySidecarBlockQueryWithUnsignedEnvelope(endpoint connection.WithAddress, tlsConfig connection.TLSConfig) error {
	creds, err := tlsConfig.ClientCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint.Address(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := committerpb.NewBlockQueryServiceClient(conn)

	// Create an unsigned envelope
	envelope, err := createUnsignedEnvelope(runner.TestChannelName)
	if err != nil {
		return err
	}

	_, err = client.GetBlockchainInfo(ctx, envelope)
	return err
}

// trySidecarNotificationWithUnsignedEnvelope attempts to open a notification stream with an unsigned envelope.
func trySidecarNotificationWithUnsignedEnvelope(endpoint connection.WithAddress, tlsConfig connection.TLSConfig) error {
	creds, err := tlsConfig.ClientCredentials()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint.Address(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := committerpb.NewNotifierClient(conn)
	stream, err := client.OpenNotificationStream(ctx)
	if err != nil {
		return err
	}

	// Create an unsigned envelope
	envelope, err := createUnsignedEnvelope(runner.TestChannelName)
	if err != nil {
		return err
	}

	// Send the envelope
	if err := stream.Send(envelope); err != nil {
		return err
	}

	// Try to receive a response (or error)
	_, err = stream.Recv()
	return err
}

// createSignedEnvelope creates a signed envelope for testing ACL enforcement.
func createSignedEnvelope(channelID string, signer msp.SigningIdentity, payload proto.Message) (*common.Envelope, error) {
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return protoutil.CreateSignedEnvelope(
		common.HeaderType_ENDORSER_TRANSACTION,
		channelID,
		signer,
		&common.Payload{Data: payloadBytes},
		0, // msgVersion
		0, // epoch
	)
}

// createUnsignedEnvelope creates an unsigned envelope for testing ACL rejection.
func createUnsignedEnvelope(channelID string) (*common.Envelope, error) {
	return protoutil.CreateSignedEnvelope(
		common.HeaderType_ENDORSER_TRANSACTION,
		channelID,
		nil, // no signer
		&common.Payload{Data: []byte("test payload")},
		0, // msgVersion
		0, // epoch
	)
}

// requirePermissionDenied asserts that the error is a permission denied error.
func requirePermissionDenied(t require.TestingT, err error, msgAndArgs ...interface{}) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}
	require.Error(t, err, msgAndArgs...)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	require.Equal(t, codes.PermissionDenied, st.Code(), msgAndArgs...)
}

// Made with Bob
