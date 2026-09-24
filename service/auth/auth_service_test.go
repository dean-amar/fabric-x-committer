/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"

	"github.com/hyperledger/fabric-x-committer/api/servicepb"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
)

// TestAuthSecureConnection verifies the auth service gRPC server's behavior
// under various client TLS configurations.
func TestAuthSecureConnection(t *testing.T) {
	t.Parallel()
	test.RunSecureConnectionTest(
		t,
		func(t *testing.T, serverTLS, clientTLS connection.TLSConfig) test.RPCAttempt {
			t.Helper()
			env := NewAuthTestEnv(t, &ACLTestEnvParams{ServerTLS: serverTLS, ClientTLS: clientTLS})
			return func(ctx context.Context, t *testing.T, cfg connection.TLSConfig) error {
				t.Helper()
				client := test.CreateClientWithTLS(
					t, &env.ServerConfig.GRPC.Endpoint, cfg, servicepb.NewAuthServiceClient,
				)
				_, err := client.IssueNonce(ctx, nil)
				return err
			}
		},
	)
}
