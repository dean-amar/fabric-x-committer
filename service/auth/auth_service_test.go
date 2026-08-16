/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"testing"

	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAuthorizeHandlerFailsClosed verifies the defensive fallback: in normal operation the
// AuthorizeInterceptor handles the Authorize RPC before it reaches this handler. Reaching the
// handler means the interceptor chain is misconfigured, so it must fail closed (Internal error)
// rather than binding an identity or returning success.
func TestAuthorizeHandlerFailsClosed(t *testing.T) {
	t.Parallel()
	svc := NewAuthService()

	resp, err := svc.Authorize(t.Context(), &committerpb.AuthorizeRequest{})
	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	require.ErrorContains(t, err, "interceptor not installed")
}
