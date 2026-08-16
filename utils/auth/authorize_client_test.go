/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-x-common/api/committerpb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hyperledger/fabric-x-committer/utils/retry"
)

// fakeClientConn implements grpc.ClientConnInterface for the Authorize unary RPC. It records how
// many times Invoke was called and returns a scripted response/error per call.
type fakeClientConn struct {
	mu      sync.Mutex
	calls   int
	handler func(call int, reply any) error
}

// Invoke implements grpc.ClientConnInterface; the argument list is fixed by that interface.
//
//nolint:revive // argument-limit: signature is dictated by grpc.ClientConnInterface.
func (c *fakeClientConn) Invoke(_ context.Context, _ string, _, reply any, _ ...grpc.CallOption) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.handler(c.calls, reply)
}

// NewStream satisfies grpc.ClientConnInterface; the Authorize unary RPC never opens a stream.
//
//nolint:ireturn // return type is dictated by the grpc.ClientConnInterface method set.
func (*fakeClientConn) NewStream(
	_ context.Context, _ *grpc.StreamDesc, _ string, _ ...grpc.CallOption,
) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streaming not used by Authorize")
}

func (c *fakeClientConn) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestAuthorizeConnectionNoSignerIsNoOp(t *testing.T) {
	t.Parallel()
	conn := &fakeClientConn{handler: func(int, any) error {
		require.FailNow(t, "no RPC should be issued when Signer is nil")
		return nil
	}}
	require.NoError(t, AuthorizeConnection(t.Context(), conn, AuthorizeParameters{}))
	require.Zero(t, conn.callCount())
}

func TestAuthorizeConnectionSuccess(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	conn := &fakeClientConn{handler: func(_ int, reply any) error {
		setAuthorizeSuccess(reply)
		return nil
	}}
	require.NoError(t, AuthorizeConnection(t.Context(), conn, AuthorizeParameters{
		Signer:    f.signer,
		ChannelID: testChannelID,
	}))
	require.Equal(t, 1, conn.callCount())
}

func TestAuthorizeConnectionPermanentDenialStops(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	conn := &fakeClientConn{handler: func(_ int, reply any) error {
		// A structured denial (Success=false, no gRPC error) must be permanent: no retry.
		resp, ok := reply.(*committerpb.AuthorizeResponse)
		require.True(t, ok)
		resp.Success = false
		resp.Message = "identity is not a member of Readers"
		return nil
	}}
	err := AuthorizeConnection(t.Context(), conn, AuthorizeParameters{Signer: f.signer, ChannelID: testChannelID})
	require.ErrorContains(t, err, "authorization denied")
	require.Equal(t, 1, conn.callCount(), "a permanent denial must not be retried")
}

func TestAuthorizeConnectionRetriesOnUnavailable(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	// Fail with Unavailable twice (server bootstrapping), then succeed. The helper must retry.
	conn := &fakeClientConn{handler: func(call int, reply any) error {
		if call < 3 {
			return status.Error(codes.Unavailable, "bundle not loaded yet")
		}
		setAuthorizeSuccess(reply)
		return nil
	}}

	err := authorizeConnection(t.Context(), conn,
		AuthorizeParameters{Signer: f.signer, ChannelID: testChannelID}, fastRetryProfile())
	require.NoError(t, err)
	require.GreaterOrEqual(t, conn.callCount(), 3)
}

func TestAuthorizeConnectionGivesUpAfterTimeout(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	conn := &fakeClientConn{handler: func(int, any) error {
		return status.Error(codes.Unavailable, "still bootstrapping")
	}}

	err := authorizeConnection(t.Context(), conn,
		AuthorizeParameters{Signer: f.signer, ChannelID: testChannelID}, fastRetryProfile())
	require.ErrorContains(t, err, "did not succeed before timeout")
	require.Positive(t, conn.callCount())
}

// --- helpers -------------------------------------------------------------------------------

func setAuthorizeSuccess(reply any) {
	if resp, ok := reply.(*committerpb.AuthorizeResponse); ok {
		resp.Success = true
		resp.Message = "authorized"
	}
}

// fastRetryProfile returns a retry profile with a short budget and backoff, so bootstrap-retry
// tests exercise multiple attempts quickly. It is passed explicitly to authorizeConnection rather
// than mutating package state, keeping the tests race-free under t.Parallel().
func fastRetryProfile() retry.Profile {
	budget := 2 * time.Second
	return retry.Profile{
		InitialInterval: 10 * time.Millisecond,
		MaxInterval:     20 * time.Millisecond,
		Multiplier:      1.5,
		MaxElapsedTime:  &budget,
	}
}
