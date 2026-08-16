/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestPolicyChangeRevokesUnaryAccess verifies the RFC's core guarantee for unary RPCs: when an
// operator tightens a resource's policy so the client's role no longer satisfies it, the next call
// is denied. The client is a plain channel member (Readers); the resource is re-mapped to a policy
// requiring membership in an MSP the client does not belong to.
func TestPolicyChangeRevokesUnaryAccess(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)

	// Step 1: Under the original config (sequence 1) GetRows falls back to Readers, which the
	// client satisfies. The call is allowed.
	t.Log("Step 1: original policy — member is authorized for the resource")
	allowBundle := f.bundleAt(t, 1)
	provider := enforcingProvider(allowBundle)
	ctx := authContext(boundAuthInfo(f.identity()))

	allowed := false
	_, err := MSPUnaryServerInterceptor(provider)(ctx, nil, unaryInfo(queryGetRows),
		func(context.Context, any) (any, error) { allowed = true; return nil, nil })
	require.NoError(t, err)
	require.True(t, allowed)

	// Step 2: Operator submits a new config (sequence 2) that maps GetRows to an admin-only-style
	// policy the member cannot satisfy. The provider now serves the stricter bundle.
	t.Log("Step 2: config advances — resource tightened beyond the member's role")
	provider.bundle = f.denyBundle(t, queryGetRows, 2)

	// Step 3: The same authorized connection is now denied on the resource.
	t.Log("Step 3: the member is denied under the new policy")
	_, err = MSPUnaryServerInterceptor(provider)(ctx, nil, unaryInfo(queryGetRows),
		func(context.Context, any) (any, error) {
			require.FailNow(t, "handler must not run after access is revoked")
			return nil, nil
		})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.ErrorContains(t, err, "access denied")
}

// TestPolicyChangeTerminatesStreamMidFlight verifies the same guarantee for an established stream:
// after the config sequence advances to a policy the client no longer satisfies, the next RecvMsg
// (or SendMsg) re-evaluates the identity and terminates the stream instead of delivering the
// message. This is the mid-stream revocation the RFC calls out (e.g. the client's organization is
// removed from the channel).
func TestPolicyChangeTerminatesStreamMidFlight(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)

	// Step 1: Establish the stream under the original config (sequence 1), where the member is
	// authorized. The first messages flow normally.
	t.Log("Step 1: stream established under the original policy")
	allowBundle := f.bundleAt(t, 1)
	authInfo := boundAuthInfo(f.identity())
	provider := enforcingProvider(allowBundle)
	ss := &fakeServerStream{ctx: authContext(authInfo)}
	stream := &authServerStream{
		ServerStream:  ss,
		authInfo:      authInfo,
		provider:      provider,
		fullMethod:    notifierStream,
		currentBundle: allowBundle,
	}
	require.NoError(t, stream.RecvMsg(nil))
	require.NoError(t, stream.SendMsg(nil))
	require.Equal(t, 1, ss.recvCalls)

	// Step 2: Operator tightens the notification stream's policy beyond the member's role and the
	// config sequence advances to 2.
	t.Log("Step 2: config advances mid-stream — notification stream restricted")
	provider.bundle = f.denyBundle(t, notifierStream, 2)

	// Step 3: The next receive detects the sequence advance, re-evaluates the cached identity, and
	// terminates the stream. The underlying stream must NOT be read again after revocation.
	t.Log("Step 3: next receive re-evaluates and terminates the stream")
	recvBefore, sendBefore := ss.recvCalls, ss.sendCalls
	err := stream.RecvMsg(nil)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.ErrorContains(t, err, "access revoked due to config change")
	require.Equal(t, recvBefore, ss.recvCalls, "no further message should be delivered after revocation")

	// A send after revocation is likewise refused and does not reach the underlying stream.
	require.Error(t, stream.SendMsg(nil))
	require.Equal(t, sendBefore, ss.sendCalls)
}

// TestPolicyChangeReEvaluationStillAllowed is the positive counterpart: when the config advances
// but the identity still satisfies the (possibly re-mapped) policy, the stream continues and the
// cached bundle/sequence are updated so later messages take the cheap no-op path.
func TestPolicyChangeReEvaluationStillAllowed(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)

	allowBundle := f.bundleAt(t, 1)
	authInfo := boundAuthInfo(f.identity())
	provider := enforcingProvider(allowBundle)
	ss := &fakeServerStream{ctx: authContext(authInfo)}
	stream := &authServerStream{
		ServerStream:  ss,
		authInfo:      authInfo,
		provider:      provider,
		fullMethod:    notifierStream,
		currentBundle: allowBundle,
	}

	// Advance to a new sequence whose default mapping still authorizes the member.
	provider.bundle = f.bundleAt(t, 2)
	require.NoError(t, stream.RecvMsg(nil))
	require.Equal(t, 1, ss.recvCalls)

	// The cached sequence is now 2, so a subsequent message is a no-op re-check and still passes.
	_, seq := authInfo.GetIdentity()
	require.Equal(t, uint64(2), seq)
	require.NoError(t, stream.SendMsg(nil))
	require.Equal(t, 1, ss.sendCalls)
}

var _ grpc.ServerStream = (*authServerStream)(nil)
