/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMSPAuthInfoAuthType(t *testing.T) {
	t.Parallel()
	require.Equal(t, "mTLS+MSP", (&MSPAuthInfo{}).AuthType())
}

func TestMSPAuthInfoSetGetIdentity(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	info := &MSPAuthInfo{}

	// Before binding, no identity is present.
	identity, seq := info.GetIdentity()
	require.Nil(t, identity)
	require.Zero(t, seq)

	// After binding, the identity and sequence round-trip.
	info.SetIdentity(f.identity(), 7)
	identity, seq = info.GetIdentity()
	require.NotNil(t, identity)
	require.Equal(t, f.mspID, identity.GetMSPIdentifier())
	require.Equal(t, uint64(7), seq)

	// Re-binding overwrites (as it does when the config sequence advances mid-stream).
	info.SetIdentity(f.identity(), 8)
	_, seq = info.GetIdentity()
	require.Equal(t, uint64(8), seq)
}

func TestMSPAuthInfoHasClientCertificate(t *testing.T) {
	t.Parallel()
	require.False(t, (&MSPAuthInfo{}).HasClientCertificate())
	require.False(t, (&MSPAuthInfo{TLSCertHash: []byte{}}).HasClientCertificate())
	require.True(t, (&MSPAuthInfo{TLSCertHash: []byte{0x01}}).HasClientCertificate())
}

// TestMSPAuthInfoConcurrentAccess exercises the RWMutex under the race detector: the identity is
// bound on one goroutine (the Authorize RPC / mid-stream re-eval) while other goroutines read it
// (concurrent business RPCs on the same connection).
func TestMSPAuthInfoConcurrentAccess(t *testing.T) {
	t.Parallel()
	f := newBundleFixture(t)
	info := &MSPAuthInfo{}

	var wg sync.WaitGroup
	for i := range 8 {
		seq := uint64(i)
		wg.Go(func() {
			info.SetIdentity(f.identity(), seq)
		})
		wg.Go(func() {
			_, _ = info.GetIdentity()
			_ = info.HasClientCertificate()
		})
	}
	wg.Wait()

	identity, _ := info.GetIdentity()
	require.NotNil(t, identity)
}
