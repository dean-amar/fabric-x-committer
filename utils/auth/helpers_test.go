/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/configtx"
	"github.com/hyperledger/fabric-x-common/common/policydsl"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testChannelID = "testchannel"

// bundleFixture holds a freshly generated channel configuration and the peer signing identity
// that belongs to it. It builds real channelconfig.Bundle values (no fakes), so tests exercise
// the same MSP deserialization, policy evaluation, and sequence handling the production path uses.
type bundleFixture struct {
	cryptoDir string
	baseCfg   *cb.Config // configuration at sequence 0, cloned before each derived bundle
	signer    msp.SigningIdentity
	mspID     string
}

// newBundleFixture generates crypto material for one peer org and captures the base config and the
// peer's signing identity. The peer identity satisfies the channel's implicit-meta Readers/Writers/
// Admins policies (single-org network), which makes it a good "authorized" identity; denyBundle
// builds a policy it provably does NOT satisfy.
func newBundleFixture(t *testing.T) *bundleFixture {
	t.Helper()

	dir := t.TempDir()
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(dir, &testcrypto.ConfigBlock{
		ChannelID:             testChannelID,
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, block)

	env, err := protoutil.UnmarshalEnvelope(block.Data.Data[0])
	require.NoError(t, err)
	payload, err := protoutil.UnmarshalPayload(env.Payload)
	require.NoError(t, err)
	confEnv, err := configtx.UnmarshalConfigEnvelope(payload.Data)
	require.NoError(t, err)

	identities, err := testcrypto.GetPeersIdentities(dir)
	require.NoError(t, err)
	require.NotEmpty(t, identities)

	return &bundleFixture{
		cryptoDir: dir,
		baseCfg:   confEnv.Config,
		signer:    identities[0],
		mspID:     identities[0].GetMSPIdentifier(),
	}
}

// identity returns the peer's identity (an msp.Identity view of its signing identity).
//
//nolint:ireturn // msp.Identity is an interface by design.
func (f *bundleFixture) identity() msp.Identity {
	return f.signer
}

// bundleAt builds the unmodified base configuration at the given sequence. The peer identity is
// authorized for every ACL-mapped resource here (resources fall back to the Readers default).
func (f *bundleFixture) bundleAt(t *testing.T, sequence uint64) *channelconfig.Bundle {
	t.Helper()
	cfg := cloneProto(t, f.baseCfg)
	cfg.Sequence = sequence
	bundle, err := channelconfig.NewBundle(testChannelID, cfg, factory.GetDefault())
	require.NoError(t, err)
	return bundle
}

// denyBundle builds a configuration at the given sequence whose ACLs map `resource` to a signature
// policy that requires membership in a non-existent MSP. The fixture's peer identity therefore
// provably fails that policy, modeling an operator tightening a resource beyond the client's role.
func (f *bundleFixture) denyBundle(t *testing.T, resource string, sequence uint64) *channelconfig.Bundle {
	t.Helper()
	cfg := cloneProto(t, f.baseCfg)
	cfg.Sequence = sequence

	appGroup := cfg.ChannelGroup.Groups[channelconfig.ApplicationGroupKey]
	require.NotNil(t, appGroup, "application group must exist in the base config")

	// A signature policy naming an MSP that no channel member belongs to: unsatisfiable by
	// the fixture's peer identity, so it exercises the genuine "policy not satisfied" path
	// rather than the "no such policy" fail-closed path.
	const denyPolicyName = "DenyForTest"
	appGroup.Policies[denyPolicyName] = &cb.ConfigPolicy{
		Policy: &cb.Policy{
			Type:  int32(cb.Policy_SIGNATURE),
			Value: protoutil.MarshalOrPanic(policydsl.SignedByMspMember("no-such-msp")),
		},
	}
	appGroup.Values[channelconfig.ACLsKey] = &cb.ConfigValue{
		Value: protoutil.MarshalOrPanic(channelconfig.ACLValues(map[string]string{
			resource: "/Channel/Application/" + denyPolicyName,
		}).Value()),
	}

	bundle, err := channelconfig.NewBundle(testChannelID, cfg, factory.GetDefault())
	require.NoError(t, err)
	return bundle
}

// signedEnvelope builds a signed authorization envelope for the fixture's identity, carrying the
// given TLS cert hash (nil for non-mTLS). protoutil stamps a current timestamp into the channel
// header, so the envelope is fresh unless the caller rewrites it.
func (f *bundleFixture) signedEnvelope(t *testing.T, tlsCertHash []byte) *cb.Envelope {
	t.Helper()
	env, err := protoutil.CreateSignedEnvelopeWithTLSBinding(
		cb.HeaderType_MESSAGE, testChannelID, f.signer, &cb.Envelope{}, 0, 0, tlsCertHash,
	)
	require.NoError(t, err)
	return env
}

// envelopeWithTimestamp is like signedEnvelope but stamps a specific creation time into the
// channel header, for exercising the freshness window.
func (f *bundleFixture) envelopeWithTimestamp(t *testing.T, tlsCertHash []byte, ts time.Time) *cb.Envelope {
	t.Helper()
	env := f.signedEnvelope(t, tlsCertHash)
	rewriteEnvelopeTimestamp(t, env, ts)
	return env
}

// rewriteEnvelopeTimestamp re-signs the envelope with its channel-header timestamp set to ts,
// so freshness checks can be driven to specific skews. It preserves the TLS cert hash binding.
func rewriteEnvelopeTimestamp(t *testing.T, env *cb.Envelope, ts time.Time) {
	t.Helper()
	payload, err := protoutil.UnmarshalPayload(env.Payload)
	require.NoError(t, err)
	chdr, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	require.NoError(t, err)
	chdr.Timestamp = timestamppb.New(ts)
	payload.Header.ChannelHeader = protoutil.MarshalOrPanic(chdr)
	env.Payload = protoutil.MarshalOrPanic(payload)
	// The signature does not cover freshness for these tests; the timestamp check runs before
	// signature verification, so re-signing is unnecessary for the freshness assertions.
}

// stubProvider is a test BundleProvider whose returned bundle, error, and RequiresACL flag are all
// controllable. It lets interceptor tests drive the enforcement branches (internal, no-bundle,
// error, enforced) and swap the bundle mid-test to simulate a configuration update.
type stubProvider struct {
	bundle      *channelconfig.Bundle
	err         error
	requiresACL bool
}

func (p *stubProvider) GetBundle() (*channelconfig.Bundle, error) {
	return p.bundle, p.err
}

func (p *stubProvider) RequiresACL() bool {
	return p.requiresACL
}

// enforcingProvider returns a provider that enforces ACL against the given bundle.
func enforcingProvider(bundle *channelconfig.Bundle) *stubProvider {
	return &stubProvider{bundle: bundle, requiresACL: true}
}

// authContext returns a context carrying the given MSPAuthInfo as gRPC peer auth info, as the
// custom credentials would install it on a real connection.
func authContext(authInfo *MSPAuthInfo) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: authInfo})
}

// boundAuthInfo returns an MSPAuthInfo with the given identity already bound at config sequence 1,
// as it would be after a successful Authorize call against the establishing bundle (which the
// fixtures build at sequence 1).
func boundAuthInfo(identity msp.Identity) *MSPAuthInfo {
	info := &MSPAuthInfo{}
	info.SetIdentity(identity, 1)
	return info
}

// cloneProto deep-copies a protobuf message and returns it as its concrete type, failing the test
// if the clone is somehow not of the expected type (which cannot happen for proto.Clone, but keeps
// the type assertion checked).
func cloneProto[T proto.Message](t *testing.T, msg T) T {
	t.Helper()
	cloned, ok := proto.Clone(msg).(T)
	require.True(t, ok, "cloned message has unexpected type")
	return cloned
}
