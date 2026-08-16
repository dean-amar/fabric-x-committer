/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package serve

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-x-common/api/types"
	"github.com/hyperledger/fabric-x-common/common/channelconfig"
	"github.com/hyperledger/fabric-x-common/common/configtx"
	"github.com/hyperledger/fabric-x-common/common/crypto/tlsgen"
	"github.com/hyperledger/fabric-x-common/protoutil"
	"github.com/hyperledger/fabric-x-common/tools/configtxgen"
	"github.com/hyperledger/fabric-x-common/tools/cryptogen"
	"github.com/hyperledger/fabric-x-common/utils/testcrypto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/serialization"
)

const localHost = "localhost"

func TestDynamicTLS(t *testing.T) {
	t.Parallel()

	var cas [3]tlsgen.CA
	for i := range cas {
		ca, err := tlsgen.NewCA()
		require.NoError(t, err)
		cas[i] = ca
	}

	for _, tc := range []struct {
		name       string
		updates    []tlsgen.CA // sequential SetClientRootCAs calls
		contain    []tlsgen.CA
		notContain []tlsgen.CA
	}{
		{
			name:    "initial config has only static CAs",
			contain: []tlsgen.CA{cas[0]},
		},
		{
			name:    "after SetClientRootCAs includes dynamic CAs",
			updates: []tlsgen.CA{cas[1]},
			contain: []tlsgen.CA{cas[0], cas[1]},
		},
		{
			name:    "SetClientRootCAs replaces previous dynamic CAs",
			updates: []tlsgen.CA{cas[1], cas[2]},
			contain: []tlsgen.CA{cas[0], cas[2]},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dtls, updater := newTestDynamicTLS(t, cas[0])
			require.False(t, dtls.updateNoLock())
			for _, ca := range tc.updates {
				updater.UpdateClientRootCAs([][]byte{ca.CertBytes()})
				require.True(t, dtls.updateNoLock())
				require.False(t, dtls.updateNoLock())
			}

			cfg, err := dtls.GetConfigForClient(nil)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			requireCAs(t, cfg.ClientCAs, tc.contain...)
		})
	}

	t.Run("server certificate is preserved across updates", func(t *testing.T) {
		t.Parallel()
		dtls, updater := newTestDynamicTLS(t, cas[0])
		updater.UpdateClientRootCAs([][]byte{cas[1].CertBytes()})

		cfg, err := dtls.GetConfigForClient(nil)
		require.NoError(t, err)
		require.Len(t, cfg.Certificates, 1)
	})

	t.Run("SetClientRootCAs rejects invalid cert", func(t *testing.T) {
		t.Parallel()
		dtls, updater := newTestDynamicTLS(t, cas[0])

		badCA, err := tlsgen.NewCA()
		require.NoError(t, err)
		badCA.CertBytes()[0] = 0

		updater.UpdateClientRootCAs([][]byte{badCA.CertBytes()})
		require.True(t, dtls.updateNoLock())
		require.False(t, dtls.updateNoLock())

		cfg, err := dtls.GetConfigForClient(nil)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		requireCAs(t, cfg.ClientCAs, cas[0])
	})
}

func TestExtractAppTLSCAsFromEnvelope(t *testing.T) {
	t.Parallel()
	targetPath := t.TempDir()

	block, err := cryptogen.CreateOrExtendConfigBlockWithCrypto(cryptogen.ConfigBlockParameters{
		TargetPath:  targetPath,
		BaseProfile: configtxgen.SampleFabricX,
		ChannelID:   "test-channel",
		Organizations: []cryptogen.OrganizationParameters{
			{
				Name:   "orderer-org",
				Domain: "orderer-org.com",
				OrdererEndpoints: []*types.OrdererEndpoint{
					{Host: "localhost", Port: 7050},
				},
				ConsenterNodes: []cryptogen.Node{
					{CommonName: "consenter", Hostname: "consenter.com"},
				},
				OrdererNodes: []cryptogen.Node{
					{CommonName: "orderer", Hostname: "orderer.com", SANS: []string{"localhost"}},
				},
			},
			{
				Name:   "peer-org",
				Domain: "peer-org.com",
				PeerNodes: []cryptogen.Node{
					{CommonName: "peer0", Hostname: "peer0.com", SANS: []string{"localhost"}},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, block.Data.Data)

	t.Run("extracts TLS CAs from valid config envelope", func(t *testing.T) {
		t.Parallel()
		certs, err := serialization.ExtractAppTLSCAsFromEnvelope(block.Data.Data[0])
		require.NoError(t, err)
		require.NotEmpty(t, certs, "should extract at least one TLS CA certificate")

		for _, cert := range certs {
			require.NotEmpty(t, cert)
			blk, _ := pem.Decode(cert)
			require.NotNil(t, blk, "each cert should be valid PEM")
		}
	})

	t.Run("returns error for invalid envelope", func(t *testing.T) {
		t.Parallel()
		_, err := serialization.ExtractAppTLSCAsFromEnvelope([]byte("invalid"))
		require.Error(t, err)
	})

	t.Run("returns error for nil envelope", func(t *testing.T) {
		t.Parallel()
		_, err := serialization.ExtractAppTLSCAsFromEnvelope(nil)
		require.Error(t, err)
	})
}

// TestUpdateBundleMonotonic verifies that UpdateBundle only installs a bundle whose config
// sequence is strictly greater than the currently stored one. This is the sink-side guard against
// a stale config read rolling the effective ACL policy backward and reinstating revoked access.
func TestUpdateBundleMonotonic(t *testing.T) {
	t.Parallel()

	baseCfg := loadBaseConfig(t)
	bundleAt := func(seq uint64) *channelconfig.Bundle {
		cfg, ok := proto.Clone(baseCfg).(*cb.Config)
		require.True(t, ok)
		cfg.Sequence = seq
		bundle, err := channelconfig.NewBundle("testchannel", cfg, factory.GetDefault())
		require.NoError(t, err)
		return bundle
	}

	var updater ACLUpdater

	// A nil bundle is ignored.
	require.False(t, updater.UpdateBundle(nil))

	// Step 1: first non-nil bundle is accepted.
	require.True(t, updater.UpdateBundle(bundleAt(1)))
	require.Equal(t, uint64(1), updater.bundle.Load().ConfigtxValidator().Sequence())

	// Step 2: a strictly newer sequence is accepted.
	require.True(t, updater.UpdateBundle(bundleAt(2)))
	require.Equal(t, uint64(2), updater.bundle.Load().ConfigtxValidator().Sequence())

	// Step 3: an equal or older sequence is rejected, and the stored bundle is unchanged.
	require.False(t, updater.UpdateBundle(bundleAt(2)))
	require.False(t, updater.UpdateBundle(bundleAt(1)))
	require.Equal(t, uint64(2), updater.bundle.Load().ConfigtxValidator().Sequence(),
		"a stale (older/equal) bundle must not roll the stored sequence backward")
}

// loadBaseConfig generates a config block and returns its channel configuration at sequence 0, for
// building derived bundles at chosen sequences.
func loadBaseConfig(t *testing.T) *cb.Config {
	t.Helper()
	dir := t.TempDir()
	block, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(dir, &testcrypto.ConfigBlock{
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	env, err := protoutil.UnmarshalEnvelope(block.Data.Data[0])
	require.NoError(t, err)
	payload, err := protoutil.UnmarshalPayload(env.Payload)
	require.NoError(t, err)
	confEnv, err := configtx.UnmarshalConfigEnvelope(payload.Data)
	require.NoError(t, err)
	return confEnv.Config
}

// newTestDynamicTLS creates a DynamicTLS via NewDynamicTLSFromConfig using the given CA
// for both server credentials and client CA trust.
func newTestDynamicTLS(t *testing.T, ca tlsgen.CA) (*ACLProvider, *ACLUpdater) {
	t.Helper()
	keyPair, err := ca.NewServerCertKeyPair(localHost)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(certPath, keyPair.Cert, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPair.Key, 0o600))
	require.NoError(t, os.WriteFile(caPath, ca.CertBytes(), 0o600))

	dtls, err := NewACLProvider(connection.TLSConfig{
		Mode:        connection.MutualTLSMode,
		CertPath:    certPath,
		KeyPath:     keyPath,
		CACertPaths: []string{caPath},
	})
	require.NoError(t, err)

	var updater ACLUpdater
	RegisterACLUpdater(dtls, &updater, true) // Test with ACL enforcement enabled
	return dtls, &updater
}

// requireCAs asserts that the pool contains all CAs in `contain` and none of the CAs in `notContain`.
func requireCAs(t *testing.T, pool *x509.CertPool, contain ...tlsgen.CA) {
	t.Helper()
	require.NotNil(t, pool)

	containsCAs := make([][]byte, len(contain))
	for i, ca := range contain {
		containsCAs[i] = ca.CertBytes()
	}
	expectedPool, err := connection.BuildCertPool(containsCAs...)
	require.NoError(t, err)
	require.True(t, pool.Equal(expectedPool))
}
