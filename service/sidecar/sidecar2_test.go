package sidecar

import (
	"context"
	"github.com/hyperledger/fabric-x-committer/loadgen/workload"
	"github.com/hyperledger/fabric-x-committer/mock"
	"github.com/hyperledger/fabric-x-committer/utils/connection"
	"github.com/hyperledger/fabric-x-committer/utils/test"
	commontypes "github.com/hyperledger/fabric-x-common/api/types"
	"github.com/hyperledger/fabric-x-common/tools/cryptogen"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// OrdererServerTLSConfigsPerOrg holds each orderer organization's TLS configs.
// Each organization can have multiple orderer nodes, each with its own TLS config.
type OrdererServerTLSConfigsPerOrg struct {
	// Map: orgName -> []TLSConfig (one per orderer node in that org)
	Orderer map[string][]connection.TLSConfig
}

// TestSidecarWithDynamicOrdererRootCAs verifies that the Sidecar correctly updates
// orderer connections when config blocks change orderer organizations.
//
// This test validates the mechanism in sidecar.go:
//   - Bootstrap: ordererconn.NewOrganizationsMaterialsFromConfigBlock + ordererClient.UpdateConnections
//   - Runtime:   configUpdater -> NewOrganizationsMaterialsFromConfigBlock + UpdateConnections
func TestSidecarWithDynamicOrdererRootCAs(t *testing.T) {
	t.Parallel()

	// ── Phase 1: Start initial mock orderers ──────────────────────────────────

	// Generate crypto materials for initial orderer organizations.
	// Use placeholder endpoints — actual ports are assigned dynamically below.
	cryptoPath := t.TempDir()
	_, err := workload.CreateDefaultConfigBlockWithCrypto(cryptoPath, &workload.ConfigBlock{
		OrdererEndpoints:      []*commontypes.OrdererEndpoint{{Host: "localhost", Port: 7050, ID: 0}},
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	// Extract orderer server TLS configs from crypto materials.
	ordererTLSConfigs := BuildOrdererServerTLSConfigsPerOrg(t, cryptoPath)
	t.Logf("Found %d initial orderer organizations", len(ordererTLSConfigs.Orderer))

	// Convert TLS configs to ServerConfigs (Port=0 → dynamic allocation).
	var serverConfigs []*connection.ServerConfig
	for _, tlsConfigs := range ordererTLSConfigs.Orderer {
		for _, tlsCfg := range tlsConfigs {
			serverConfigs = append(serverConfigs, connection.NewLocalHostServer(tlsCfg))
		}
	}

	// Start mock orderers. After this call, serverConfigs[i].Endpoint.Port
	// is updated in-place to the actual assigned port.
	orderer, ordererServers := mock.StartMockOrderingServices(t, &mock.OrdererConfig{
		BlockSize:     100,
		BlockTimeout:  100 * time.Millisecond,
		ServerConfigs: serverConfigs,
	})

	// Build actual endpoints using the now-assigned ports.
	actualEndpoints := test.NewOrdererEndpoints(0, ordererServers.Configs...)
	t.Logf("Initial orderer endpoints: %v", actualEndpoints)

	// Recreate config block with actual endpoints and write as genesis block.
	configBlock, err := workload.CreateDefaultConfigBlockWithCrypto(cryptoPath, &workload.ConfigBlock{
		OrdererEndpoints:      actualEndpoints,
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	// ── Phase 2: Start sidecar with genesis block ─────────────────────────────

	serverTLS, clientTLS := test.CreateServerAndClientTLSConfig(t, connection.MutualTLSMode)
	env := newSidecarTestEnvWithTLS(t, sidecarTestConfig{
		NumService: 1,
		ServerTLS:  serverTLS,
		ClientTLS:  clientTLS,
	})
	// Override the orderer env with our custom orderer that has real TLS certs.
	env.ordererEnv = &mock.OrdererTestEnv{
		Orderer:        orderer,
		OrdererServers: ordererServers,
		TestConfig:     &mock.OrdererTestConfig{ChanID: "testchannel"},
	}
	env.configBlock = configBlock

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	env.startSidecarService(ctx, t)

	// Verify sidecar can fetch blocks from initial orderers.
	env.ordererEnv.SubmitConfigBlock(t, nil)
	env.requireBlock(ctx, t, 0)
	t.Log("✓ Sidecar connected to initial orderers")

	// ── Phase 3: Start new mock orderers ─────────────────────────────────────

	newCryptoPath := t.TempDir()
	_, err = workload.CreateDefaultConfigBlockWithCrypto(newCryptoPath, &workload.ConfigBlock{
		OrdererEndpoints:      []*commontypes.OrdererEndpoint{{Host: "localhost", Port: 8050, ID: 1}},
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	newOrdererTLSConfigs := BuildOrdererServerTLSConfigsPerOrg(t, newCryptoPath)

	var newServerConfigs []*connection.ServerConfig
	for _, tlsConfigs := range newOrdererTLSConfigs.Orderer {
		for _, tlsCfg := range tlsConfigs {
			newServerConfigs = append(newServerConfigs, connection.NewLocalHostServer(tlsCfg))
		}
	}

	newOrderer, newOrdererServers := mock.StartMockOrderingServices(t, &mock.OrdererConfig{
		BlockSize:     100,
		BlockTimeout:  100 * time.Millisecond,
		ServerConfigs: newServerConfigs,
	})

	newActualEndpoints := test.NewOrdererEndpoints(uint32(len(actualEndpoints)), newOrdererServers.Configs...)

	newConfigBlock, err := workload.CreateDefaultConfigBlockWithCrypto(newCryptoPath, &workload.ConfigBlock{
		OrdererEndpoints:      newActualEndpoints,
		ChannelID:             "testchannel",
		PeerOrganizationCount: 1,
	})
	require.NoError(t, err)

	// ── Phase 4: Submit config block and verify orderer connection update ─────

	// Submit config block through existing orderer — sidecar's configUpdater will
	// call ordererconn.NewOrganizationsMaterialsFromConfigBlock + UpdateConnections.
	require.NoError(t, orderer.SubmitBlock(ctx, newConfigBlock))

	// Verify sidecar updated connections and can fetch from new orderers.
	require.NoError(t, newOrderer.SubmitBlock(ctx, createTestBlock(t, 3)))
	require.Eventually(t, func() bool {
		return env.sidecar.blockStore.Height() > 3
	}, 30*time.Second, 500*time.Millisecond,
		"Sidecar should receive blocks from new orderers after config update")

	t.Log("✓ Sidecar updated orderer connections and connected to new orderers")
}

// BuildOrdererServerTLSConfigsPerOrg extracts orderer server TLS configs from crypto materials.
// For each orderer organization, it returns the server credentials for ALL orderer nodes.
// The caller should convert these to []*connection.ServerConfig via connection.NewLocalHostServer
// and pass them to mock.StartMockOrderingServices via conf.ServerConfigs.
func BuildOrdererServerTLSConfigsPerOrg(t *testing.T, root string) *OrdererServerTLSConfigsPerOrg {
	t.Helper()

	ordererRoot := filepath.Join(root, cryptogen.OrdererOrganizationsDir)
	ordererConfigs := make(map[string][]connection.TLSConfig)

	orgEntries, err := os.ReadDir(ordererRoot)
	if err != nil {
		return &OrdererServerTLSConfigsPerOrg{
			Orderer: make(map[string][]connection.TLSConfig),
		}
	}

	for _, orgEntry := range orgEntries {
		if !orgEntry.IsDir() {
			continue
		}

		orgName := orgEntry.Name()
		orderersDir := filepath.Join(ordererRoot, orgName, cryptogen.OrdererOU)

		if _, err := os.Stat(orderersDir); err != nil {
			continue
		}

		ordererEntries, err := os.ReadDir(orderersDir)
		require.NoError(t, err)

		for _, ordererEntry := range ordererEntries {
			if !ordererEntry.IsDir() {
				continue
			}

			tlsDir := filepath.Join(orderersDir, ordererEntry.Name(), "tls")

			certPath := filepath.Join(tlsDir, "server.crt")
			require.FileExists(t, certPath)
			keyPath := filepath.Join(tlsDir, "server.key")
			require.FileExists(t, keyPath)
			caPath := filepath.Join(tlsDir, "ca.crt")
			require.FileExists(t, caPath)

			ordererConfigs[orgName] = append(ordererConfigs[orgName], connection.TLSConfig{
				Mode:        connection.MutualTLSMode,
				CertPath:    certPath,
				KeyPath:     keyPath,
				CACertPaths: []string{caPath},
			})
		}
	}

	return &OrdererServerTLSConfigsPerOrg{
		Orderer: ordererConfigs,
	}
}
