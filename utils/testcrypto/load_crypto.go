/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testcrypto

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/hyperledger/fabric-x-common/msp"
	"github.com/hyperledger/fabric-x-common/tools/cryptogen"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric-x-committer/utils/connection"
)

// GetPeersIdentities returns the peers' identities from a crypto path.
func GetPeersIdentities(cryptoPath string) ([]msp.SigningIdentity, error) {
	return GetSigningIdentities(GetPeersMspDirs(cryptoPath)...)
}

// GetConsenterIdentities returns the orderer consenters identities from a crypto path.
func GetConsenterIdentities(cryptoPath string) ([]msp.SigningIdentity, error) {
	return GetSigningIdentities(GetOrdererMspDirs(cryptoPath)...)
}

// GetSigningIdentities loads signing identities from the given MSP directories.
func GetSigningIdentities(mspDirs ...*msp.DirLoadParameters) ([]msp.SigningIdentity, error) {
	identities := make([]msp.SigningIdentity, len(mspDirs))
	for i, mspDir := range mspDirs {
		localMsp, err := msp.LoadLocalMspDir(*mspDir)
		if err != nil {
			return nil, err
		}
		identities[i], err = localMsp.GetDefaultSigningIdentity()
		if err != nil {
			return nil, errors.Wrap(err, "loading signing identity")
		}
	}
	return identities, nil
}

// GetPeersMspDirs returns the peers' MSP directory path.
func GetPeersMspDirs(cryptoPath string) []*msp.DirLoadParameters {
	peerOrgPath := path.Join(cryptoPath, cryptogen.PeerOrganizationsDir)
	peerMspDirs := GetMspDirs(peerOrgPath)
	for _, mspItem := range peerMspDirs {
		clientName := "client@" + mspItem.MspName + ".com"
		mspItem.MspDir = path.Join(mspItem.MspDir, "users", clientName, "msp")
	}
	return peerMspDirs
}

// GetOrdererMspDirs returns the orderers' MSP directory path.
func GetOrdererMspDirs(cryptoPath string) []*msp.DirLoadParameters {
	ordererOrgPath := path.Join(cryptoPath, cryptogen.OrdererOrganizationsDir)
	ordererMspDirs := GetMspDirs(ordererOrgPath)
	for _, mspItem := range ordererMspDirs {
		nodeName := "consenter-" + mspItem.MspName[len("orderer-"):]
		mspItem.MspDir = path.Join(mspItem.MspDir, "orderers", nodeName, "msp")
	}
	return ordererMspDirs
}

// GetMspDirs returns the MSP dir parameter per organization in the path.
func GetMspDirs(targetPath string) []*msp.DirLoadParameters {
	dir, err := os.ReadDir(targetPath)
	if err != nil {
		return nil
	}
	mspDirs := make([]*msp.DirLoadParameters, 0, len(dir))
	for _, dirEntry := range dir {
		if !dirEntry.IsDir() {
			continue
		}
		orgName := dirEntry.Name()
		mspDirs = append(mspDirs, &msp.DirLoadParameters{
			MspName: orgName,
			MspDir:  path.Join(targetPath, orgName),
		})
	}
	return mspDirs
}

// ServerTLSConfigsPerOrg holds server TLS configurations for peer and orderer organizations.
type ServerTLSConfigsPerOrg struct {
	// Sidecar maps peer organization names to their sidecar server TLS configurations.
	Sidecar map[string]connection.TLSConfig
	// Orderer maps orderer organization names to their orderer server TLS configurations.
	// The key format is "orderer-org-{ID}-node-{index}" for each orderer node.
	Orderer map[string]connection.TLSConfig
}

// BuildSidecarServerTLSConfigsPerOrg builds server TLS configs for sidecar services across all peer organizations.
// It reads the crypto materials from the given root path and constructs TLS configurations
// for each peer organization's sidecar service.
//
// Directory structure expected:
//
//	{root}/peerOrganizations/peer-org-{N}/
//	  ├── peers/sidecar/tls/
//	  │   ├── server.crt
//	  │   ├── server.key
//	  │   └── ca.crt
//	  └── msp/tlscacerts/
//	      └── tlspeer-org-{N}-CA-cert.pem
//
// Returns a ServerTLSConfigsPerOrg with the Sidecar map populated.
// If the peerOrganizations directory doesn't exist, returns empty maps to avoid nil pointer issues.
func BuildSidecarServerTLSConfigsPerOrg(t *testing.T, root string) *ServerTLSConfigsPerOrg {
	t.Helper()

	peerRoot := filepath.Join(root, cryptogen.PeerOrganizationsDir)
	sidecarConfigs := make(map[string]connection.TLSConfig)

	orgEntries, err := os.ReadDir(peerRoot)
	// If the path doesn't exist, return empty maps to avoid nil pointer issues
	if err != nil {
		return &ServerTLSConfigsPerOrg{
			Sidecar: make(map[string]connection.TLSConfig),
			Orderer: make(map[string]connection.TLSConfig),
		}
	}

	// Go over all peer organizations
	for _, orgEntry := range orgEntries {
		if !orgEntry.IsDir() {
			continue
		}

		orgName := orgEntry.Name()
		orgDir := filepath.Join(peerRoot, orgName)

		// Get the sidecar peer directory
		sidecarDir := filepath.Join(orgDir, cryptogen.PeerNodesDir, "sidecar")
		require.DirExists(t, sidecarDir, "missing sidecar dir for org %s", orgName)

		// Define paths for sidecar server TLS
		sidecarTLSDir := filepath.Join(sidecarDir, cryptogen.TLSDir)
		require.DirExists(t, sidecarTLSDir, "missing sidecar TLS dir for org %s", orgName)

		// Extract organization ID from name (e.g., "peer-org-0" -> "0")
		orgID := strings.TrimPrefix(orgName, "peer-org-")

		sidecarConfigs[orgName] = connection.TLSConfig{
			Mode:     connection.MutualTLSMode,
			CertPath: filepath.Join(sidecarTLSDir, "server.crt"),
			KeyPath:  filepath.Join(sidecarTLSDir, "server.key"),
			CACertPaths: []string{
				filepath.Join(orgDir, cryptogen.MSPDir, cryptogen.TLSCaCertsDir,
					fmt.Sprintf("tls%s-CA-cert.pem", orgName)),
			},
		}

		// Verify the certificate files exist
		require.FileExists(t, sidecarConfigs[orgName].CertPath,
			"missing server.crt for sidecar in org %s", orgName)
		require.FileExists(t, sidecarConfigs[orgName].KeyPath,
			"missing server.key for sidecar in org %s", orgName)
		require.FileExists(t, sidecarConfigs[orgName].CACertPaths[0],
			"missing CA cert for org %s (expected: tls%s-CA-cert.pem)", orgName, orgName)

		t.Logf("Loaded sidecar server TLS config for %s (org ID: %s)", orgName, orgID)
	}

	return &ServerTLSConfigsPerOrg{
		Sidecar: sidecarConfigs,
		Orderer: make(map[string]connection.TLSConfig),
	}
}

// BuildOrdererServerTLSConfigsPerOrg builds server TLS configs for orderer services across all orderer organizations.
// It reads the crypto materials from the given root path and constructs TLS configurations
// for each orderer node in each orderer organization.
//
// Directory structure expected:
//
//	{root}/ordererOrganizations/orderer-org-{ID}/
//	  ├── orderers/orderer-{index}-org-{ID}/tls/
//	  │   ├── server.crt
//	  │   ├── server.key
//	  │   └── ca.crt
//	  └── msp/tlscacerts/
//	      └── tlsorderer-org-{ID}-CA-cert.pem
//
// Returns a ServerTLSConfigsPerOrg with the Orderer map populated.
// The map keys are in the format "orderer-org-{ID}-node-{index}".
// If the ordererOrganizations directory doesn't exist, returns empty maps to avoid nil pointer issues.
func BuildOrdererServerTLSConfigsPerOrg(t *testing.T, root string) *ServerTLSConfigsPerOrg {
	t.Helper()

	ordererRoot := filepath.Join(root, cryptogen.OrdererOrganizationsDir)
	ordererConfigs := make(map[string]connection.TLSConfig)

	orgEntries, err := os.ReadDir(ordererRoot)
	// If the path doesn't exist, return empty maps to avoid nil pointer issues
	if err != nil {
		return &ServerTLSConfigsPerOrg{
			Sidecar: make(map[string]connection.TLSConfig),
			Orderer: make(map[string]connection.TLSConfig),
		}
	}

	// Go over all orderer organizations
	for _, orgEntry := range orgEntries {
		if !orgEntry.IsDir() {
			continue
		}

		orgName := orgEntry.Name()
		orgDir := filepath.Join(ordererRoot, orgName)

		// Get the orderers directory
		orderersDir := filepath.Join(orgDir, cryptogen.OrdererNodesDir)
		require.DirExists(t, orderersDir, "missing orderers dir for org %s", orgName)

		// Read all orderer nodes in this organization
		ordererEntries, err := os.ReadDir(orderersDir)
		require.NoError(t, err, "failed to read orderers dir for org %s", orgName)

		// Extract organization ID from name (e.g., "orderer-org-0" -> "0")
		orgID := strings.TrimPrefix(orgName, "orderer-org-")

		// Process each orderer node
		for nodeIndex, ordererEntry := range ordererEntries {
			if !ordererEntry.IsDir() {
				continue
			}

			ordererNodeName := ordererEntry.Name()
			ordererNodeDir := filepath.Join(orderersDir, ordererNodeName)

			// Define paths for orderer server TLS
			ordererTLSDir := filepath.Join(ordererNodeDir, cryptogen.TLSDir)
			require.DirExists(t, ordererTLSDir, "missing TLS dir for orderer %s in org %s",
				ordererNodeName, orgName)

			// Create a unique key for this orderer node
			configKey := fmt.Sprintf("%s-node-%d", orgName, nodeIndex)

			ordererConfigs[configKey] = connection.TLSConfig{
				Mode:     connection.MutualTLSMode,
				CertPath: filepath.Join(ordererTLSDir, "server.crt"),
				KeyPath:  filepath.Join(ordererTLSDir, "server.key"),
				CACertPaths: []string{
					filepath.Join(orgDir, cryptogen.MSPDir, cryptogen.TLSCaCertsDir,
						fmt.Sprintf("tls%s-CA-cert.pem", orgName)),
				},
			}

			// Verify the certificate files exist
			require.FileExists(t, ordererConfigs[configKey].CertPath,
				"missing server.crt for orderer %s in org %s", ordererNodeName, orgName)
			require.FileExists(t, ordererConfigs[configKey].KeyPath,
				"missing server.key for orderer %s in org %s", ordererNodeName, orgName)
			require.FileExists(t, ordererConfigs[configKey].CACertPaths[0],
				"missing CA cert for org %s (expected: tls%s-CA-cert.pem)", orgName, orgName)

			t.Logf("Loaded orderer server TLS config for %s (node: %s, org ID: %s)",
				configKey, ordererNodeName, orgID)
		}
	}

	return &ServerTLSConfigsPerOrg{
		Sidecar: make(map[string]connection.TLSConfig),
		Orderer: ordererConfigs,
	}
}

// BuildServerTLSConfigsPerOrg builds server TLS configs for both sidecar and orderer services.
// This is a convenience function that combines BuildSidecarServerTLSConfigsPerOrg and
// BuildOrdererServerTLSConfigsPerOrg into a single call.
//
// Returns a ServerTLSConfigsPerOrg with both Sidecar and Orderer maps populated.
func BuildServerTLSConfigsPerOrg(t *testing.T, root string) *ServerTLSConfigsPerOrg {
	t.Helper()

	sidecarConfigs := BuildSidecarServerTLSConfigsPerOrg(t, root)
	ordererConfigs := BuildOrdererServerTLSConfigsPerOrg(t, root)

	return &ServerTLSConfigsPerOrg{
		Sidecar: sidecarConfigs.Sidecar,
		Orderer: ordererConfigs.Orderer,
	}
}
