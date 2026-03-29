# Server TLS Configuration Usage Examples

This document provides examples of how to use the new server TLS configuration functions in your tests.

## Overview

The `testcrypto` package now provides functions to extract server TLS configurations from crypto materials:

- `BuildSidecarServerTLSConfigsPerOrg()` - Extracts sidecar server certificates for all peer organizations
- `BuildOrdererServerTLSConfigsPerOrg()` - Extracts orderer server certificates for all orderer organizations  
- `BuildServerTLSConfigsPerOrg()` - Convenience function that extracts both sidecar and orderer configs

## Directory Structure

The functions expect the following crypto materials structure:

```
{cryptoMaterialsPath}/
├── peerOrganizations/
│   └── peer-org-{N}/
│       ├── peers/
│       │   └── sidecar/
│       │       └── tls/
│       │           ├── server.crt
│       │           ├── server.key
│       │           └── ca.crt
│       └── msp/
│           └── tlscacerts/
│               └── tlspeer-org-{N}-CA-cert.pem
└── ordererOrganizations/
    └── orderer-org-{ID}/
        ├── orderers/
        │   └── orderer-{index}-org-{ID}/
        │       └── tls/
        │           ├── server.crt
        │           ├── server.key
        │           └── ca.crt
        └── msp/
            └── tlscacerts/
                └── tlsorderer-org-{ID}-CA-cert.pem
```

## Example 1: Using Sidecar Server Certificates in Tests

```go
func TestSidecarWithCryptoMaterials(t *testing.T) {
    // Create crypto materials
    cryptoMaterialsPath := t.TempDir()
    configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
        cryptoMaterialsPath,
        &testcrypto.ConfigBlock{
            OrdererEndpoints:      ordererEndpoints,
            ChannelID:             "mychannel",
            PeerOrganizationCount: 1,
        },
    )
    require.NoError(t, err)

    // Load sidecar server TLS configurations
    serverConfigs := testcrypto.BuildSidecarServerTLSConfigsPerOrg(t, cryptoMaterialsPath)
    
    // Get the sidecar server config for peer-org-0
    sidecarServerTLS := serverConfigs.Sidecar["peer-org-0"]
    
    // Use in sidecar configuration
    sidecarConf := &Config{
        Server: connection.ServerConfig{
            Endpoint: connection.Endpoint{
                Host: "localhost",
                Port: 7051,
            },
            TLSConfig: sidecarServerTLS,
        },
        // ... rest of config
    }
    
    sidecar, err := New(sidecarConf)
    require.NoError(t, err)
    defer sidecar.Close()
}
```

## Example 2: Using Orderer Server Certificates in Tests

```go
func TestOrdererWithCryptoMaterials(t *testing.T) {
    // Create crypto materials
    cryptoMaterialsPath := t.TempDir()
    configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
        cryptoMaterialsPath,
        &testcrypto.ConfigBlock{
            OrdererEndpoints: []*types.OrdererEndpoint{
                {Host: "localhost", Port: 7050, ID: 0},
            },
            ChannelID:             "mychannel",
            PeerOrganizationCount: 1,
        },
    )
    require.NoError(t, err)

    // Load orderer server TLS configurations
    serverConfigs := testcrypto.BuildOrdererServerTLSConfigsPerOrg(t, cryptoMaterialsPath)
    
    // Get the orderer server config for the first node in orderer-org-0
    ordererServerTLS := serverConfigs.Orderer["orderer-org-0-node-0"]
    
    // Use in orderer configuration
    ordererConf := &OrdererConfig{
        Server: connection.ServerConfig{
            Endpoint: connection.Endpoint{
                Host: "localhost",
                Port: 7050,
            },
            TLSConfig: ordererServerTLS,
        },
        // ... rest of config
    }
}
```

## Example 3: Loading Both Sidecar and Orderer Configs

```go
func TestFullSystemWithCryptoMaterials(t *testing.T) {
    // Create crypto materials
    cryptoMaterialsPath := t.TempDir()
    configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
        cryptoMaterialsPath,
        &testcrypto.ConfigBlock{
            OrdererEndpoints: []*types.OrdererEndpoint{
                {Host: "localhost", Port: 7050, ID: 0},
            },
            ChannelID:             "mychannel",
            PeerOrganizationCount: 2, // Multiple peer organizations
        },
    )
    require.NoError(t, err)

    // Load all server TLS configurations at once
    serverConfigs := testcrypto.BuildServerTLSConfigsPerOrg(t, cryptoMaterialsPath)
    
    // Access sidecar configs for different organizations
    sidecarOrg0 := serverConfigs.Sidecar["peer-org-0"]
    sidecarOrg1 := serverConfigs.Sidecar["peer-org-1"]
    
    // Access orderer configs
    ordererNode0 := serverConfigs.Orderer["orderer-org-0-node-0"]
    
    // Use these configs in your test setup
    // ...
}
```

## Example 4: Iterating Over All Organizations

```go
func TestMultipleOrganizations(t *testing.T) {
    cryptoMaterialsPath := t.TempDir()
    configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
        cryptoMaterialsPath,
        &testcrypto.ConfigBlock{
            OrdererEndpoints:      ordererEndpoints,
            ChannelID:             "mychannel",
            PeerOrganizationCount: 3,
        },
    )
    require.NoError(t, err)

    serverConfigs := testcrypto.BuildSidecarServerTLSConfigsPerOrg(t, cryptoMaterialsPath)
    
    // Iterate over all peer organizations
    for orgName, tlsConfig := range serverConfigs.Sidecar {
        t.Logf("Organization: %s", orgName)
        t.Logf("  Cert Path: %s", tlsConfig.CertPath)
        t.Logf("  Key Path: %s", tlsConfig.KeyPath)
        t.Logf("  CA Certs: %v", tlsConfig.CACertPaths)
        
        // Start a sidecar for this organization
        // ...
    }
}
```

## Example 5: Updating Existing Sidecar Test

Here's how to update the existing `newSidecarTestEnvWithTLS` function in `service/sidecar/sidecar_test.go`:

```go
func newSidecarTestEnvWithTLS(
    t *testing.T,
    conf sidecarTestConfig,
) *sidecarTestEnv {
    t.Helper()
    
    // ... existing coordinator and orderer setup ...
    
    ordererEndpoints := ordererEnv.AllEndpoints()
    cryptoMaterialsPath := t.TempDir()
    configBlock, err := testcrypto.CreateOrExtendConfigBlockWithCrypto(
        cryptoMaterialsPath,
        &testcrypto.ConfigBlock{
            OrdererEndpoints:      ordererEndpoints,
            ChannelID:             ordererEnv.TestConfig.ChanID,
            PeerOrganizationCount: 1,
        },
    )
    require.NoError(t, err)

    // NEW: Load server certificates from crypto materials
    serverConfigs := testcrypto.BuildSidecarServerTLSConfigsPerOrg(t, cryptoMaterialsPath)
    sidecarServerTLS := serverConfigs.Sidecar["peer-org-0"]
    
    // Use the loaded server TLS config instead of conf.ServerTLS
    sidecarConf := &Config{
        Server: test.NewLocalHostServer(sidecarServerTLS), // Use crypto materials
        Committer: test.NewTLSClientConfig(conf.ClientTLS, &coordinatorServer.Configs[0].Endpoint),
        // ... rest of config
    }
    
    // ... rest of function ...
}
```

## Benefits

1. **Realistic Testing**: Uses actual crypto materials generated by cryptogen, matching production setup
2. **Consistency**: Server certificates match the organizational structure in the config block
3. **Flexibility**: Supports multiple peer and orderer organizations
4. **Error Detection**: Validates that all required certificate files exist
5. **Maintainability**: Centralized certificate loading logic

## Notes

- The functions use `require` assertions, so they will fail the test if certificates are missing
- Empty maps are returned if the crypto directories don't exist (to avoid nil pointer issues)
- All TLS configs are set to `MutualTLSMode` by default
- The functions log which configurations were loaded for debugging purposes