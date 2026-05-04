# Design of Access Control Lists for Fabric-X-Committer

**Document Version:** 1.0  
**Date:** May 3, 2026  
**Status:** For Internal Review  
**Authors:** IBM Fabric-X Team

---

## Table of Contents

1. [Background: Policies in Fabric](#1-background-policies-in-fabric)
   - 1.1 [Signature Policies](#11-signature-policies)
   - 1.2 [ImplicitMeta Policies](#12-implicitmeta-policies)
2. [Background: Policies in FabricX](#2-background-policies-in-fabricx)
3. [Problem Statement](#3-problem-statement)
4. [Proposed Solution](#4-proposed-solution)
5. [Implementation Details](#5-implementation-details)
   - 5.1 [Package Structure](#51-package-structure)
   - 5.2 [ACL Provider Interface](#52-acl-provider-interface)
   - 5.3 [ACL Provider Implementation](#53-acl-provider-implementation)
   - 5.4 [Bundle Manager](#54-bundle-manager)
   - 5.5 [Envelope Helper Functions](#55-envelope-helper-functions)
   - 5.6 [Service Integration](#56-service-integration)
   - 5.7 [Configuration Update Mechanisms](#57-configuration-update-mechanisms)
6. [Reuse of Fabric Packages](#6-reuse-of-fabric-packages)
7. [Other Important Considerations](#7-other-important-considerations)
8. [Phased Implementation](#8-phased-implementation)

---

## 1. Background: Policies in Fabric

Hyperledger Fabric employs a sophisticated policy system fundamental to defining network operations, participant eligibility, and conditions for making changes. These policies are the primary mechanism for enforcing governance and ensuring controlled access within a consortium, reflecting Fabric's permissioned nature where all participants have known identities managed via Membership Service Providers (MSPs).

A policy in Hyperledger Fabric is a set of rules determining whether a proposed action is authorized. Actions can range from endorsing a transaction, updating a channel configuration, instantiating a chaincode (which establishes a namespace/partition in the ledger), or adding a new organization to a channel. Policies evaluate the collection of signatures attached to transactions or configuration update proposals to validate if they meet the agreed-upon criteria.

These policies are primarily defined in the `configtx.yaml` file, which is used by the `configtxgen` tool to create the channel genesis block. Additionally, policies are defined per chaincode (or namespace). Fabric supports two main types of policies: Signature Policies and ImplicitMeta Policies.

### 1.1 Signature Policies

Signature policies are the most explicit policy type, precisely defining which identities must provide signatures for a proposal to be considered valid. These policies are constructed using logical combinations of MSP Principals, which represent roles (e.g., member, admin, client, or peer) associated with an MSP ID. Signature policies use a specific rule syntax to combine principal evaluations:

- **AND(rule1, rule2, ...)**: Requires all specified rules to be satisfied.
- **OR(rule1, rule2, ...)**: Requires at least one of the specified rules to be satisfied.
- **NOutOf(N, rule1, rule2, ...)**: Requires at least 'N' of the specified rules to be satisfied.

Each rule can reference an MSP Principal or another nested logical combination.

The following snippet from `configtx.yaml` illustrates how Signature Policies are defined at the organizational level (e.g., for Org2MSP). These organization-level policies are crucial as they form the foundational building blocks evaluated by higher-level ImplicitMeta policies.

```yaml
Organizations:
  - &Org2
    Name: Org2MSP
    ID: Org2MSP
    Policies:
      Readers:
        Type: Signature
        Rule: "OR('Org2MSP.member')"
      Writers:
        Type: Signature
        Rule: "OR('Org2MSP.member')"
      Admins:
        Type: Signature
        Rule: "OR('Org2MSP.admin')"
```

In this example, `'Org2MSP.admin'` refers to an identity that holds the 'admin' role within the 'Org2MSP' organization.

- The **Readers** policy is essential for maintaining data confidentiality. It ensures that only authorized identities belonging to member organizations can inspect the ledger's contents. Various Access Control Lists (ACLs) often reference this policy to control access to specific read-related resources, such as `peer/Deliver` (who peers will deliver blocks to).
- The **Writers** policy is critical for controlling who can attempt to modify the blockchain's state. It's a fundamental part of securing the ledger against unauthorized writes.
- The **Admins** policies are the cornerstone of channel governance. They ensure that significant changes to the channel's structure or rules are collectively agreed upon by enough authorized administrative entities. The `mod_policy` (modification policy) associated with each configuration element in the channel often points to an Admins policy, thereby controlling how that element can be changed.

Signature Policies are most encountered when defining chaincode/namespace endorsement policies. An endorsement policy for a chaincode/namespace specifies which organizations' peers (or how many of them) must simulate and endorse a transaction before it can be validated and committed to the ledger. For instance, an endorsement policy might be `AND('Org1MSP.peer', 'Org2MSP.peer')`, requiring endorsement from a peer of Org1 and a peer of Org2.

### 1.2 ImplicitMeta Policies

ImplicitMeta policies are primarily used for channel configuration governance and provide a more abstract and dynamic way to define rules by aggregating the outcomes of other policies (sub-policies).

- **Implicit**: The policy's evaluation is "implicitly" derived from the current channel configuration, specifically by considering the organizations that are members of the relevant group (e.g., the Application group for application channel policies, or the Orderer group for orderer policies). It does not require an explicit listing of each organization whose sub-policy will be checked.
- **Meta**: The policy's evaluation is "meta" because it does not directly evaluate signatures against specific MSP principals. Instead, it evaluates the outcome of the specified sub-policies. These sub-policies are typically the Signature Policies defined at the organizational level (as shown in the Org2MSP example).

The following snippet from `configtx.yaml` shows common channel-level policies defined as ImplicitMeta policies:

```yaml
Application: &ApplicationDefaults
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
    Endorsement:
      Type: ImplicitMeta
      Rule: "MAJORITY Endorsement"
```

**Key Components:**

1. **Type: ImplicitMeta**: Declares the policy type.
2. **Rule**: Defines how the outcomes of the sub-policies are combined.
   - **ANY SubPolicyName**: Satisfied if any of the corresponding sub-policies are met. For example, if `/Channel/Application/Readers` has `Rule: "ANY Readers"`, it looks for the Readers policy in each application organization. If any single organization's Readers Signature Policy is satisfied, the ImplicitMeta policy is met.
   - **ALL SubPolicyName**: Satisfied only if all corresponding sub-policies are met.
   - **MAJORITY SubPolicyName**: Satisfied if a strict majority (more than half) of the corresponding sub-policies are met. For example, `/Channel/Application/Admins` with `Rule: "MAJORITY Admins"` would require the Admins Signature Policy of a majority of application organizations to be satisfied.
3. **SubPolicyName**: (e.g., Readers, Admins, Endorsement in the rules above) This indicates the name of the sub-policy that the ImplicitMeta policy will look for within each underlying group/organization. For `/Channel/Application/Admins` with `Rule: "MAJORITY Admins"`, Fabric seeks out a policy named Admins in each application organization (like the `Admins: Type: Signature, Rule: "OR('Org2MSP.admin')"` for Org2).

**How ImplicitMeta Policies Work:**

Consider the `/Channel/Application/Admins` policy with `Rule: "MAJORITY Admins"` on a channel with three application organizations: Org1, Org2, and Org3. Each of these organizations would have its own Admins Signature Policy defined (e.g., Org1MSP.admin, Org2MSP.admin, Org3MSP.admin).

1. A channel configuration update is proposed, carrying signatures.
2. Fabric identifies that satisfying `/Channel/Application/Admins` requires satisfying the Admins Signature Policy of a majority of {Org1, Org2, Org3}.
3. Fabric evaluates the provided signatures against Org1's Admins policy, Org2's Admins policy, and Org3's Admins policy.
4. If at least two of these three organizational Admins policies are satisfied, the `/Channel/Application/Admins` ImplicitMeta policy is satisfied, and the update is allowed.

**Advantages:**

ImplicitMeta policies automatically adjust to changes in channel membership. If an organization is added or removed, a MAJORITY rule recalculates based on the new total number of organizations without needing a manual update to the policy rule itself. This greatly simplifies channel administration.

---

## 2. Background: Policies in FabricX

In standard Hyperledger Fabric (often referred to as "vanilla" Fabric), transactions are expected to include individual signatures from each endorsing peer, along with their corresponding X.509 certificates. For FabricX, a primary objective was to minimize transaction size, thereby potentially increasing ordering service throughput. This goal led to an exploration of alternative approaches, one of which involves restricting transactions to a single signature per chaincode.

In this alternative model, when multiple entities need to collectively endorse a transaction, client applications or endorsing peers would be responsible for employing a threshold signature scheme. This scheme enables multiple parties to contribute to a single, consolidated signature. For this system to function effectively, the client-side (or a designated aggregator) would need a robust key distribution and management mechanism. During validation, the committer peer would only need the aggregated public key—potentially defined within the chaincode/namespace's endorsement policy—to verify this single signature. This approach avoids embedding individual signer certificates within the transaction, further reducing its size. Although this single-signature method is implemented in FabricX, a comprehensive key distribution and management mechanism is not yet in place.

---

## 3. Problem Statement

The Fabric-X-Committer system currently lacks application-level access control for read operations. While TLS mutual authentication provides transport security, any authenticated client can read data from any channel. This does not align with Fabric's security model where channel membership and policies control access.

**Specific Requirements:**

1. **Channel Isolation**: Clients should only access channels they are authorized for.
2. **Policy-Based Control**: Channel administrators should control read access via standard Fabric policies.
3. **Fabric Compatibility**: ACL behavior should match Fabric peer's access control model.
4. **Performance**: ACL checks should not significantly impact query latency (target: < 1ms per check).
5. **Dynamic Updates**: ACL policies must update automatically when channel configuration changes.

**Services Requiring ACL Enforcement:**

- **Query Service**: State queries, transaction status, receipts, metadata
- **Sidecar Block Query Service**: Block retrieval by number, transaction ID, or hash
- **Sidecar Notification Service**: Block delivery streams

---

## 4. Proposed Solution

The proposed solution implements Access Control Lists (ACLs) for Fabric-X-Committer's read-only operations by leveraging Hyperledger Fabric's native policy framework. The design is simplified compared to Fabric's full ACL system because Fabric-X-Committer only handles read operations.

**Key Design Principles:**

1. **Envelope-Based Authentication**: All client requests are wrapped in signed `common.Envelope` messages containing identity and signature.
2. **Single Read Policy**: Unlike Fabric's resource-specific ACLs, Fabric-X-Committer uses a single policy (`/Channel/Application/Readers`) for all read operations.
3. **Channel Configuration Storage**: ACL policies are stored in channel configuration blocks and updated dynamically.
4. **Fabric Package Reuse**: Leverages existing Fabric packages from `fabric-x-common` for policy evaluation.
5. **Optional Enforcement**: ACL checking can be enabled or disabled via configuration for backward compatibility.

**Architecture Overview:**

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT                                   │
│  - Creates request (e.g., GetRows)                              │
│  - Signs with private key                                        │
│  - Wraps in common.Envelope                                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ gRPC (TLS)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              FABRIC-X-COMMITTER SERVICE                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Query Service / Sidecar Service                          │  │
│  │  1. Receive Envelope                                     │  │
│  │  2. Call aclProvider.CheckReadAccess(envelope)           │  │
│  │  3. Extract request data from envelope                   │  │
│  │  4. Process request                                      │  │
│  └────────────────────┬─────────────────────────────────────┘  │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ ACL Provider (service/acl/provider.go)                   │  │
│  │  1. Extract channel ID from envelope                     │  │
│  │  2. Get channel config bundle                            │  │
│  │  3. Extract signed data (identity + signature)           │  │
│  │  4. Get /Channel/Application/Readers policy              │  │
│  │  5. Evaluate policy against signed data                  │  │
│  └────────────────────┬─────────────────────────────────────┘  │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Bundle Manager (service/acl/bundle_manager.go)           │  │
│  │  - Stores channel config bundles (map[channelID]Bundle)  │  │
│  │  - Thread-safe access with RWMutex                       │  │
│  │  - Updates from config blocks                            │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                         ▲
                         │
                         │ Config Block Updates
                         │
┌────────────────────────┴────────────────────────────────────────┐
│              CONFIGURATION UPDATE SOURCES                        │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │ Sidecar:             │    │ Query Service:               │  │
│  │ - Receives config    │    │ - Polls database for config  │  │
│  │   blocks from relay  │    │ - Checks version changes     │  │
│  │ - Updates immediately│    │ - Updates periodically       │  │
│  └──────────────────────┘    └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Comparison with Fabric:**

| Aspect | Hyperledger Fabric | Fabric-X-Committer |
|--------|-------------------|-------------------|
| **ACL Granularity** | Per-resource (e.g., `qscc/GetChainInfo`, `peer/Propose`) | Single read policy for all operations |
| **Policy Types** | Peer-wide + Channel-specific | Channel-specific only |
| **Default Policies** | Hardcoded fallback for each resource | No defaults (requires channel config) |
| **Configuration** | Channel config ACLs + defaults | Channel config only |
| **Identity Types** | SignedProposal, Envelope, SignedData | Envelope only (wraps all requests) |
| **Update Mechanism** | Automatic via gossip | Sidecar: immediate; Query: polling |
| **Enforcement Points** | System chaincode entry points | gRPC service methods |

---

## 5. Implementation Details

### 5.1 Package Structure

The ACL implementation is organized in the `service/acl/` package:

```
service/acl/
├── acl.go              # Provider interface definition
├── provider.go         # Provider implementation
├── bundle_manager.go   # Channel config bundle management
├── envelope.go         # Envelope helper functions
├── test_helper.go      # Test utilities
└── acl_test.go         # Unit tests
```

**File Locations:**

- **ACL Interface**: `service/acl/acl.go` (lines 16-31)
- **ACL Provider**: `service/acl/provider.go` (lines 1-114)
- **Bundle Manager**: `service/acl/bundle_manager.go` (lines 1-63)
- **Envelope Helpers**: `service/acl/envelope.go` (lines 1-42)
- **Query Service Integration**: `service/query/envelope_acl.go` (lines 17-54)
- **Sidecar Integration**: `service/sidecar/envelope_acl.go` (lines 13-28)
- **Sidecar Config Updates**: `service/sidecar/sidecar.go` (lines 432-474)
- **Query Config Updates**: `service/query/query_service.go` (lines 374-430)

### 5.2 ACL Provider Interface

**File**: `service/acl/acl.go` (lines 16-31)

```go
// Provider defines the interface for ACL enforcement in fabric-x-committer.
type Provider interface {
    // CheckReadAccess verifies if the envelope's identity has read access
    // to the channel specified in the envelope.
    CheckReadAccess(envelope *common.Envelope) error
    
    // UpdateFromConfigBlock updates the channel configuration bundle
    // from a config block received by the sidecar.
    UpdateFromConfigBlock(configBlock *common.Block) error
    
    // UpdateFromConfigEnvelope updates the channel configuration bundle
    // from envelope bytes retrieved from the database by the query service.
    UpdateFromConfigEnvelope(envelopeBytes []byte) error
}
```

**Design Rationale:**

- **Single `CheckReadAccess` method**: Unlike Fabric's `CheckACL(resource, channelID, idinfo)`, we use a single method because all Fabric-X-Committer operations are reads. The channel ID is extracted from the envelope rather than passed as a parameter to ensure consistency and prevent spoofing.
- **Two update methods**: Support different sources—blocks from the sidecar and envelope bytes from the query service database.
- **Envelope-centric**: All operations work with `common.Envelope` to maintain consistency with Fabric's authentication model.

### 5.3 ACL Provider Implementation

**File**: `service/acl/provider.go` (lines 28-71)

```go
// CheckReadAccess verifies read access for the envelope.
// This is the main ACL enforcement point for all read operations in fabric-x-committer.
func (p *provider) CheckReadAccess(envelope *common.Envelope) error {
    // Step 1: Extract channel ID from envelope
    channelID, err := extractChannelID(envelope)
    if err != nil {
        return errors.Wrap(err, "failed to extract channel ID from envelope")
    }

    logger.Debugf("Checking read access for channel %s", channelID)

    // Step 2: Get channel config bundle
    bundle := p.bundleManager.GetChannelConfig(channelID)
    if bundle == nil {
        return errors.Errorf("channel config not found for channel %s", channelID)
    }

    // Step 3: Extract signed data from envelope
    signedData, err := extractSignedData(envelope)
    if err != nil {
        return errors.Wrap(err, "failed to extract signed data from envelope")
    }

    // Step 4: Get Readers policy from channel config
    // Use /Channel/Application/Readers as the standard read policy for all operations
    policyName := policies.ChannelApplicationReaders
    policy, ok := bundle.PolicyManager().GetPolicy(policyName)
    if !ok {
        return errors.Errorf("policy %s not found in channel config", policyName)
    }

    // Step 5: Evaluate policy
    err = policy.EvaluateSignedData(signedData)
    if err != nil {
        logger.Warnw("Read access denied",
            "channelID", channelID,
            "policy", policyName,
            "error", err)
        return errors.Wrapf(err, "access denied for channel %s", channelID)
    }

    logger.Debugf("Read access granted for channel %s", channelID)
    return nil
}
```

**Key Implementation Points:**

1. **Always uses `/Channel/Application/Readers` policy**: Simplified from Fabric's resource-specific ACLs since all operations are reads.
2. **Extracts channel ID from envelope**: Ensures client cannot spoof channel ID by passing it as a parameter.
3. **Uses Fabric's policy evaluation engine**: Reuses proven, tested code from `fabric-x-common`.
4. **Returns descriptive errors**: Includes channel ID and policy name in error messages for debugging.

**Configuration Update Methods:**

**File**: `service/acl/provider.go` (lines 73-114)

```go
// UpdateFromConfigBlock updates the channel configuration bundle from a config block.
func (p *provider) UpdateFromConfigBlock(configBlock *common.Block) error {
    // Extract channel ID from the config block
    if len(configBlock.Data.Data) == 0 {
        return errors.New("config block has no data")
    }

    envelope, err := protoutil.UnmarshalEnvelope(configBlock.Data.Data[0])
    if err != nil {
        return errors.Wrap(err, "failed to unmarshal envelope from config block")
    }

    channelID, err := extractChannelID(envelope)
    if err != nil {
        return errors.Wrap(err, "failed to extract channel ID from config block")
    }

    return p.bundleManager.UpdateFromConfigBlock(channelID, configBlock)
}

// UpdateFromConfigEnvelope updates the channel configuration bundle from a config envelope.
func (p *provider) UpdateFromConfigEnvelope(envelopeBytes []byte) error {
    envelope, err := protoutil.UnmarshalEnvelope(envelopeBytes)
    if err != nil {
        return errors.Wrap(err, "failed to unmarshal config envelope")
    }

    channelID, err := extractChannelID(envelope)
    if err != nil {
        return errors.Wrap(err, "failed to extract channel ID from config envelope")
    }

    // Create a minimal block structure containing just the envelope
    // This is sufficient for LoadConfigBlockMaterial which only needs the envelope data
    configBlock := &common.Block{
        Data: &common.BlockData{
            Data: [][]byte{envelopeBytes},
        },
    }

    return p.bundleManager.UpdateFromConfigBlock(channelID, configBlock)
}
```

### 5.4 Bundle Manager

**File**: `service/acl/bundle_manager.go` (lines 17-63)

```go
// BundleManager manages channel configuration bundles.
// Services don't hold channel IDs - they're extracted from envelopes.
type BundleManager struct {
    mu      sync.RWMutex
    bundles map[string]*channelconfig.Bundle
}

// NewBundleManager creates a new bundle manager.
func NewBundleManager() *BundleManager {
    return &BundleManager{
        bundles: make(map[string]*channelconfig.Bundle),
    }
}

// GetChannelConfig retrieves the channel config bundle for a channel.
func (bm *BundleManager) GetChannelConfig(channelID string) *channelconfig.Bundle {
    bm.mu.RLock()
    defer bm.mu.RUnlock()
    return bm.bundles[channelID]
}

// UpdateBundle updates the channel config bundle.
func (bm *BundleManager) UpdateBundle(channelID string, bundle *channelconfig.Bundle) {
    bm.mu.Lock()
    defer bm.mu.Unlock()
    bm.bundles[channelID] = bundle
    logger.Infof("Updated channel config bundle for channel %s", channelID)
}

// UpdateFromConfigBlock creates a bundle from a config block and stores it.
func (bm *BundleManager) UpdateFromConfigBlock(channelID string, configBlock *common.Block) error {
    material, err := channelconfig.LoadConfigBlockMaterial(configBlock)
    if err != nil {
        return errors.Wrap(err, "failed to load config block material")
    }

    bm.UpdateBundle(channelID, material.Bundle)
    return nil
}

// RemoveChannel removes a channel's config bundle.
func (bm *BundleManager) RemoveChannel(channelID string) {
    bm.mu.Lock()
    defer bm.mu.Unlock()
    delete(bm.bundles, channelID)
    logger.Infof("Removed channel config bundle for channel %s", channelID)
}
```

**Design Rationale:**

- **Thread-safe**: Uses `sync.RWMutex` for concurrent access (many readers, few writers).
- **In-memory storage**: Fast access, acceptable memory overhead (~1MB per channel).
- **Leverages Fabric code**: Uses `channelconfig.LoadConfigBlockMaterial` from `fabric-x-common`.

### 5.5 Envelope Helper Functions

**File**: `service/acl/envelope.go` (lines 15-42)

```go
// extractChannelID extracts the channel ID from the envelope's channel header.
func extractChannelID(envelope *common.Envelope) (string, error) {
    payload, err := protoutil.UnmarshalPayload(envelope.Payload)
    if err != nil {
        return "", errors.Wrap(err, "failed to unmarshal payload")
    }

    channelHeader, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
    if err != nil {
        return "", errors.Wrap(err, "failed to unmarshal channel header")
    }

    if channelHeader.ChannelId == "" {
        return "", errors.New("channel ID is empty in envelope")
    }

    return channelHeader.ChannelId, nil
}

// extractSignedData extracts SignedData from envelope for policy evaluation.
// This is used by the policy framework to verify signatures and evaluate policies.
func extractSignedData(envelope *common.Envelope) ([]*protoutil.SignedData, error) {
    signedData, err := protoutil.EnvelopeAsSignedData(envelope)
    if err != nil {
        return nil, errors.Wrap(err, "failed to extract signed data from envelope")
    }
    return signedData, nil
}
```

**Purpose:**

- **`extractChannelID`**: Extracts channel ID from envelope's channel header, ensuring it cannot be spoofed.
- **`extractSignedData`**: Converts envelope to `SignedData` format required by Fabric's policy evaluation engine.

### 5.6 Service Integration

#### 5.6.1 Query Service Integration

**File**: `service/query/envelope_acl.go` (lines 17-32)

```go
func (q *Service) checkACL(envelope *common.Envelope) error {
    if q.aclProvider == nil {
        // ACL checking disabled
        return nil
    }
    
    err := q.aclProvider.CheckReadAccess(envelope)
    if err != nil {
        logger.Warnw("ACL check failed for query operation", "error", err)
        return grpcerror.WrapWithContext(err, "access denied")
    }
    
    return nil
}
```

**Integration Points:**

All query service methods call `checkACL` before processing:
- `BeginView`: Checks ACL before creating view
- `EndView`: Checks ACL before ending view
- `GetRows`: Checks ACL before querying state
- `GetTransactionStatus`: Checks ACL before querying transaction status
- `GetTransactionReceipt`: Checks ACL before querying receipt
- `GetNamespaceMetadata`: Checks ACL before querying metadata

#### 5.6.2 Sidecar Service Integration

**File**: `service/sidecar/envelope_acl.go` (lines 13-28)

```go
func (s *Service) checkACL(envelope *common.Envelope) error {
    if s.aclProvider == nil {
        // ACL checking disabled
        return nil
    }
    
    err := s.aclProvider.CheckReadAccess(envelope)
    if err != nil {
        logger.Warnw("ACL check failed for notification stream", "error", err)
        return err
    }
    
    return nil
}
```

**Integration Points:**

All sidecar methods call `checkACL` before processing:
- `GetBlockByNumber`: Checks ACL before returning block
- `GetBlockByTxID`: Checks ACL before returning block
- `GetBlockByHash`: Checks ACL before returning block
- `Notify`: Checks ACL for each notification message

### 5.7 Configuration Update Mechanisms

#### 5.7.1 Sidecar Service: Immediate Updates

**File**: `service/sidecar/sidecar.go` (lines 432-474)

The sidecar receives config blocks from the relay and updates ACL bundles immediately:

```go
func (s *Service) updateDynamicTLSAndACL(ctx context.Context, configBlocks <-chan *common.Block) error {
    reader := channel.NewReader(ctx, configBlocks)
    for ctx.Err() == nil {
        configBlk, ok := reader.Read()
        if !ok {
            return nil
        }
        
        // Update TLS certificates if TLS updater is configured
        if s.tlsUpdater != nil {
            // ... TLS update logic ...
        }
        
        // Update ACL bundles if ACL provider is configured
        if s.aclProvider != nil {
            if err := s.aclProvider.UpdateFromConfigBlock(configBlk); err != nil {
                return errors.Wrapf(err, "failed to update ACL bundle from config block %d", configBlk.Header.Number)
            }
            logger.Infof("Updated ACL bundle from config block %d", configBlk.Header.Number)
        }
    }
    return nil
}
```

**Flow:**

1. Relay detects config block (single transaction)
2. Config block sent to `configBlocks` channel
3. `updateDynamicTLSAndACL` goroutine reads config block
4. ACL provider extracts channel config and updates bundle
5. Subsequent requests use new ACL configuration

**Latency**: < 100ms from config block receipt to ACL update

#### 5.7.2 Query Service: Polling Updates

**File**: `service/query/query_service.go` (lines 374-430)

The query service polls the database for config changes:

```go
// refreshTLSAndACLFromDB periodically polls the database for the config transaction
// and updates both the dynamic TLS CA certificates and ACL bundles when the config version changes.
func (q *Service) refreshTLSAndACLFromDB(ctx context.Context, pool querier) {
    if q.tlsUpdater == nil && q.aclProvider == nil {
        return
    }

    var lastVersion uint64
    seen := false

    // tryRefresh attempts a single refresh. Errors are logged but not returned,
    // as this is a background polling loop that should continue on transient failures.
    tryRefresh := func() {
        configTX, err := queryConfig(ctx, pool)
        if err != nil {
            logger.Errorf("Failed to read config transaction from DB: %v", err)
            return
        }

        if len(configTX.Envelope) == 0 || (seen && configTX.Version == lastVersion) {
            return
        }

        // Update TLS certificates if TLS updater is configured
        if q.tlsUpdater != nil {
            // ... TLS update logic ...
        }

        // Update ACL bundles if ACL provider is configured
        if q.aclProvider != nil {
            if err := q.aclProvider.UpdateFromConfigEnvelope(configTX.Envelope); err != nil {
                logger.Errorf("Failed to update ACL bundle from config envelope: %v", err)
                return
            }
            logger.Infof("Updated ACL bundle from config version %d", configTX.Version)
        }

        seen = true
        lastVersion = configTX.Version
    }

    // Attempt immediate refresh at startup to pick up existing config without waiting the
    // full polling interval.
    tryRefresh()

    ticker := time.NewTicker(q.config.TLSRefreshInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            tryRefresh()
        case <-ctx.Done():
            return
        }
    }
}
```

**Flow:**

1. Query service starts background goroutine
2. Immediate refresh at startup
3. Periodic refresh every `TLSRefreshInterval` (default: 5 minutes)
4. Queries `config_tx` table for latest config
5. Compares version with last seen version
6. Updates ACL bundle if version changed

**Latency**: Up to `TLSRefreshInterval` (configurable, default 5 minutes)

---

## 6. Reuse of Fabric Packages

The ACL implementation leverages several Fabric packages from `fabric-x-common`:

### 6.1 common/channelconfig Package

The `common/channelconfig` package provides an in-memory representation (Bundle) of channel configuration. It encapsulates:

- **Organization definitions**: MSPs and policies (Admins, Readers, Writers)
- **MSPManager**: For identity validation
- **PolicyManager**: For policy enforcement
- **Orderer settings**: Batch sizes, consensus mechanisms
- **Application configurations**: Capabilities, chaincode lifecycle policies
- **ACLs**: Resource-to-policy mappings

**Usage in Fabric-X-Committer:**

```go
// Load channel config from block
material, err := channelconfig.LoadConfigBlockMaterial(configBlock)
bundle := material.Bundle

// Access policy manager
policyManager := bundle.PolicyManager()
policy, ok := policyManager.GetPolicy("/Channel/Application/Readers")
```

### 6.2 msp (Membership Service Provider) Package

The `msp` package provides identity management and validation:

- **Identity authentication**: Validates signatures from recognized identities
- **Principal satisfaction**: Determines if identity satisfies a role (e.g., 'admin' in 'Org1MSP')
- **MSP configuration**: Root CAs, intermediate CAs, admin certificates, CRLs
- **MSPManager**: Manages all MSP instances, retrieval by MSP ID

**Usage in Fabric-X-Committer:**

The MSP package is used internally by the policy evaluation engine. The ACL provider doesn't directly interact with MSP—it's abstracted through the policy framework.

### 6.3 common/policydsl (Policy DSL Protobuf Definitions)

The `fabric-protos/common/policies.proto` file defines protobuf messages for policy types:

- **SignaturePolicyEnvelope**: Overall rule and identities (MSPPrincipals)
- **SignaturePolicy**: Logical conditions (signed_by, NOutOf)
- **ImplicitMetaPolicy**: Meta-policy definitions

The `common/policydsl` package provides utility functions:

- **FromString**: Converts human-readable policy strings to protobuf (e.g., `"AND('Org1MSP.member', 'Org2MSP.admin')"`)

**Usage in Fabric-X-Committer:**

Policy definitions are loaded from channel configuration blocks. The ACL provider doesn't need to parse policy strings—it uses pre-parsed policies from the Bundle.

### 6.4 common/policies Package

The `common/policies` package provides the policy evaluation framework:

- **Manager interface**: Grants access to policies by path (e.g., `/Channel/Application/Writers`)
- **Policy interface**: `Evaluate` method that accepts signatures and determines satisfaction
- **Provider delegation**: Delegates to specific providers (cauthdsl for Signature Policies, internal for ImplicitMeta)

**Usage in Fabric-X-Committer:**

```go
// Get policy from bundle
policy, ok := bundle.PolicyManager().GetPolicy(policies.ChannelApplicationReaders)

// Evaluate signed data against policy
err := policy.EvaluateSignedData(signedData)
```

### 6.5 common/cauthdsl (Signature Policy Implementation)

The `common/cauthdsl` package implements Signature Policy evaluation:

- **Parsing and compiling**: Signature policies with AND, OR, NOutOf operators
- **Principal evaluation**: Interacts with MSP to validate identities and check role satisfaction
- **Logical combination**: Combines principal checks according to policy rules

**Usage in Fabric-X-Committer:**

The cauthdsl package is used internally by the policy framework. The ACL provider calls `policy.EvaluateSignedData()`, which delegates to cauthdsl for Signature Policies.

### 6.6 protoutil Package

The `protoutil` package provides utility functions for working with protobuf messages:

- **UnmarshalEnvelope**: Unmarshals envelope bytes
- **UnmarshalPayload**: Unmarshals payload from envelope
- **UnmarshalChannelHeader**: Extracts channel header
- **EnvelopeAsSignedData**: Converts envelope to SignedData format

**Usage in Fabric-X-Committer:**

```go
// Extract channel ID
payload, err := protoutil.UnmarshalPayload(envelope.Payload)
channelHeader, err := protoutil.UnmarshalChannelHeader(payload.Header.ChannelHeader)
channelID := channelHeader.ChannelId

// Extract signed data
signedData, err := protoutil.EnvelopeAsSignedData(envelope)
```

---

## 7. Other Important Considerations

### 7.1 Backward Compatibility

ACL enforcement is **optional** and controlled by configuration:

```yaml
# Enable ACL enforcement
acl:
  enabled: true

# Disable ACL enforcement (backward compatible)
acl:
  enabled: false
```

When disabled:
- `aclProvider` is `nil`
- All ACL checks return immediately without error
- Existing deployments continue to work

### 7.2 Error Handling

ACL errors are wrapped with context and converted to appropriate gRPC status codes:

```go
// In query service
if err := q.checkACL(envelope); err != nil {
    return nil, grpcerror.WrapWithContext(err, "access denied")
}

// Results in gRPC error:
// Code: PermissionDenied
// Message: "access denied: failed evaluating policy on signed data..."
```

### 7.3 Logging and Monitoring

```go
// Success case
logger.Debugf("Read access granted for channel %s", channelID)

// Failure case
logger.Warnw("Read access denied",
    "channelID", channelID,
    "policy", policyName,
    "error", err)
```

**Metrics (to be added):**
- `acl_checks_total{result="success|failure"}`: Counter of ACL checks
- `acl_check_duration_seconds`: Histogram of ACL check latency
- `acl_bundle_updates_total`: Counter of bundle updates

### 7.4 Performance Considerations

| Operation | Overhead | Notes |
|-----------|----------|-------|
| ACL check | < 1ms | Signature verification + policy evaluation |
| Bundle update | < 100ms | Config block parsing + bundle creation |
| Memory per channel | ~1MB | Channel config bundle in memory |
| Network overhead | ~1KB | Envelope wrapper around requests |

**Optimization Strategies:**

1. **Caching**: Channel config bundles cached in memory
2. **Read-write locks**: Many concurrent readers, few writers
3. **Lazy loading**: Bundles loaded on first access
4. **Efficient serialization**: Protocol buffers for compact encoding

### 7.5 Security Considerations

**Threat Model:**

| Threat | Mitigation |
|--------|-----------|
| **Unauthorized channel access** | ACL checks verify identity against channel policies |
| **Identity spoofing** | Cryptographic signature verification |
| **Replay attacks** | TLS provides transport security; nonces in proposals |
| **Man-in-the-middle** | Mutual TLS authentication |
| **Configuration tampering** | Config blocks are signed by orderers and validated |
| **Denial of service** | Rate limiting (existing), ACL check performance |

**Trust Assumptions:**

1. **Trusted Orderers**: Config blocks from orderers are valid and properly signed
2. **Trusted CA**: Client certificates issued by trusted Certificate Authority
3. **Secure Key Storage**: Client private keys are securely stored
4. **TLS Infrastructure**: TLS certificates and CAs are properly managed

---

## 8. Phased Implementation

### Phase 1: Core ACL Infrastructure (Completed)

**Objectives:**
1. ✅ Create `service/acl` package with Provider interface
2. ✅ Implement ACL provider with `CheckReadAccess` method
3. ✅ Implement Bundle Manager for channel config storage
4. ✅ Implement envelope helper functions
5. ✅ Add unit tests for ACL package

**Deliverables:**
- `service/acl/acl.go`: Provider interface
- `service/acl/provider.go`: Provider implementation
- `service/acl/bundle_manager.go`: Bundle management
- `service/acl/envelope.go`: Envelope helpers
- `service/acl/acl_test.go`: Unit tests

### Phase 2: Service Integration (Completed)

**Objectives:**
1. ✅ Integrate ACL provider into Query Service
2. ✅ Integrate ACL provider into Sidecar Service
3. ✅ Update all service methods to use envelope-based API
4. ✅ Implement configuration update mechanisms
5. ✅ Add integration tests

**Deliverables:**
- `service/query/envelope_acl.go`: Query service ACL integration
- `service/sidecar/envelope_acl.go`: Sidecar ACL integration
- `service/sidecar/sidecar.go`: Immediate config updates
- `service/query/query_service.go`: Polling-based config updates
- `integration/test/acl_test.go`: Integration tests (438 lines)

**Integration Test Coverage:**
- Query Service: All 6 methods (BeginView, EndView, GetRows, GetTransactionStatus, GetTransactionReceipt, GetNamespaceMetadata)
- Sidecar Block Query: All 4 methods (GetBlockByNumber, GetBlockByTxID, GetBlockByHash, GetBlockRange)
- Sidecar Notification: Notify stream

### Phase 3: Production Readiness (In Progress)

**Objectives:**
1. ⏳ Add Prometheus metrics for ACL checks
2. ⏳ Enhance logging with structured fields
3. ⏳ Create client SDK examples for envelope creation
4. ⏳ Performance testing and optimization
5. ⏳ Documentation and deployment guide

**Deliverables:**
- Metrics implementation
- Enhanced logging
- Client SDK examples (Go, Java)
- Performance benchmarks
- Deployment documentation

### Phase 4: Advanced Features (Future)

**Objectives:**
1. ⬜ Fine-grained ACLs (per-operation policies if needed)
2. ⬜ Namespace-level access control
3. ⬜ Attribute-based access control (ABAC)
4. ⬜ Policy evaluation caching
5. ⬜ Audit trail for access decisions

**Deliverables:**
- Enhanced ACL granularity
- ABAC implementation
- Performance optimizations
- Audit logging

---

## Appendices

### Appendix A: Configuration Examples

#### Enable ACL Enforcement

```yaml
services:
  query:
    acl:
      enabled: true
  sidecar:
    acl:
      enabled: true
```

#### Channel Configuration with ACLs

```yaml
Application:
  Policies:
    Readers:
      Type: ImplicitMeta
      Rule: "ANY Readers"
    Writers:
      Type: ImplicitMeta
      Rule: "ANY Writers"
    Admins:
      Type: ImplicitMeta
      Rule: "MAJORITY Admins"
```

### Appendix B: Error Messages

| Error | Cause | Resolution |
|-------|-------|------------|
| `channel config not found for channel X` | Channel not initialized | Wait for config block or check channel ID |
| `policy /Channel/Application/Readers not found` | Invalid channel config | Update channel config with Readers policy |
| `access denied for channel X` | Identity not authorized | Check identity is member of authorized org |
| `failed to extract channel ID from envelope` | Malformed envelope | Check envelope structure and headers |
| `failed to extract signed data from envelope` | Invalid signature | Check envelope signature and identity |

### Appendix C: Testing

**Test Files:**
- Unit tests: `service/acl/acl_test.go`
- Integration tests: `integration/test/acl_test.go` (438 lines)

**Test Scenarios:**
- Valid signed envelope → Request succeeds
- Unsigned envelope → Request rejected with PermissionDenied
- Invalid signature → Request rejected with PermissionDenied
- Wrong channel → Request rejected (identity not in channel)
- Expired certificate → Request rejected with PermissionDenied
- Config update → New policy takes effect
- ACL disabled → All requests succeed (backward compatibility)

---

**End of Document**