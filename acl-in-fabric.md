# Hyperledger Fabric ACL Implementation Guide

## Overview

This document explains how Hyperledger Fabric implements Access Control Lists (ACLs) for authorization, covering the complete flow from gRPC service definitions to policy evaluation, and provides design recommendations for the committer-x implementation.

---

## 1. gRPC Services and Message Types

Fabric uses two primary signed message types for different purposes:

### SignedProposal
- **Purpose**: Execute chaincode (read/write ledger)
- **Service**: `Endorser.ProcessProposal()`
- **Use case**: Invoke smart contracts, query ledger via system chaincodes

### SignedEnvelope
- **Purpose**: Submit transactions and retrieve blocks
- **Services**:
    - `Deliver.Deliver()` - Stream blocks from orderer/peer
    - `Broadcast.Broadcast()` - Submit endorsed transactions to orderer
- **Use case**: Get blocks, submit transactions for ordering

---

## 2. Complete gRPC Flow: Endorser Service (SignedProposal)

### 2.1 Proto Definition

```protobuf
// vendor/github.com/hyperledger/fabric-protos-go-apiv2/peer/peer.proto
service Endorser {
    rpc ProcessProposal(SignedProposal) returns (ProposalResponse) {}
}
```

### 2.2 gRPC Handler Implementation

**File**: [`core/endorser/endorser.go:304-367`](core/endorser/endorser.go:304)

```go
// ProcessProposal is the gRPC handler - receives SignedProposal from client
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal) (*pb.ProposalResponse, error) {
    // Step 1: Unpack and validate proposal
    up, err := UnpackProposal(signedProp)
    if err != nil {
        return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
    }

    // Step 2: Get channel context
    channel := e.ChannelFetcher.Channel(up.ChannelID())
    
    // Step 3: ⭐ PRE-PROCESS (includes ACL check) ⭐
    err = e.preProcess(up, channel)
    if err != nil {
        return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
    }

    // Step 4: Process the proposal (execute chaincode)
    pResp, err := e.ProcessProposalSuccessfullyOrError(up)
    return pResp, nil
}
```

**Key insight**: The SignedProposal contains:
- Chaincode name (e.g., "qscc", "myapp")
- Function name (e.g., "GetBlockByNumber")
- Arguments
- Identity (for ACL check)

### 2.3 ACL Check in preProcess

**File**: [`core/endorser/endorser.go:195-245`](core/endorser/endorser.go:195)

```go
func (e *Endorser) preProcess(up *UnpackedProposal, channel *Channel) error {
    // Validate the proposal message
    err := up.Validate(channel.IdentityDeserializer)
    if err != nil {
        return errors.WithMessage(err, "error validating proposal")
    }

    // ⭐ ACL CHECK HAPPENS HERE ⭐
    if up.ChannelID() != "" {
        err = e.Support.CheckACL(up.ChannelID(), up.SignedProposal)
        if err != nil {
            return err
        }
    }
    return nil
}
```

### 2.4 Support.CheckACL Implementation

**File**: [`core/endorser/support.go:115-125`](core/endorser/support.go:115)

```go
func (s *SupportImpl) CheckACL(channelID string, signedProp *pb.SignedProposal) error {
    // ⭐ CALLS THE ACL PROVIDER ⭐
    return s.ACLProvider.CheckACL(resources.Peer_Propose, channelID, signedProp)
}
```

### 2.5 ACL Provider: The Switch Case

**File**: [`core/aclmgmt/defaultaclprovider.go:139-156`](core/aclmgmt/defaultaclprovider.go:139)

```go
func (d *defaultACLProviderImpl) CheckACL(resName string, channelID string, idinfo any) error {
    // Map resource to policy
    policy := d.cResourcePolicyMap[resName]
    // For resources.Peer_Propose, policy = "/Channel/Application/Writers"
    
    // ⭐ SWITCH ON MESSAGE TYPE ⭐
    switch typedData := idinfo.(type) {
    case *pb.SignedProposal:
        // ⭐ THIS CASE IS USED FOR ENDORSER ⭐
        return d.policyChecker.CheckPolicy(channelID, policy, typedData)
    case *common.Envelope:
        // Used for deliver service
        sd, err := protoutil.EnvelopeAsSignedData(typedData)
        if err != nil {
            return err
        }
        return d.policyChecker.CheckPolicyBySignedData(channelID, policy, sd)
    default:
        return fmt.Errorf("unsupported type %T", typedData)
    }
}
```

**This switch case is the single point where Fabric handles different signed message types for ACL checking.**

---

## 3. Deliver/Broadcast Services (SignedEnvelope)

### 3.1 Proto Definition

```protobuf
// vendor/github.com/hyperledger/fabric-protos-go-apiv2/orderer/ab.proto
service AtomicBroadcast {
    rpc Deliver(stream Envelope) returns (stream DeliverResponse) {}
    rpc Broadcast(stream Envelope) returns (stream BroadcastResponse) {}
}
```

### 3.2 Deliver Service Implementation

**File**: [`orderer/common/server/server.go:186-218`](orderer/common/server/server.go:186)

```go
// Deliver sends a stream of blocks to a client
func (s *server) Deliver(srv ab.AtomicBroadcast_DeliverServer) error {
    logger.Debugf("Starting new Deliver handler")
    
    // ⭐ ACL CHECK with Envelope ⭐
    policyChecker := func(env *cb.Envelope, channelID string) error {
        chain := s.GetChain(channelID)
        // Check Readers policy
        sf := msgprocessor.NewSigFilter(
            policies.ChannelReaders,         // Normal mode
            policies.ChannelOrdererReaders,  // Maintenance mode
            chain
        )
        return sf.Apply(env)  // ⭐ Checks ACL on Envelope
    }
    
    deliverServer := &deliver.Server{
        PolicyChecker: deliver.PolicyCheckerFunc(policyChecker),
        Receiver:      &deliverMsgTracer{Receiver: srv},
        ResponseSender: &responseSender{srv},
    }
    return s.dh.Handle(srv.Context(), deliverServer)
}
```

### 3.3 Broadcast Service Implementation

**File**: [`orderer/common/server/server.go:168-183`](orderer/common/server/server.go:168)

```go
// Broadcast receives a stream of messages from a client for ordering
func (s *server) Broadcast(srv ab.AtomicBroadcast_BroadcastServer) error {
    logger.Debugf("Starting new Broadcast handler")
    return s.bh.Handle(&broadcastMsgTracer{
        AtomicBroadcast_BroadcastServer: srv,
    })
}
```

**File**: [`orderer/common/broadcast/broadcast.go:66-90`](orderer/common/broadcast/broadcast.go:66)

```go
func (bh *Handler) Handle(srv ab.AtomicBroadcast_BroadcastServer) error {
    for {
        msg, err := srv.Recv()  // ⭐ Receives Envelope
        if err != nil {
            return err
        }
        
        resp := bh.ProcessMessage(msg, addr)  // ⭐ Process Envelope (includes ACL)
        err = srv.Send(resp)
    }
}
```

### 3.4 SigFilter: ACL Check for Envelope

**File**: [`orderer/common/msgprocessor/sigfilter.go:50-79`](orderer/common/msgprocessor/sigfilter.go:50)

```go
func (sf *SigFilter) Apply(message *cb.Envelope) error {
    // ⭐ Step 1: Convert Envelope to SignedData ⭐
    signedData, err := protoutil.EnvelopeAsSignedData(message)
    if err != nil {
        return fmt.Errorf("could not convert message to signedData: %s", err)
    }
    
    // ⭐ Step 2: Determine which policy to use ⭐
    policyName := sf.normalPolicyName  // e.g., "ChannelReaders"
    if ordererConf.ConsensusState() == orderer.ConsensusType_STATE_MAINTENANCE {
        policyName = sf.maintenancePolicyName  // e.g., "ChannelOrdererReaders"
    }
    
    // ⭐ Step 3: Get policy from channel config ⭐
    policy, ok := sf.support.PolicyManager().GetPolicy(policyName)
    
    // ⭐ Step 4: Evaluate policy against identity in Envelope ⭐
    err = policy.EvaluateSignedData(signedData)
    if err != nil {
        return errors.Wrap(ErrPermissionDenied, err.Error())
    }
    return nil
}
```

---

## 4. ACL Rule Storage: Resource→Policy Mapping

### 4.1 Hardcoded Resource Mappings

**File**: [`core/aclmgmt/defaultaclprovider.go:42-100`](core/aclmgmt/defaultaclprovider.go:42)

```go
func newDefaultACLProvider(policyChecker policy.PolicyChecker) defaultACLProvider {
    d := &defaultACLProviderImpl{
        pResourcePolicyMap: map[string]string{},  // Peer-wide policies
        cResourcePolicyMap: map[string]string{},  // Channel policies
    }
    
    // ⭐ HARDCODED RESOURCE → POLICY MAPPINGS ⭐
    
    // QSCC (Query System Chaincode)
    d.cResourcePolicyMap[resources.Qscc_GetChainInfo]       = CHANNELREADERS
    d.cResourcePolicyMap[resources.Qscc_GetBlockByNumber]   = CHANNELREADERS
    d.cResourcePolicyMap[resources.Qscc_GetBlockByHash]     = CHANNELREADERS
    d.cResourcePolicyMap[resources.Qscc_GetTransactionByID] = CHANNELREADERS
    d.cResourcePolicyMap[resources.Qscc_GetBlockByTxID]     = CHANNELREADERS
    
    // Lifecycle
    d.pResourcePolicyMap[resources.Lifecycle_InstallChaincode] = policy.Admins
    d.cResourcePolicyMap[resources.Lifecycle_CommitChaincodeDefinition] = CHANNELWRITERS
    
    // Peer operations
    d.cResourcePolicyMap[resources.Peer_Propose] = CHANNELWRITERS
    
    return d
}
```

**Resource name constants**: [`core/aclmgmt/resources/resources.go:14-69`](core/aclmgmt/resources/resources.go:14)

```go
const (
    Qscc_GetBlockByNumber   = "qscc/GetBlockByNumber"
    Qscc_GetTransactionByID = "qscc/GetTransactionByID"
    Peer_Propose            = "peer/Propose"
    // ... etc
)
```

### 4.2 Policy Definitions in Channel Config

**File**: [`sampleconfig/configtx.yaml:231-239`](sampleconfig/configtx.yaml:231)

```yaml
# ⭐ ACTUAL POLICY DEFINITIONS (in channel config) ⭐
Policies:
    Readers:
        Type: ImplicitMeta
        Rule: "ANY Readers"  # Any org's Readers can read
    Writers:
        Type: ImplicitMeta
        Rule: "ANY Writers"  # Any org's Writers can write
    Admins:
        Type: ImplicitMeta
        Rule: "MAJORITY Admins"  # Majority of org Admins
```

---

## 5. Why Two Different ACL Mechanisms?

### ACLProvider (Peer-side)
- **Location**: `core/aclmgmt`
- **Scope**: Fine-grained, resource-based
- **Mapping**: `"qscc/GetBlockByNumber"` → `"/Channel/Application/Readers"`
- **Message types**: SignedProposal, Envelope, SignedData
- **Use case**: Chaincode invocations, system chaincode queries

### SigFilter (Orderer-side)
- **Location**: `orderer/common/msgprocessor`
- **Scope**: Simple, policy-based
- **Mapping**: Always checks one policy (Readers or Writers)
- **Message types**: Envelope only
- **Use case**: Block delivery, transaction submission

**Why different?**
- Historical reasons and separation of concerns
- Orderer code predates ACLProvider
- Both ultimately call the same policy evaluation engine: `policy.EvaluateSignedData()`

---

## 6. Design Recommendations for Committer-X

### 6.1 Use SignedEnvelope for Query Service

**Rationale**:
1. Your sidecar already streams `common.Envelope` from deliver service
2. Matches Fabric's pattern for block delivery services
3. Clients already know how to create SignedEnvelope
4. Uniform ACL checking across all query operations

### 6.2 Implementation Pattern

```go
// Your query service
func (s *QueryService) GetBlock(ctx context.Context, req *SignedEnvelope) (*Block, error) {
    // 1. Extract identity from SignedEnvelope
    signedData, err := protoutil.EnvelopeAsSignedData(req.Envelope)
    if err != nil {
        return nil, fmt.Errorf("invalid envelope: %w", err)
    }
    
    // 2. Get policy from channel config
    policy, ok := s.policyManager.GetPolicy("/Channel/Application/Readers")
    if !ok {
        return nil, fmt.Errorf("policy not found")
    }
    
    // 3. Check ACL (Readers policy)
    err = policy.EvaluateSignedData(signedData)
    if err != nil {
        return nil, fmt.Errorf("access denied: %w", err)
    }
    
    // 4. If authorized, return block from your stream
    return s.getBlockFromStream(req.BlockNumber), nil
}
```

### 6.3 Policy Choice

**Recommendation**: Use `"/Channel/Application/Readers"` policy for all query operations

**Reasoning**:
- Consistent with QSCC (Query System Chaincode) which uses Readers
- Consistent with Deliver service which uses Readers
- Allows any organization member with Reader role to query
- Matches the semantic meaning: queries are read operations

### 6.4 Architecture Benefits

1. **Fabric-native**: Uses same patterns as core Fabric services
2. **Reusable code**: Can use `protoutil.EnvelopeAsSignedData()` and existing policy evaluation
3. **Client-friendly**: Clients use familiar SignedEnvelope creation
4. **Extensible**: Easy to add more query types with same ACL mechanism
5. **Secure**: Leverages Fabric's battle-tested policy evaluation engine

### 6.5 Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ CLIENT                                                          │
│ Creates SignedEnvelope with identity and sends via gRPC        │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ gRPC: queryService.GetBlock(signedEnvelope)
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ COMMITTER-X: Query Service gRPC Handler                        │
│                                                                 │
│ 1. Receive SignedEnvelope                                       │
│ 2. Extract identity: protoutil.EnvelopeAsSignedData()          │
│ 3. Get policy: policyManager.GetPolicy("/Channel/.../Readers") │
│ 4. Check ACL: policy.EvaluateSignedData(signedData)           │
│ 5. If authorized, return block from stream                      │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ Success: Return block
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ CLIENT                                                          │
│ Receives block data                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Key Takeaways

1. **Two message types**: SignedProposal (chaincode execution) vs SignedEnvelope (block delivery/submission)
2. **Single gRPC endpoint**: `ProcessProposal` handles all chaincode invocations; proposal specifies which chaincode/function
3. **Two ACL mechanisms**: ACLProvider (peer, fine-grained) vs SigFilter (orderer, simple)
4. **Two-level ACL system**: Resource→Policy mapping (hardcoded) + Policy definitions (channel config)
5. **For committer-x**: Use SignedEnvelope + Readers policy for uniform, Fabric-native ACL checking

---

## References

- ACL Provider: [`core/aclmgmt/defaultaclprovider.go`](core/aclmgmt/defaultaclprovider.go)
- Endorser Service: [`core/endorser/endorser.go`](core/endorser/endorser.go)
- Deliver Service: [`orderer/common/server/server.go`](orderer/common/server/server.go)
- SigFilter: [`orderer/common/msgprocessor/sigfilter.go`](orderer/common/msgprocessor/sigfilter.go)
- Resource Names: [`core/aclmgmt/resources/resources.go`](core/aclmgmt/resources/resources.go)
- Policy Config: [`sampleconfig/configtx.yaml`](sampleconfig/configtx.yaml)