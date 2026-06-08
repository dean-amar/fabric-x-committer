<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

# MSP Authentication with Stateless Session Binding

## Overview

This document describes the MSP (Membership Service Provider) authentication system implemented in fabric-x-committer. The system provides a lightweight, memory-safe approach to enforcing Access Control Lists (ACLs) on gRPC APIs without requiring every message to be wrapped in a signed envelope.

## Architecture

### Key Concept: Stateless Session Binding

Instead of maintaining a global session registry (which risks memory leaks), we bind the authenticated MSP identity directly to the TLS connection's memory graph. When a client disconnects, the Go runtime automatically garbage collects the session state.

### Components

1. **CommitterAuthInfo** (`utils/auth/msp_credentials.go`)
   - Implements `credentials.AuthInfo`
   - Embeds standard TLS info
   - Provides thread-safe storage for MSP identity
   - Lives in the connection's memory, automatically cleaned up on disconnect

2. **CommitterCreds** (`utils/auth/msp_transport_credentials.go`)
   - Wraps standard TLS credentials
   - Injects `CommitterAuthInfo` during server handshake
   - Ensures every connection has identity binding capability

3. **MSP Interceptor** (`utils/auth/msp_interceptor.go`)
   - Unary gRPC interceptor
   - Handles authentication RPC (binds identity)
   - Enforces ACL policies on data RPCs (checks bound identity)

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Client establishes mTLS connection                       │
│    - TLS handshake with client certificate                  │
│    - CommitterAuthInfo injected (identity slot empty)       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Client calls Authorize RPC with signed envelope          │
│    - Envelope contains MSP identity + signature             │
│    - Server validates signature and identity                │
│    - MSP identity bound to connection via SetIdentity()     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Client calls data RPCs (e.g., GetTransactionStatus)     │
│    - Interceptor retrieves bound identity via GetIdentity() │
│    - Evaluates identity against channel ACL policy          │
│    - Allows or denies based on policy result                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Client disconnects                                       │
│    - Connection closed                                       │
│    - CommitterAuthInfo automatically garbage collected      │
│    - No manual cleanup required                             │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Guide

### Step 1: Server Setup

The server must use `CommitterCreds` and be started with proper TLS:

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    
    "github.com/hyperledger/fabric-x-committer/utils/auth"
    "github.com/hyperledger/fabric-x-committer/utils/connection"
)

func setupServer(tlsConfig *tls.Config) (*grpc.Server, error) {
    // 1. Create standard TLS credentials
    standardTLSCreds := credentials.NewTLS(tlsConfig)
    
    // 2. Wrap with CommitterCreds to inject MSP auth capability
    committerCreds := auth.NewCommitterCreds(standardTLSCreds)
    
    // 3. Create MSP interceptor
    interceptor := auth.NewMSPUnaryServerInterceptor(&auth.MSPInterceptorConfig{
        AuthMethod:     "/auth.AuthService/Authorize",
        Bundle:         channelBundle,      // Your channel config bundle
        AuthHandler:    authHandler,        // Your auth handler
        ResourceMapper: resourceMapper,     // Your resource mapper
    })
    
    // 4. Create gRPC server with credentials and interceptor
    opts := []grpc.ServerOption{
        grpc.Creds(committerCreds),
        grpc.UnaryInterceptor(interceptor),
    }
    
    return grpc.NewServer(opts...), nil
}
```

**Critical Security Requirement**: The server MUST be started with `ServeTLS` (not `Serve`) to ensure the transport is encrypted:

```go
// CORRECT - Enforces encrypted transport
listener, _ := net.Listen("tcp", address)
server.ServeTLS(listener, "", "") // Certs already in TLS config

// WRONG - Does not enforce encryption, vulnerable to hijacking
server.Serve(listener)
```

### Step 2: Implement AuthHandler

The `AuthHandler` validates authentication requests and extracts the MSP identity:

```go
type MyAuthHandler struct {
    mspManager msp.MSPManager
}

func (h *MyAuthHandler) Authenticate(
    ctx context.Context,
    req interface{},
    sequence uint64,
) (msp.Identity, error) {
    // Cast request to your auth request type
    authReq, ok := req.(*pb.AuthorizeRequest)
    if !ok {
        return nil, errors.New("invalid request type")
    }
    
    // Extract and validate the signed envelope
    envelope := authReq.SignedEnvelope
    
    // Unmarshal payload
    payload := &common.Payload{}
    if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
        return nil, errors.Wrap(err, "failed to unmarshal payload")
    }
    
    // Extract signature header
    signatureHeader := &common.SignatureHeader{}
    if err := proto.Unmarshal(payload.Header.SignatureHeader, signatureHeader); err != nil {
        return nil, errors.Wrap(err, "failed to unmarshal signature header")
    }
    
    // Deserialize MSP identity from creator
    identity, err := h.mspManager.DeserializeIdentity(signatureHeader.Creator)
    if err != nil {
        return nil, errors.Wrap(err, "failed to deserialize identity")
    }
    
    // Verify the signature
    if err := identity.Verify(envelope.Payload, envelope.Signature); err != nil {
        return nil, errors.Wrap(err, "signature verification failed")
    }
    
    // Validate identity
    if err := identity.Validate(); err != nil {
        return nil, errors.Wrap(err, "identity validation failed")
    }
    
    return identity, nil
}
```

### Step 3: Implement ResourceMapper

The `ResourceMapper` maps gRPC methods to policy resource paths:

```go
type MyResourceMapper struct{}

func (m *MyResourceMapper) MethodToResource(method string) string {
    // Map gRPC methods to channel policy resources
    switch method {
    case "/committerpb.QueryService/GetTransactionStatus":
        return "/Channel/Application/Readers"
    case "/committerpb.QueryService/QueryState":
        return "/Channel/Application/Readers"
    case "/committerpb.BlockQueryService/GetBlockByNumber":
        return "/Channel/Application/Readers"
    default:
        return "/Channel/Application/Readers" // Default policy
    }
}
```

### Step 4: Define Proto Service

Add the authentication RPC to your proto service:

```protobuf
syntax = "proto3";

import "common/common.proto";

service AuthService {
    rpc Authorize(AuthorizeRequest) returns (AuthorizeResponse);
}

message AuthorizeRequest {
    common.Envelope signed_envelope = 1;
}

message AuthorizeResponse {
    bool success = 1;
    string message = 2;
    string session_token = 3;  // Optional: for client tracking
}
```

### Step 5: Client Implementation

Clients authenticate once per connection:

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func connectAndAuthenticate(address string, tlsConfig *tls.Config) error {
    // 1. Establish mTLS connection
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
    if err != nil {
        return err
    }
    defer conn.Close()
    
    // 2. Create signed envelope with MSP identity
    envelope, err := createSignedEnvelope(mspIdentity, signer)
    if err != nil {
        return err
    }
    
    // 3. Authenticate
    authClient := pb.NewAuthServiceClient(conn)
    resp, err := authClient.Authorize(context.Background(), &pb.AuthorizeRequest{
        SignedEnvelope: envelope,
    })
    if err != nil {
        return err
    }
    
    if !resp.Success {
        return errors.New("authentication failed")
    }
    
    // 4. Use the same connection for subsequent RPCs
    // The MSP identity is now bound to this connection
    queryClient := committerpb.NewQueryServiceClient(conn)
    status, err := queryClient.GetTransactionStatus(context.Background(), &committerpb.TxStatusQuery{
        TxId: "tx123",
    })
    
    return err
}
```

## Security Considerations

### Critical Requirements

1. **Encrypted Transport**: The server MUST use `ServeTLS` to enforce encrypted connections
2. **mTLS**: Client certificates should be validated during TLS handshake
3. **Certificate Binding**: The MSP identity certificate should match the TLS client certificate
4. **Signature Verification**: All envelopes must be cryptographically verified

### Memory Safety

- **No Global State**: Identity is stored in the connection object, not in global maps
- **Automatic Cleanup**: When a connection closes, the Go runtime garbage collects the `CommitterAuthInfo`
- **No Memory Leaks**: No manual cleanup or eviction logic required

### Thread Safety

- `CommitterAuthInfo` uses `sync.RWMutex` for thread-safe access
- Multiple goroutines can safely read/write identity on the same connection
- The interceptor is called serially per RPC, preventing race conditions

## Testing

### Unit Tests

Test the core components in isolation:

```go
func TestCommitterAuthInfo(t *testing.T) {
    authInfo := &auth.CommitterAuthInfo{}
    
    // Initially not authenticated
    _, _, authenticated := authInfo.GetIdentity()
    assert.False(t, authenticated)
    
    // Bind identity
    authInfo.SetIdentity(mockIdentity, 42)
    
    // Verify retrieval
    identity, seq, authenticated := authInfo.GetIdentity()
    assert.True(t, authenticated)
    assert.Equal(t, uint64(42), seq)
}
```

### Integration Tests

Test the full authentication flow:

```go
func TestMSPAuthentication(t *testing.T) {
    // Setup server with MSP interceptor
    server := setupTestServer(t)
    defer server.Stop()
    
    // Create client with mTLS
    conn := createMTLSClient(t, server.Address())
    defer conn.Close()
    
    // Authenticate
    authClient := pb.NewAuthServiceClient(conn)
    envelope := createTestEnvelope(t, testIdentity)
    resp, err := authClient.Authorize(context.Background(), &pb.AuthorizeRequest{
        SignedEnvelope: envelope,
    })
    
    require.NoError(t, err)
    assert.True(t, resp.Success)
    
    // Call protected RPC
    queryClient := committerpb.NewQueryServiceClient(conn)
    status, err := queryClient.GetTransactionStatus(context.Background(), &committerpb.TxStatusQuery{
        TxId: "tx123",
    })
    
    require.NoError(t, err)
    assert.NotNil(t, status)
}
```

## Performance Characteristics

- **Overhead**: Minimal - identity lookup is a simple map read from connection context
- **Scalability**: Excellent - no global locks or shared state
- **Memory**: O(connections) - one `CommitterAuthInfo` per active connection
- **Latency**: Negligible - no network calls after initial authentication

## Comparison with Alternatives

### vs. Per-Message Envelopes

**Advantages**:
- Better developer experience (no envelope wrapping for every call)
- Lower bandwidth (no repeated signatures)
- Simpler client code

**Trade-offs**:
- Requires initial authentication RPC
- Identity bound to connection lifetime

### vs. Global Session Registry

**Advantages**:
- No memory leak risk
- Automatic cleanup on disconnect
- No eviction logic needed

**Trade-offs**:
- Requires connection-level state (but this is natural for gRPC)

## References

- [Fabric MSP Documentation](https://hyperledger-fabric.readthedocs.io/en/latest/msp.html)
- [gRPC Authentication Guide](https://grpc.io/docs/guides/auth/)
- [fabric-protos-go](https://github.com/hyperledger/fabric-protos-go-apiv2)

## Appendix: Complete Example

See `utils/auth/example_test.go` for a complete working example.