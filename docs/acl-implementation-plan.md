<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

# ACL Implementation Plan for Fabric-X Committer

## Executive Summary

This document provides a comprehensive plan for implementing production-grade Access Control Lists (ACLs) for the Query Service and Sidecar Service in fabric-x-committer. The implementation follows Hyperledger Fabric's proven ACL patterns while adhering to the project's simplicity-first coding guidelines.

**Key Design Decisions:**
- **Simple Role-Based Access Control**: Uses certificate OU (Organizational Unit) field for roles (admin, client, member)
- **Optional by Default**: ACL enforcement only activates when configuration is provided
- **Read-Only Operations**: Both Query and Sidecar services expose read-only APIs, simplifying policy requirements
- **No Complex Policies**: Avoids Fabric's AND/OR/k-of-n policy logic - uses straightforward role checks
- **Minimal Abstractions**: Follows project guidelines by avoiding unnecessary interfaces and generics

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Exposed APIs Analysis](#exposed-apis-analysis)
3. [ACL Components Design](#acl-components-design)
4. [Implementation Phases](#implementation-phases)
5. [File Structure](#file-structure)
6. [Configuration Schema](#configuration-schema)
7. [Testing Strategy](#testing-strategy)
8. [Security Considerations](#security-considerations)
9. [Metrics and Observability](#metrics-and-observability)
10. [Migration Guide](#migration-guide)

---

## Architecture Overview

### High-Level Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. CLIENT: Send gRPC Request with mTLS Certificate      │
│    - Certificate contains: CN, O (org), OU (role)       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. gRPC INTERCEPTOR: Extract Certificate from Context   │
│    - Runs before handler execution                       │
│    - Extracts peer certificate from TLS connection       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. ACL PROVIDER: Check if ACL is Enabled                │
│    - If no config → ALLOW (backward compatible)          │
│    - If config exists → proceed to validation            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 4. IDENTITY EXTRACTOR: Parse Certificate                │
│    - Extract Organization (O field)                      │
│    - Extract Role (OU field: admin/client/member)        │
│    - Validate certificate chain against trusted CAs      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5. POLICY EVALUATOR: Check Role Against Resource        │
│    - Map gRPC method → resource name                     │
│    - Get required role for resource                      │
│    - Compare client role with required role              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 6. RESULT: ALLOW or DENY                                │
│    - ALLOW → Continue to handler                         │
│    - DENY → Return PermissionDenied gRPC error           │
│    - Log decision with metrics                           │
└─────────────────────────────────────────────────────────┘
```

### Three-Layer Architecture

Following Fabric's proven design, but simplified:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Configuration Layer                           │
│  - ACL mappings (Resource → Required Role)              │
│  - MSP configuration (Org → Trusted CA certs)           │
│  - Optional: loaded from YAML or disabled               │
│  Location: utils/acl/config.go                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Layer 2: ACL Provider Layer                            │
│  - CheckACL(method, identity) → error                   │
│  - Coordinates identity extraction and policy check     │
│  - Handles "disabled" mode gracefully                   │
│  Location: utils/acl/provider.go                        │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│  Layer 3: Validation Layer                              │
│  - Certificate validation (chain, expiry, revocation)   │
│  - Role extraction from OU field                        │
│  - Simple role comparison (no complex logic)            │
│  Location: utils/acl/identity.go, policy.go             │
└─────────────────────────────────────────────────────────┘
```

---

## Exposed APIs Analysis

### Query Service APIs

From [`service/query/query_service.go`](../service/query/query_service.go):

| RPC Method | Purpose | Access Level | Rationale |
|------------|---------|--------------|-----------|
| `BeginView` | Start a consistent read view | **Reader** | Read operation, needs basic access |
| `EndView` | Close a read view | **Reader** | Cleanup operation, same as BeginView |
| `GetRows` | Query state data | **Reader** | Core read operation |
| `GetTransactionStatus` | Query tx status | **Reader** | Read operation, status is public info |
| `GetNamespacePolicies` | Get namespace policies | **Reader** | Metadata read, needed for clients |
| `GetConfigTransaction` | Get config transaction | **Reader** | Config is public within channel |

**Conclusion**: All Query Service operations are read-only and should require **Reader** role (least privilege).

### Sidecar Service APIs

From [`service/sidecar/sidecar.go`](../service/sidecar/sidecar.go) and registration:

| RPC Method | Service | Purpose | Access Level | Rationale |
|------------|---------|---------|--------------|-----------|
| `Deliver` | peer.DeliverServer | Stream committed blocks | **Reader** | Read-only block delivery |
| `DeliverFiltered` | peer.DeliverServer | Filtered block delivery (deprecated) | **Reader** | Read-only, deprecated |
| `DeliverWithPrivateData` | peer.DeliverServer | Private data delivery (deprecated) | **Reader** | Read-only, deprecated |
| `Subscribe` | NotifierServer | Subscribe to tx status updates | **Reader** | Read-only notification stream |
| `GetBlockByNumber` | BlockQueryService | Query specific block | **Reader** | Read-only block query |
| `GetBlockByTxID` | BlockQueryService | Query block by tx ID | **Reader** | Read-only block query |

**Conclusion**: All Sidecar operations are read-only and should require **Reader** role.

### Role Hierarchy

```
Admin (highest privilege)
  ↓ can do everything Reader can do
Reader (read-only access)
  ↓ can query data, subscribe to events
Member (default, no special privileges)
  ↓ rejected by default
```

**Note**: Since all exposed operations are read-only, we only need Reader role. Admin role is reserved for future administrative operations (if any).

---

## ACL Components Design

### Component 1: Identity Extractor

**File**: `utils/acl/identity.go`

**Purpose**: Extract and validate client identity from gRPC context.

**Key Functions**:
```go
// Identity represents a validated client identity
type Identity struct {
    Certificate *x509.Certificate
    Organization string  // From O field
    Role        string   // From OU field: "admin", "client", "member"
}

// ExtractIdentityFromContext extracts client certificate from gRPC TLS context
func ExtractIdentityFromContext(ctx context.Context) (*Identity, error)

// ValidateCertificate validates certificate chain against trusted CAs
func ValidateCertificate(cert *x509.Certificate, trustedRoots *x509.CertPool) error

// ExtractRole extracts role from certificate OU field
func ExtractRole(cert *x509.Certificate) string
```

**Design Principles**:
- No interfaces - concrete types only
- Clear error messages for debugging
- Follows project's error handling guidelines (cockroachdb/errors)

### Component 2: Policy Evaluator

**File**: `utils/acl/policy.go`

**Purpose**: Evaluate if an identity satisfies the required role for a resource.

**Key Functions**:
```go
// Policy defines access requirements for a resource
type Policy struct {
    Resource     string  // e.g., "query/GetRows"
    RequiredRole string  // "admin", "reader", "member"
}

// Evaluate checks if identity satisfies the policy
func (p *Policy) Evaluate(identity *Identity) error

// RoleHierarchy checks if actualRole satisfies requiredRole
func RoleHierarchy(actualRole, requiredRole string) bool
```

**Role Hierarchy Logic**:
```go
// Simple hierarchy: admin > reader > member
// admin can do everything
// reader can do read operations
// member has no special privileges
```

### Component 3: ACL Provider

**File**: `utils/acl/provider.go`

**Purpose**: Main ACL enforcement coordinator.

**Key Structure**:
```go
// Provider coordinates ACL checks
type Provider struct {
    enabled      bool
    policies     map[string]*Policy  // method -> policy
    trustedRoots map[string]*x509.CertPool  // org -> CA certs
}

// NewProvider creates a new ACL provider
// If config is nil, returns a disabled provider (backward compatible)
func NewProvider(config *Config) *Provider

// CheckACL performs the complete ACL check
func (p *Provider) CheckACL(ctx context.Context, method string) error

// IsEnabled returns whether ACL is active
func (p *Provider) IsEnabled() bool
```

**Key Design Points**:
- **Optional by default**: If no config provided, `enabled = false`, all checks pass
- **No callbacks**: Direct function calls only
- **Simple map lookup**: No complex policy resolution

### Component 4: gRPC Interceptor

**File**: `utils/acl/interceptor.go`

**Purpose**: Integrate ACL checks into gRPC request flow.

**Key Function**:
```go
// UnaryServerInterceptor creates a gRPC interceptor for ACL checks
func UnaryServerInterceptor(provider *Provider) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, 
                handler grpc.UnaryHandler) (interface{}, error) {
        // Skip if ACL is disabled
        if !provider.IsEnabled() {
            return handler(ctx, req)
        }
        
        // Perform ACL check
        if err := provider.CheckACL(ctx, info.FullMethod); err != nil {
            return nil, grpcerror.WrapPermissionDenied(err)
        }
        
        // Continue to handler
        return handler(ctx, req)
    }
}
```

**Integration Points**:
- Query Service: Add interceptor in server setup
- Sidecar Service: Add interceptor in server setup

### Component 5: Configuration Loader

**File**: `utils/acl/config.go`

**Purpose**: Load and validate ACL configuration from YAML.

**Configuration Structure**:
```go
type Config struct {
    Enabled bool                    `yaml:"enabled"`
    ACLs    map[string]string       `yaml:"acls"`  // method -> required role
    MSPs    map[string]MSPConfig    `yaml:"msps"`  // org -> CA certs
}

type MSPConfig struct {
    ID            string   `yaml:"id"`
    RootCerts     []string `yaml:"root_certs"`      // paths to CA cert files
    Organization  string   `yaml:"organization"`
}

// LoadConfig loads ACL configuration from file
func LoadConfig(path string) (*Config, error)

// Validate validates the configuration
func (c *Config) Validate() error
```

---

## Implementation Phases

### Phase 1: Core ACL Infrastructure (Week 1)

**Goal**: Build the foundation without breaking existing functionality.

**Tasks**:
1. Create `utils/acl/` package structure
2. Implement `Identity` extraction from certificates
3. Implement simple role-based `Policy` evaluator
4. Implement `Provider` with optional mode
5. Write unit tests for each component

**Deliverables**:
- `utils/acl/identity.go` with tests
- `utils/acl/policy.go` with tests
- `utils/acl/provider.go` with tests
- All tests passing with `make test`

**Success Criteria**:
- ✅ Can extract identity from certificate
- ✅ Can evaluate role-based policies
- ✅ Provider works in both enabled and disabled modes
- ✅ No existing tests broken

### Phase 2: Configuration and Integration (Week 1-2)

**Goal**: Add configuration support and integrate with services.

**Tasks**:
1. Implement configuration loader (`utils/acl/config.go`)
2. Create gRPC interceptor (`utils/acl/interceptor.go`)
3. Define default ACL mappings (`utils/acl/defaults.go`)
4. Integrate interceptor into Query Service
5. Integrate interceptor into Sidecar Service
6. Add configuration examples

**Deliverables**:
- `utils/acl/config.go` with YAML support
- `utils/acl/interceptor.go` with gRPC integration
- `utils/acl/defaults.go` with resource mappings
- Updated service initialization code
- Sample configuration files

**Success Criteria**:
- ✅ Can load ACL config from YAML
- ✅ Services start successfully with and without ACL config
- ✅ Interceptor correctly enforces ACLs when enabled
- ✅ Backward compatible (no config = no ACL)

### Phase 3: Testing Infrastructure (Week 2)

**Goal**: Comprehensive testing with real certificates.

**Tasks**:
1. Extend `CredentialsFactory` to support org and role
2. Create test certificates with different roles
3. Write integration tests for Query Service
4. Write integration tests for Sidecar Service
5. Add negative test cases (access denied scenarios)

**Deliverables**:
- Enhanced `utils/test/secure_connection.go`
- `utils/acl/provider_test.go` (integration tests)
- `service/query/acl_integration_test.go`
- `service/sidecar/acl_integration_test.go`

**Success Criteria**:
- ✅ Can generate test certificates with custom org/role
- ✅ Integration tests cover all RPC methods
- ✅ Tests verify both allow and deny scenarios
- ✅ All tests pass with `make test-integration`

### Phase 4: Observability and Documentation (Week 2-3)

**Goal**: Production-ready monitoring and documentation.

**Tasks**:
1. Add Prometheus metrics for ACL operations
2. Add structured logging for ACL decisions
3. Write comprehensive documentation
4. Create configuration examples
5. Write migration guide

**Deliverables**:
- `utils/acl/metrics.go` with Prometheus metrics
- Enhanced logging in ACL components
- `docs/acl-guide.md` (user documentation)
- `docs/acl-implementation-plan.md` (this document)
- Sample configurations in `cmd/config/samples/`

**Success Criteria**:
- ✅ Metrics track ACL checks, denials, and latency
- ✅ Logs provide clear audit trail
- ✅ Documentation is clear and complete
- ✅ Examples work out of the box

---

## File Structure

```
fabric-x-committer/
├── utils/
│   ├── acl/
│   │   ├── provider.go              # Main ACL provider
│   │   ├── provider_test.go         # Unit + integration tests
│   │   ├── identity.go              # Certificate identity extraction
│   │   ├── identity_test.go         # Identity tests
│   │   ├── policy.go                # Role-based policy evaluation
│   │   ├── policy_test.go           # Policy tests
│   │   ├── config.go                # Configuration loading
│   │   ├── config_test.go           # Config tests
│   │   ├── interceptor.go           # gRPC interceptor
│   │   ├── interceptor_test.go      # Interceptor tests
│   │   ├── defaults.go              # Default ACL mappings
│   │   ├── metrics.go               # Prometheus metrics
│   │   └── doc.go                   # Package documentation
│   │
│   └── test/
│       └── secure_connection.go     # Enhanced with org/role support
│
├── service/
│   ├── query/
│   │   ├── query_service.go         # Add ACL interceptor
│   │   └── acl_integration_test.go  # ACL integration tests
│   │
│   └── sidecar/
│       ├── sidecar.go               # Add ACL interceptor
│       └── acl_integration_test.go  # ACL integration tests
│
├── cmd/
│   └── config/
│       └── samples/
│           ├── acl-config.yaml      # Sample ACL configuration
│           └── acl-disabled.yaml    # Sample with ACL disabled
│
└── docs/
    ├── acl-guide.md                 # User guide
    ├── acl-implementation-plan.md   # This document
    └── acl-security.md              # Security considerations
```

---

## Configuration Schema

### ACL Configuration File

**File**: `cmd/config/samples/acl-config.yaml`

```yaml
# ACL Configuration for Fabric-X Committer
# If this section is omitted or enabled=false, ACL is disabled (backward compatible)

acl:
  enabled: true
  
  # Resource to required role mappings
  # Format: "service/method": "required_role"
  # Roles: admin, reader, member
  policies:
    # Query Service - all read operations require reader role
    "/committerpb.QueryService/BeginView": "reader"
    "/committerpb.QueryService/EndView": "reader"
    "/committerpb.QueryService/GetRows": "reader"
    "/committerpb.QueryService/GetTransactionStatus": "reader"
    "/committerpb.QueryService/GetNamespacePolicies": "reader"
    "/committerpb.QueryService/GetConfigTransaction": "reader"
    
    # Sidecar - Deliver Service
    "/peer.Deliver/Deliver": "reader"
    "/peer.Deliver/DeliverFiltered": "reader"
    "/peer.Deliver/DeliverWithPrivateData": "reader"
    
    # Sidecar - Notifier Service
    "/committerpb.Notifier/Subscribe": "reader"
    
    # Sidecar - Block Query Service
    "/committerpb.BlockQueryService/GetBlockByNumber": "reader"
    "/committerpb.BlockQueryService/GetBlockByTxID": "reader"
  
  # MSP (Membership Service Provider) configuration
  # Maps organizations to their trusted CA certificates
  msps:
    Org1MSP:
      id: "Org1MSP"
      organization: "org1.example.com"
      root_certs:
        - "/path/to/crypto-config/peerOrganizations/org1.example.com/msp/cacerts/ca.org1.example.com-cert.pem"
    
    Org2MSP:
      id: "Org2MSP"
      organization: "org2.example.com"
      root_certs:
        - "/path/to/crypto-config/peerOrganizations/org2.example.com/msp/cacerts/ca.org2.example.com-cert.pem"
```

### Disabled ACL Configuration

**File**: `cmd/config/samples/acl-disabled.yaml`

```yaml
# ACL disabled - all requests allowed (backward compatible)
acl:
  enabled: false
```

### Service Configuration Integration

**Query Service Config** (`cmd/config/samples/query-config.yaml`):

```yaml
# ... existing config ...

# Optional: ACL configuration
acl:
  enabled: true
  config_file: "./acl-config.yaml"  # Path to ACL config
```

**Sidecar Service Config** (`cmd/config/samples/sidecar-config.yaml`):

```yaml
# ... existing config ...

# Optional: ACL configuration
acl:
  enabled: true
  config_file: "./acl-config.yaml"  # Path to ACL config
```

---

## Testing Strategy

### Unit Tests

**Location**: `utils/acl/*_test.go`

**Coverage**:
1. **Identity Extraction**:
   - Extract org from certificate O field
   - Extract role from certificate OU field
   - Handle missing or invalid fields
   - Validate certificate chains

2. **Policy Evaluation**:
   - Role hierarchy (admin > reader > member)
   - Exact role matches
   - Role mismatches (deny scenarios)

3. **Provider Logic**:
   - Disabled mode (all checks pass)
   - Enabled mode with valid identity
   - Enabled mode with invalid identity
   - Missing policy for method

4. **Configuration Loading**:
   - Valid YAML parsing
   - Invalid YAML handling
   - Missing files
   - Certificate file loading

**Test Pattern** (following project guidelines):
```go
func TestProvider_CheckACL(t *testing.T) {
    t.Parallel()
    
    // Success cases
    for _, tc := range []struct {
        name     string
        identity *Identity
        method   string
    }{
        {
            name: "admin can access reader resource",
            identity: &Identity{Role: "admin"},
            method: "/committerpb.QueryService/GetRows",
        },
        {
            name: "reader can access reader resource",
            identity: &Identity{Role: "reader"},
            method: "/committerpb.QueryService/GetRows",
        },
    } {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            provider := setupTestProvider()
            err := provider.CheckACL(context.Background(), tc.method)
            require.NoError(t, err)
        })
    }
    
    // Failure cases
    for _, tc := range []struct {
        name     string
        identity *Identity
        method   string
    }{
        {
            name: "member cannot access reader resource",
            identity: &Identity{Role: "member"},
            method: "/committerpb.QueryService/GetRows",
        },
    } {
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            provider := setupTestProvider()
            err := provider.CheckACL(context.Background(), tc.method)
            require.Error(t, err)
        })
    }
}
```

### Integration Tests

**Location**: `service/query/acl_integration_test.go`, `service/sidecar/acl_integration_test.go`

**Test Scenarios**:

1. **Query Service Integration**:
   ```go
   func TestQueryService_ACL_Integration(t *testing.T) {
       t.Parallel()
       
       // Setup: Start query service with ACL enabled
       // Create test certificates with different roles
       
       for _, tc := range []struct {
           name       string
           clientRole string
           method     string
           shouldPass bool
       }{
           {
               name: "reader can query rows",
               clientRole: "reader",
               method: "GetRows",
               shouldPass: true,
           },
           {
               name: "member cannot query rows",
               clientRole: "member",
               method: "GetRows",
               shouldPass: false,
           },
       } {
           t.Run(tc.name, func(t *testing.T) {
               t.Parallel()
               // Create client with specific role
               // Attempt RPC call
               // Verify result matches shouldPass
           })
       }
   }
   ```

2. **Sidecar Service Integration**:
   - Test Deliver stream with different roles
   - Test Subscribe with different roles
   - Test block queries with different roles

3. **Backward Compatibility**:
   - Service starts without ACL config
   - All operations succeed when ACL disabled
   - No performance impact when disabled

### Enhanced CredentialsFactory

**Location**: `utils/test/secure_connection.go`

**Enhancement**:
```go
// CreateClientCredentialsWithRole creates a client certificate with specific org and role
func (scm *CredentialsFactory) CreateClientCredentialsWithRole(
    t *testing.T,
    tlsMode string,
    org string,
    role string,  // "admin", "client", "member"
) (connection.TLSConfig, string) {
    t.Helper()
    
    // Create certificate with custom OU field for role
    clientKeypair, err := scm.CertificateAuthority.NewClientCertKeyPairWithOU(org, role)
    require.NoError(t, err)
    
    return scm.createTLSConfig(t, tlsMode, clientKeypair)
}
```

**Note**: May need to extend `tlsgen` library to support custom OU field.

---

## Security Considerations

### 1. Certificate Validation

**Threats**:
- Expired certificates
- Revoked certificates
- Self-signed certificates
- Certificate chain manipulation

**Mitigations**:
- ✅ Validate certificate expiration before accepting
- ✅ Verify certificate chain against trusted CAs
- ✅ Check certificate key usage constraints
- ⚠️ CRL/OCSP checking (future enhancement)

**Implementation**:
```go
func ValidateCertificate(cert *x509.Certificate, trustedRoots *x509.CertPool) error {
    // Check expiration
    now := time.Now()
    if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
        return errors.New("certificate expired or not yet valid")
    }
    
    // Verify chain
    opts := x509.VerifyOptions{
        Roots:     trustedRoots,
        KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }
    
    if _, err := cert.Verify(opts); err != nil {
        return errors.Wrap(err, "certificate verification failed")
    }
    
    return nil
}
```

### 2. Role Extraction Security

**Threats**:
- Malicious OU field values
- Missing OU field
- Multiple OU fields

**Mitigations**:
- ✅ Whitelist valid role values
- ✅ Default to least privilege (member) if invalid
- ✅ Log suspicious role values

**Implementation**:
```go
func ExtractRole(cert *x509.Certificate) string {
    validRoles := map[string]bool{
        "admin":  true,
        "client": true,
        "member": true,
    }
    
    if len(cert.Subject.OrganizationalUnit) == 0 {
        return "member"  // Default to least privilege
    }
    
    role := cert.Subject.OrganizationalUnit[0]
    if !validRoles[role] {
        logger.Warnf("Invalid role in certificate: %s, defaulting to member", role)
        return "member"
    }
    
    return role
}
```

### 3. Audit Logging

**Requirements**:
- Log all ACL decisions (allow and deny)
- Include identity information (org, role)
- Include resource being accessed
- Include timestamp and result

**Implementation**:
```go
func (p *Provider) CheckACL(ctx context.Context, method string) error {
    identity, err := ExtractIdentityFromContext(ctx)
    if err != nil {
        logger.ErrorStackTrace(errors.Wrap(err, "failed to extract identity"))
        return err
    }
    
    policy, exists := p.policies[method]
    if !exists {
        logger.Warnf("No policy defined for method: %s", method)
        return errors.Newf("no policy for method: %s", method)
    }
    
    if err := policy.Evaluate(identity); err != nil {
        logger.Infof("ACL denied: org=%s role=%s method=%s reason=%v",
            identity.Organization, identity.Role, method, err)
        return err
    }
    
    logger.Debugf("ACL allowed: org=%s role=%s method=%s",
        identity.Organization, identity.Role, method)
    return nil
}
```

### 4. Performance Considerations

**Concerns**:
- Certificate validation overhead
- Policy lookup overhead
- Impact on request latency

**Optimizations**:
- ✅ Cache validated certificates (with TTL)
- ✅ Use map for O(1) policy lookup
- ✅ Skip ACL entirely when disabled
- ✅ Measure and monitor ACL latency

**Caching Strategy** (future enhancement):
```go
type Provider struct {
    // ... existing fields ...
    identityCache *lru.Cache  // Cache validated identities
    cacheTTL      time.Duration
}
```

### 5. Configuration Security

**Threats**:
- Unauthorized config file access
- Config file tampering
- Sensitive data in config

**Mitigations**:
- ✅ Validate file permissions (0600 or 0400)
- ✅ Validate config on load
- ✅ Use absolute paths for certificate files
- ✅ Log config changes

---

## Metrics and Observability

### Prometheus Metrics

**File**: `utils/acl/metrics.go`

**Metrics to Track**:

1. **ACL Check Counter**:
   ```go
   acl_checks_total{method, result}
   // Labels:
   // - method: gRPC method name
   // - result: "allowed" or "denied"
   ```

2. **ACL Check Latency**:
   ```go
   acl_check_duration_seconds{method}
   // Histogram of ACL check duration
   ```

3. **Certificate Validation Errors**:
   ```go
   acl_cert_validation_errors_total{reason}
   // Labels:
   // - reason: "expired", "invalid_chain", "invalid_role", etc.
   ```

4. **Policy Lookup Failures**:
   ```go
   acl_policy_lookup_failures_total{method}
   // Counter for missing policy definitions
   ```

**Implementation**:
```go
type Metrics struct {
    checksTotal          *prometheus.CounterVec
    checkDuration        *prometheus.HistogramVec
    certValidationErrors *prometheus.CounterVec
    policyLookupFailures *prometheus.CounterVec
}

func NewMetrics() *Metrics {
    return &Metrics{
        checksTotal: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "acl_checks_total",
                Help: "Total number of ACL checks performed",
            },
            []string{"method", "result"},
        ),
        // ... other metrics ...
    }
}
```

### Structured Logging

**Log Levels**:
- **DEBUG**: Successful ACL checks (verbose)
- **INFO**: ACL denials (important for audit)
- **WARN**: Configuration issues, invalid roles
- **ERROR**: Certificate validation failures, system errors

**Log Format**:
```go
logger.Infof("ACL check: method=%s org=%s role=%s result=%s",
    method, identity.Organization, identity.Role, result)
```

---

## Migration Guide

### For Existing Deployments

**Step 1: Upgrade Without ACL (Backward Compatible)**

1. Deploy new version with ACL code
2. Do NOT add ACL configuration
3. Verify services work as before
4. Monitor for any issues

**Step 2: Prepare ACL Configuration**

1. Create ACL configuration file
2. Set `enabled: false` initially
3. Configure MSP certificates
4. Validate configuration syntax

**Step 3: Enable ACL in Test Environment**

1. Set `enabled: true` in test environment
2. Test with different client certificates
3. Verify metrics and logs
4. Tune configuration as needed

**Step 4: Gradual Production Rollout**

1. Enable ACL on one service instance
2. Monitor metrics and logs
3. Verify no legitimate requests denied
4. Roll out to remaining instances

**Step 5: Enforce ACL Globally**

1. Enable ACL on all instances
2. Remove fallback to disabled mode (optional)
3. Monitor and audit regularly

### Rollback Plan

If issues occur:

1. Set `enabled: false` in configuration
2. Restart services (or hot-reload if supported)
3. Services revert to no ACL enforcement
4. Investigate and fix issues
5. Re-enable when ready

---

## Appendix: Code Examples

### Example 1: Service Integration

**Query Service** (`service/query/query_service.go`):

```go
func NewQueryService(config *Config, tlsUpdater connection.TLSCertUpdater) *Service {
    // ... existing code ...
    
    // Load ACL configuration if provided
    var aclProvider *acl.Provider
    if config.ACL != nil && config.ACL.Enabled {
        aclConfig, err := acl.LoadConfig(config.ACL.ConfigFile)
        if err != nil {
            logger.Fatalf("Failed to load ACL config: %v", err)
        }
        aclProvider = acl.NewProvider(aclConfig)
        logger.Info("ACL enabled for Query Service")
    } else {
        aclProvider = acl.NewProvider(nil)  // Disabled provider
        logger.Info("ACL disabled for Query Service")
    }
    
    return &Service{
        // ... existing fields ...
        aclProvider: aclProvider,
    }
}

func (q *Service) RegisterService(server *grpc.Server) {
    // Add ACL interceptor
    server = grpc.NewServer(
        grpc.UnaryInterceptor(acl.UnaryServerInterceptor(q.aclProvider)),
    )
    
    committerpb.RegisterQueryServiceServer(server, q)
    healthgrpc.RegisterHealthServer(server, q.healthcheck)
}
```

### Example 2: Test Certificate Generation

**Enhanced Test Utilities** (`utils/test/secure_connection.go`):

```go
func (scm *CredentialsFactory) CreateClientCredentialsWithRole(
    t *testing.T,
    tlsMode string,
    org string,
    role string,
) (connection.TLSConfig, string) {
    t.Helper()
    
    // Create certificate template with custom OU
    template := &x509.Certificate{
        Subject: pkix.Name{
            Organization:       []string{org},
            OrganizationalUnit: []string{role},
        },
        // ... other fields ...
    }
    
    clientKeypair, err := scm.CertificateAuthority.NewClientCertKeyPairFromTemplate(template)
    require.NoError(t, err)
    
    return scm.createTLSConfig(t, tlsMode, clientKeypair)
}
```

### Example 3: Integration Test

**Query Service ACL Test** (`service/query/acl_integration_test.go`):

```go
func TestQueryService_ACL_GetRows(t *testing.T) {
    t.Parallel()
    
    // Setup query service with ACL enabled
    config := &Config{
        ACL: &ACLConfig{
            Enabled:    true,
            ConfigFile: "testdata/acl-config.yaml",
        },
    }
    service := NewQueryService(config, nil)
    
    // Start service
    // ... service startup code ...
    
    // Test with reader role (should succeed)
    t.Run("reader can query rows", func(t *testing.T) {
        t.Parallel()
        
        credsFactory := test.NewCredentialsFactory(t)
        clientTLS, _ := credsFactory.CreateClientCredentialsWithRole(
            t, connection.MutualTLSMode, "Org1MSP", "client",
        )
        
        client := test.CreateClientWithTLS(t, endpoint, clientTLS, 
            committerpb.NewQueryServiceClient)
        
        _, err := client.GetRows(context.Background(), &committerpb.Query{
            // ... query params ...
        })
        require.NoError(t, err)
    })
    
    // Test with member role (should fail)
    t.Run("member cannot query rows", func(t *testing.T) {
        t.Parallel()
        
        credsFactory := test.NewCredentialsFactory(t)
        clientTLS, _ := credsFactory.CreateClientCredentialsWithRole(
            t, connection.MutualTLSMode, "Org1MSP", "member",
        )
        
        client := test.CreateClientWithTLS(t, endpoint, clientTLS,
            committerpb.NewQueryServiceClient)
        
        _, err := client.GetRows(context.Background(), &committerpb.Query{
            // ... query params ...
        })
        require.Error(t, err)
        require.Contains(t, err.Error(), "PermissionDenied")
    })
}
```

---

## Summary

This implementation plan provides a production-ready ACL system for fabric-x-committer that:

✅ **Follows Project Guidelines**: Simple, readable code without unnecessary abstractions
✅ **Backward Compatible**: Optional by default, no breaking changes
✅ **Security Focused**: Certificate validation, audit logging, role-based access
✅ **Well Tested**: Comprehensive unit and integration tests
✅ **Observable**: Prometheus metrics and structured logging
✅ **Documented**: Clear documentation and examples

**Next Steps**:
1. Review and approve this plan
2. Begin Phase 1 implementation (Core ACL Infrastructure)
3. Iterate based on feedback and testing
4. Deploy to production with gradual rollout

**Estimated Timeline**: 2-3 weeks for complete implementation and testing.