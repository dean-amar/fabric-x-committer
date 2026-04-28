<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

# Access Control Lists (ACLs) Guide

## Overview

The fabric-x-committer ACL system provides fine-grained access control for Query and Sidecar service APIs. It uses certificate-based authentication to verify client identities and enforce role-based access policies.

## Key Concepts

### 1. Certificate-Based Identity

Client identities are extracted from X.509 certificates presented during TLS mutual authentication (mTLS). The certificate's **Organizational Unit (OU)** field determines the client's role.

**Example Certificate Subject:**
```
CN=User1@org1.example.com, OU=client, O=Org1MSP
                            ^^^^^^^^
                            This is the ROLE
```

### 2. Role Hierarchy

The system supports three roles with hierarchical privileges:

- **admin**: Full access to all operations (highest privilege)
- **client**: Can perform read and write operations
- **member**: Basic read-only access (default for any valid certificate)

**Hierarchy**: `admin > client > member`

A client with `admin` role can access methods requiring `client` or `member` roles.

### 3. Policy Mapping

Policies map gRPC methods to required roles:

```yaml
policies:
  "/query.QueryService/GetBlock": "member"      # Any valid cert can read
  "/sidecar.SidecarService/Deliver": "client"   # Requires client or admin
  "/admin.Service/UpdateConfig": "admin"        # Requires admin only
```

### 4. MSP Configuration

MSP (Membership Service Provider) configuration defines trusted Certificate Authorities for each organization:

```yaml
msps:
  Org1MSP:
    id: "Org1MSP"
    organization: "org1.example.com"
    root_certs:
      - /path/to/ca-cert.pem
```

## Configuration

### Inline Configuration (Recommended)

Add ACL configuration directly to your service configuration file:

**Query Service (`query.yaml`):**

```yaml
server:
  endpoint: :7001
  tls:
    mode: mtls  # mTLS required for ACL
    cert-path: /path/to/server.crt
    key-path: /path/to/server.key
    ca-cert-paths:
      - /path/to/ca.pem

# ACL Configuration
acl:
  enabled: true
  policies:
    # Query operations - read-only
    "/query.QueryService/GetBlock": "member"
    "/query.QueryService/GetTransaction": "member"
    "/query.QueryService/GetState": "member"
    "/query.QueryService/GetStateMetadata": "member"
    "/query.QueryService/GetStateRange": "member"
    "/query.QueryService/GetHistory": "member"
  msps:
    Org1MSP:
      id: "Org1MSP"
      organization: "org1.example.com"
      root_certs:
        - /path/to/org1-ca-cert.pem
    Org2MSP:
      id: "Org2MSP"
      organization: "org2.example.com"
      root_certs:
        - /path/to/org2-ca-cert.pem

# ... rest of configuration
```

**Sidecar Service (`sidecar.yaml`):**

```yaml
server:
  endpoint: :4001
  tls:
    mode: mtls  # mTLS required for ACL
    cert-path: /path/to/server.crt
    key-path: /path/to/server.key
    ca-cert-paths:
      - /path/to/ca.pem

# ACL Configuration
acl:
  enabled: true
  policies:
    # Block delivery - requires client role
    "/sidecar.SidecarService/Deliver": "client"
    "/sidecar.SidecarService/DeliverFiltered": "client"
    "/sidecar.SidecarService/DeliverWithPrivateData": "admin"
    
    # Notifications - requires client role
    "/sidecar.SidecarService/NotifyTxStatus": "client"
    
    # Block query - read-only
    "/sidecar.SidecarService/GetBlockByNumber": "member"
    "/sidecar.SidecarService/GetBlockByTxID": "member"
    "/sidecar.SidecarService/GetNewestBlock": "member"
  msps:
    Org1MSP:
      id: "Org1MSP"
      organization: "org1.example.com"
      root_certs:
        - /path/to/org1-ca-cert.pem

# ... rest of configuration
```

### Disabling ACL (Backward Compatible)

To disable ACL enforcement, either:

1. **Omit the `acl` section entirely** (backward compatible)
2. **Set `enabled: false`:**

```yaml
acl:
  enabled: false
```

When disabled, all requests are allowed regardless of client identity.

## Client Certificate Requirements

### Certificate Structure

Clients must present valid X.509 certificates with:

1. **Valid signature chain** to a trusted CA listed in MSP configuration
2. **OU field** containing the role (`admin`, `client`, or `member`)
3. **Organization** matching an MSP ID

**Example:**
```
Certificate:
    Subject: CN=User1@org1.example.com, OU=client, O=Org1MSP
    Issuer: CN=ca.org1.example.com, O=Org1MSP
    Validity:
        Not Before: Jan  1 00:00:00 2024 GMT
        Not After : Dec 31 23:59:59 2025 GMT
```

### Generating Certificates with Roles

Using OpenSSL:

```bash
# Generate private key
openssl genrsa -out user.key 2048

# Create certificate signing request with OU=client
openssl req -new -key user.key -out user.csr \
  -subj "/CN=User1@org1.example.com/OU=client/O=Org1MSP"

# Sign with CA
openssl x509 -req -in user.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out user.crt -days 365
```

Using Fabric CA:

```bash
# Enroll with specific role
fabric-ca-client enroll -u https://user1:password@ca.org1.example.com:7054 \
  --enrollment.attrs "hf.Type=client:ecert"
```

## Default Policies

If no policies are specified, the following defaults apply:

### Query Service Defaults

```yaml
"/query.QueryService/GetBlock": "member"
"/query.QueryService/GetTransaction": "member"
"/query.QueryService/GetBlockByTxID": "member"
"/query.QueryService/GetState": "member"
"/query.QueryService/GetStateMetadata": "member"
"/query.QueryService/GetStateRange": "member"
"/query.QueryService/GetHistory": "member"
```

### Sidecar Service Defaults

```yaml
"/sidecar.SidecarService/Deliver": "client"
"/sidecar.SidecarService/DeliverFiltered": "client"
"/sidecar.SidecarService/DeliverWithPrivateData": "admin"
"/sidecar.SidecarService/NotifyTxStatus": "client"
"/sidecar.SidecarService/GetBlockByNumber": "member"
"/sidecar.SidecarService/GetBlockByTxID": "member"
"/sidecar.SidecarService/GetNewestBlock": "member"
```

## Monitoring and Metrics

ACL operations are instrumented with Prometheus metrics:

### Available Metrics

- **`acl_checks_total{method, result}`**: Total number of ACL checks
  - Labels: `method` (gRPC method), `result` (allowed/denied)
  
- **`acl_check_duration_seconds{method}`**: ACL check latency histogram
  - Labels: `method` (gRPC method)

- **`acl_identity_validation_total{result}`**: Identity validation attempts
  - Labels: `result` (success/failure)

### Example Queries

```promql
# ACL denial rate
rate(acl_checks_total{result="denied"}[5m])

# ACL check latency (p99)
histogram_quantile(0.99, rate(acl_check_duration_seconds_bucket[5m]))

# Failed identity validations
rate(acl_identity_validation_total{result="failure"}[5m])
```

## Troubleshooting

### Common Issues

#### 1. "Permission Denied" Errors

**Symptom**: Client receives `PermissionDenied` gRPC error

**Possible Causes:**
- Client certificate has insufficient role (e.g., `member` trying to access `client` method)
- Certificate OU field is missing or incorrect
- Certificate not signed by trusted CA

**Solution:**
```bash
# Check certificate OU field
openssl x509 -in client.crt -noout -subject

# Verify certificate chain
openssl verify -CAfile ca.crt client.crt

# Check server logs for detailed error
```

#### 2. "Unauthenticated" Errors

**Symptom**: Client receives `Unauthenticated` gRPC error

**Possible Causes:**
- mTLS not configured on server
- Client not presenting certificate
- Certificate expired or not yet valid

**Solution:**
```bash
# Verify certificate validity
openssl x509 -in client.crt -noout -dates

# Check server TLS configuration
# Ensure mode: mtls in server config
```

#### 3. ACL Not Enforcing

**Symptom**: All requests succeed regardless of role

**Possible Causes:**
- ACL not enabled in configuration
- `acl.enabled: false` or `acl` section missing

**Solution:**
- Check service logs for "ACL enforcement disabled" message
- Verify `acl.enabled: true` in configuration
- Restart service after configuration changes

### Debug Logging

Enable debug logging for ACL operations:

```yaml
logging:
  logSpec: info,acl=debug
```

Debug logs include:
- Identity extraction details
- Policy evaluation steps
- Certificate validation results

## Security Best Practices

### 1. Always Use mTLS

ACL requires mTLS for certificate-based authentication:

```yaml
server:
  tls:
    mode: mtls  # Required for ACL
```

### 2. Principle of Least Privilege

Assign the minimum required role:
- Use `member` for read-only clients
- Use `client` for applications that submit transactions
- Reserve `admin` for administrative tools only

### 3. Certificate Management

- **Rotate certificates regularly** (e.g., every 90 days)
- **Use short validity periods** for client certificates
- **Implement certificate revocation** (CRL or OCSP)
- **Protect private keys** with appropriate file permissions

### 4. Monitor Access Patterns

- Set up alerts for unusual access patterns
- Monitor ACL denial rates
- Track failed authentication attempts
- Review audit logs regularly

### 5. Secure CA Private Keys

- Store CA private keys in HSM or secure key management system
- Limit access to CA signing operations
- Use intermediate CAs for issuing client certificates

### 6. Network Segmentation

- Deploy services in isolated network segments
- Use firewalls to restrict access to service endpoints
- Implement network-level access controls in addition to ACL

## Migration Guide

### Migrating from No ACL to ACL

1. **Enable mTLS** on your services (if not already enabled)
2. **Add ACL configuration** with `enabled: false` initially
3. **Test with ACL disabled** to ensure no disruption
4. **Generate client certificates** with appropriate roles
5. **Update clients** to use new certificates
6. **Enable ACL** by setting `enabled: true`
7. **Monitor metrics** for denied requests
8. **Adjust policies** as needed based on access patterns

### Rolling Update Strategy

For zero-downtime migration:

1. Deploy new service version with ACL disabled
2. Update all clients to use certificates with roles
3. Enable ACL on one service instance
4. Monitor for issues
5. Gradually enable ACL on remaining instances
6. Remove old clients without proper certificates

## Examples

### Example 1: Read-Only Client

**Certificate:**
```
Subject: CN=readonly@org1.example.com, OU=member, O=Org1MSP
```

**Allowed Operations:**
- Query service: All read operations
- Sidecar service: Block query operations

**Denied Operations:**
- Sidecar service: Deliver, NotifyTxStatus

### Example 2: Application Client

**Certificate:**
```
Subject: CN=app1@org1.example.com, OU=client, O=Org1MSP
```

**Allowed Operations:**
- Query service: All read operations
- Sidecar service: All operations except DeliverWithPrivateData

### Example 3: Administrator

**Certificate:**
```
Subject: CN=admin@org1.example.com, OU=admin, O=Org1MSP
```

**Allowed Operations:**
- All operations on all services

## Additional Resources

- [TLS Configuration Guide](tls-configurations.md)
- [Metrics Reference](metrics_reference.md)
- [Logging Guide](logging.md)
- [Sample Configurations](../cmd/config/samples/)

## Support

For issues or questions:
1. Check service logs with debug logging enabled
2. Review Prometheus metrics for ACL operations
3. Consult the troubleshooting section above
4. Open an issue on the project repository