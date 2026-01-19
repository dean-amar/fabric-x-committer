# TLS Configuration for Committer Services

This guide details how to configure Transport Layer Security (TLS) for various services within the Committer. The configuration ensures secure communication when a service operates as either a server or a client.

## Configuration Structure

Each service in the Committer configuration includes a `tls` section. This section defines the security mode and the paths to the necessary certificate files.

### Parameters

| Field | Type | Description |
| :--- | :--- | :--- |
| **`mode`** | String | Defines the TLS operation mode (e.g., `mtls`). This setting determines how the credentials are built and enforced. |
| **`cert-path`** | String | The filesystem path to the service's public key (certificate). |
| **`key-path`** | String | The filesystem path to the service's private key. |
| **`ca-cert-paths`** | List | A list of paths to Certificate Authority (CA) certificates used to verify the peer's certificate. |

## Configuration Examples

### Server Configuration
Use this configuration when the service is acting as a server (accepting incoming secure connections).

```yaml
tls:
  mode: mtls
  cert-path: /server-certs/public-key.pem
  key-path: /server-certs/private-key.pem
  ca-cert-paths:
    - /server-certs/ca-certificate.pem
```

### Client Configuration
Use this configuration when the service is acting as a client (initiating secure connections to another service).

```yaml
tls:
  mode: mtls
  cert-path: /client-certs/public-key.pem
  key-path: /client-certs/private-key.pem
  ca-cert-paths:
    - /client-certs/ca-certificate.pem
```

### Notes
mTLS Mode: When mode is set to mtls (Mutual TLS), both sides of the connection must present valid certificates. The peer's certificate is verified against the trusted CAs defined in ca-cert-paths.

File Permissions: Ensure that the certificate and key files (.pem) are accessible and readable by the process running the Committer service.