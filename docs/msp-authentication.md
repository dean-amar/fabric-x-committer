<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

# MSP Authentication and ACL Enforcement

## Overview

Committer-X's API-exposing services — the **query service** and the **sidecar**
(block query, block delivery, and notifications) — enforce Access Control Lists (ACLs)
on their gRPC APIs. Every exposed RPC is a resource mapped to a channel policy
(for example `/Channel/Application/Readers`); a client's MSP identity is evaluated against
that policy before the call proceeds.

This implements **Option B** of the ACL RFC: rather than wrapping every request in a signed
envelope, the client proves its identity **once per connection** via a dedicated `Authorize`
RPC. The verified identity is bound to the gRPC connection, and every subsequent RPC on that
connection reuses it. Internal services (coordinator, verifier, validator-committer, mock
orderer) do not enforce ACL.

## Key concept: connection-bound identity

The authenticated MSP identity is stored on a mutable `AuthInfo` value attached to the TLS
connection during the handshake. When the connection closes, the Go runtime garbage-collects
that value — there is no global session registry to leak.

## Components

All types live in `utils/auth/`.

1. **`MSPAuthInfo`** (`auth_info.go`) — implements `credentials.AuthInfo`. Holds the client
   TLS certificate and its SHA-256 hash (captured at handshake), and, once `Authorize`
   succeeds, the bound `msp.Identity` and the config sequence it was evaluated at. Identity
   access is guarded by a `sync.RWMutex`.

2. **`CustomCredentials`** (`committer_creds.go`) — wraps the standard TLS
   `TransportCredentials`. On each handshake it delegates to TLS, then replaces the connection's
   `AuthInfo` with an `*MSPAuthInfo`, capturing the client's leaf certificate and hash (under
   mTLS).

3. **Interceptors** (`interceptor.go`):
   - `AuthorizeInterceptor` (unary) — handles the `Authorize` RPC: validates the signed
     envelope and binds the identity to the connection.
   - `MSPUnaryServerInterceptor` / `MSPStreamServerInterceptor` — enforce ACL on business RPCs
     by reading the bound identity and evaluating it against the resource's policy.

4. **Envelope validation** (`envelope_utils.go`) — `ValidateAuthEnvelope` performs the
   replay-resistant checks; `ExtractIdentityFromEnvelope` performs the cryptographic identity
   checks.

5. **Client helper** (`authorize_client.go`) — `AuthorizeConnection` builds the signed,
   cert-bound envelope and calls `Authorize`, retrying while the server bootstraps.

6. **Resource map** (`default_acl.go`) — the hard-coded default resource-to-policy map and the
   set of ACL-exempt methods (health, reflection, `Authorize`).

The channel-configuration bundle (MSP definitions + policies) is supplied by
`serve.ACLProvider` / `serve.ACLUpdater` (`utils/serve/acl_provider.go`), which is refreshed
from configuration blocks by the same path that refreshes the dynamic TLS CAs.

## Authentication flow

```
1. Client establishes a (mutually authenticated) TLS connection.
   - CustomCredentials captures the client cert + hash into MSPAuthInfo (identity slot empty).

2. Client calls Authorize(signedEnvelope) once per connection.
   - AuthorizeInterceptor validates freshness + TLS cert-hash binding, verifies the signature,
     resolves the identity against the channel MSPs, and binds it to the connection.

3. Client calls business RPCs (unary or streaming).
   - The MSP interceptors read the bound identity and evaluate it against the resource policy.
   - Streams re-evaluate the identity whenever the channel config sequence advances.

4. Client disconnects.
   - MSPAuthInfo is garbage-collected; no manual cleanup.
```

## Replay prevention

The `Authorize` envelope is protected by two independent mechanisms, mirroring the RFC:

- **Timestamp freshness (always).** The envelope's `ChannelHeader.Timestamp` must fall within
  `DefaultEnvelopeFreshnessWindow` of the server's clock. A captured envelope goes stale and
  cannot be replayed later, regardless of TLS mode.
- **TLS cert-hash binding (under mTLS).** When the connection presents a client certificate,
  the envelope's `ChannelHeader.TlsCertHash` must equal the SHA-256 hash of that certificate.
  A captured envelope therefore cannot be replayed from a different connection, because the
  attacker cannot reproduce the victim's TLS private key.

Under mTLS these two together make the scheme equivalent to certificate-bound tokens
(RFC 8705) for the token-theft/replay threat: the credential is useless without the private
key, and after `Authorize` no credential travels on the wire at all. Without mTLS, timestamp
freshness is the sole guard.

## Policy resolution (fail-closed)

For a given `info.FullMethod`, the resource-to-policy lookup order is:

1. The channel configuration bundle's `ACLs` section (`APIPolicyMapper`).
2. The hard-coded `DefaultACL` map.

If neither defines a policy for the resource, the request is **denied**
(`codes.PermissionDenied`). A newly-added RPC that no one has mapped is therefore unreachable
until an explicit policy is declared, rather than silently allowed.

Exempt methods — the `Authorize` RPC itself, gRPC health, and reflection — bypass enforcement
entirely so that health probes and the authorization handshake work without a bound identity.

## Bootstrap

ACL evaluation needs the channel-configuration bundle, which the service builds from the first
committed configuration block. Until that block is processed the provider has no bundle and,
for an ACL-enforced service, `Authorize` returns `codes.Unavailable`. `AuthorizeConnection`
retries on `Unavailable` within a bounded window, so clients that connect during startup
succeed once the bundle is available. Genuine denials (bad identity, cert mismatch, stale
timestamp) are permanent and returned immediately.

## Server setup

The ACL credentials and interceptors are installed for every gRPC server built by
`serve.NewServers` (`utils/serve/start_serve.go`). Whether a given service actually enforces
ACL is decided at registration time:

```go
func (s *Service) RegisterService(srv serve.Servers) {
    // ... register the business services and health ...
    // requiresACL=true → the query/sidecar enforce ACL.
    serve.RegisterACLUpdater(srv.GrpcACLProvider, &s.aclUpdater, true)
    committerpb.RegisterAuthServiceServer(srv.GRPC, auth.NewAuthService(srv.GrpcACLProvider))
}
```

Services that only need dynamic TLS CA refresh (the mock orderer) register with
`requiresACL=false` and are never subject to ACL checks. Services that register no
`ACLUpdater` at all (internal services) bypass ACL entirely.

## Client setup

A client authorizes a connection once, before any business RPC:

```go
conn := test.NewSecuredConnection(t, endpoint, clientTLS)

tlsCertHash, err := auth.ClientTLSCertHash(clientTLS) // nil when not mTLS
// ...
err = auth.AuthorizeConnection(ctx, conn, auth.AuthorizeParameters{
    Signer:      signingIdentity, // an msp.SigningIdentity
    ChannelID:   channelID,
    TLSCertHash: tlsCertHash,
})
// ... now use committerpb.NewQueryServiceClient(conn) / NewNotifierClient(conn) / peer.NewDeliverClient(conn)
```

For block delivery through the shared `utils/delivercommitter` helper, pass the signer and
channel on `delivercommitter.Parameters`; it authorizes the connection on each (re)connection
before opening the deliver stream. A nil `Signer` skips authorization, which is correct for
servers that do not enforce ACL.

## Streaming and config changes

For streaming RPCs (block delivery, notifications), the identity is evaluated when the stream
is established and re-evaluated whenever the channel configuration sequence advances during the
stream's lifetime. If a re-check fails — for example, the client's organization was removed
from the channel — the stream is terminated. On an unchanged sequence the per-message check is
a cheap atomic comparison with no cryptographic work.

## Thread-safety and performance

- `MSPAuthInfo` uses a `sync.RWMutex` for identity access; the TLS cert fields are set once at
  handshake and read without locking.
- Memory is O(active connections): one `MSPAuthInfo` per connection, freed on disconnect.
- Unary RPCs evaluate the policy on every call (short-lived, no caching needed). Streams cache
  the last-evaluated bundle and only re-evaluate on a sequence change.
