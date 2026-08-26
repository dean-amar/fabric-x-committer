<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->
# Authentication & Authorization Service (ACL)

The `auth` service is a central Authentication & Authorization Service (`AuthService`) that guards the
gRPC APIs exposed by Committer-X. It authenticates a client once and issues a short-lived,
certificate-bound JSON Web Token (JWT); resource servers (Query, Sidecar) then authorize each RPC by
delegating to the `AuthService`. This decouples the one-time, expensive signature verification from
the many cheap per-call authorization checks, and works behind client-side load balancing because the
authoritative state lives in one place (the state database), not on a socket or an instance.

See the RFC (`updated_acl_rfc.md`) for the full motivation and design rationale.

## Structure

The service is composed of focused collaborators, each with one responsibility:

- **`configProvider`** (`bundle.go`) — *reads* the latest committed channel configuration from the
  `ns__config` namespace and exposes it as a `channelconfig.Bundle`, refreshing on an interval. It
  mirrors how the query service reads the config transaction to refresh its TLS roots; the auth
  service never owns or mutates configuration, it only reads what the sidecar and coordinator commit.
- **`tokenSigner`** (`token.go`) — mints and verifies ES256 JWTs. The signing key never leaves the
  service; resource servers never verify tokens themselves.
- **`tokenStore`** (`store.go`) — the token-to-identity binding store: it maps a token id (`jti`) to
  the client's resolved MSP identity (plus its certificate binding, scope, and expiry), persisted in
  the dedicated `auth_tokens` namespace and fronted by an in-memory read-through cache.
- **`authenticator`** (`authenticate.go`) — verifies a signed envelope and issues a token, writing
  the token-to-identity binding to the store.
- **`authorizer`** (`authorize.go`) — answers authorization decisions.
- **`Service`** (`auth_service.go`) — composes the above and exposes the gRPC handlers.

## RPCs

- `Authenticate(signed_envelope, requested_scope) -> token, expires_at` — verifies the envelope
  (channel and empty-payload scope, timestamp freshness, TLS certificate binding, MSP identity
  resolution, signature), writes the token-to-identity binding, and mints a cert-bound ES256 JWT.
- `Authorize(token, resource, tls_cert_hash) -> authorized, identity` — verifies the token, checks
  the certificate binding and optional scope, resolves the bound identity from the store, evaluates
  the resource's policy against the latest configuration, and returns the resolved identity so a
  resource server can bind it to a stream session.
- `ReAuthorize(identity, resource) -> authorized` — re-evaluates an identity already bound to a
  stream session against the latest policy, without re-presenting the token.

Every non-authorized outcome is a gRPC status error, so the resource server propagates the exact
code: `Unauthenticated` (invalid/expired/unknown token or certificate mismatch), `PermissionDenied`
(scope or policy denial), or `Unavailable` (before the configuration is loaded, or AuthService
unreachable).

## Token and certificate binding

The token is an ES256 JWT minted and verified only by the `AuthService`. It is certificate-bound per
RFC 8705: the `cnf.x5t#S256` claim carries the SHA-256 of the client's TLS certificate, so a leaked
token is useless without the matching private key. Whether the token is certificate-bound follows
entirely from the transport: mutual TLS makes the client's certificate present on the connection, and
the service binds to it. There is no separate "mutual TLS" toggle - the server's TLS mode is the one
source of truth.

**Mutual TLS is required, not optional.** The certificate binding is the token's proof-of-possession
property. Without mutual TLS the connection presents no client certificate, the token is not
certificate-bound, and it degrades to a plain bearer token that anyone who captures it can replay.
Deploy the `AuthService` and every ACL-protected resource server with `mode: mtls` end to end; the
non-mTLS path exists only for local development and tests and must not be used in production.

## Client and interceptors (`utils/acl`)

- **Server side — `Enforcer`**: the unary and stream interceptors installed on a resource server.
  They forward the caller's token (and TLS certificate hash) to `Authorize`, bind the returned
  identity to each stream, and re-authorize that identity via `ReAuthorize` on an interval. Health
  checks (`grpc.health.v1.Health`) are exempt.
- **Client side — `TokenSource`**: a `credentials.PerRPCCredentials` that authenticates once, caches
  the token, refreshes it before expiry, and attaches it to every outgoing RPC.

## Configuration

- **`AuthService`** (`cmd/config/samples/auth.yaml`): `signing-key-path` (a shared PEM EC key across
  instances; ephemeral if empty), `token-ttl`, `envelope-freshness-window`, `config-refresh-interval`,
  `token-cleanup-interval`, and the state `database`. Use `mtls` for the server TLS mode so tokens are
  certificate-bound.
- **Resource servers** (Query, Sidecar): an optional `auth:` section (`utils/acl.ClientConfig`) with
  the `AuthService` endpoint + TLS and an optional `stream-revalidate-interval`. When absent, the
  service serves without ACL enforcement, preserving existing behavior.

## Policy resolution

A resource is its gRPC full-method name (e.g. `/committerpb.QueryService/GetRows`). The policy is
resolved from the channel configuration's `ACLs` section first, then a hard-coded default map
(`policy.go`), which maps every exposed method to `/Channel/Application/Readers`. If neither defines a
policy, the request is denied.

## Operational notes

- **Fail-closed.** If a resource server cannot reach the `AuthService`, a new unary call or stream
  establishment is rejected (`Unavailable`). The one deliberate exception is periodic re-authorization
  of an *already-established* stream: a transient `AuthService` outage keeps the open stream alive and
  re-checks it on the next interval, so a blip does not tear down every live stream at once. New
  admissions never benefit from this tolerance. Run multiple `AuthService` instances behind a load
  balancer; all state is in the shared database, so any instance can serve any request.
- **Replay resistance.** An authentication envelope is scoped to this channel and must carry an empty
  payload. An ordinary transaction shares the envelope's header type and channel but always carries a
  payload, so it cannot be replayed to `Authenticate` to mint a token in its signer's name - a
  necessary guard, because any channel reader can observe committed transactions. The freshness window
  bounds replay of a captured authentication envelope, and under mutual TLS the certificate binding
  makes even a captured envelope useless without the signer's private key.
- **Streaming re-authorization is identity-based.** A stream is authorized at establishment; the
  resolved identity is bound to the stream and re-evaluated against the latest policy every
  `stream-revalidate-interval`. Because re-authorization checks the *identity* (not the token), a
  long-lived stream is torn down when a configuration change removes the identity's organization, but
  is never dropped merely because the establishment token's TTL elapsed - stream lifetime is
  decoupled from token lifetime. Re-authorization is checked on stream activity; a fully idle stream
  is re-checked on its next message.
- **Revocation.** Revocation is a delete of the token record (`tokenStore.delete`), an operational
  primitive not yet exposed through a client-facing RPC. Because each instance fronts the store with a
  short-lived read-through cache, cross-instance revocation takes effect within the token TTL rather
  than instantly - an accepted trade-off of caching. Note that revocation affects new unary calls and
  new stream establishments; a stream already established re-authorizes on identity, not token.
- **Bootstrap.** Until the first configuration block is committed and observed, the `AuthService`
  returns `Unavailable`; protected APIs reject calls until enforcement becomes active.
