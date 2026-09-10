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
  the dedicated `auth_tokens` table and fronted by an in-memory read-through cache.
- **`authenticator`** (`authenticate.go`) — verifies a signed envelope and issues a token, writing
  the token-to-identity binding to the store.
- **`authorizer`** (`authorize.go`) — answers authorization decisions.
- **`Service`** (`auth_service.go`) — composes the above and exposes the gRPC handlers.

## RPCs

- `Authenticate(signed_envelope, requested_scope) -> token, expires_at` — verifies the envelope
  (channel and empty-payload scope, timestamp freshness, TLS certificate binding, MSP identity
  resolution, signature), writes the token-to-identity binding, and mints a cert-bound ES256 JWT.
- `IssueNonce() -> nonce, expires_at` — issues the single-use challenge a client must sign into its
  envelope. It is the mandatory first step of authentication.
- `Authorize(token, resource, tls_cert_hash) -> authorized, token_expires_at` — verifies the token,
  checks the certificate binding and optional resource scope, resolves and validates the bound identity
  from the store, evaluates the resource's policy against the latest configuration, and returns the
  token's expiry. A resource server calls it for every unary RPC and, for a stream, whenever its cached
  decision lapses.

Every non-authorized outcome is a gRPC status error, so the resource server propagates the exact
code: `Unauthenticated` (invalid/expired/unknown token or certificate mismatch), `PermissionDenied`
(scope or policy denial), or `Unavailable` (before the configuration is loaded, or AuthService
unreachable).

## Replay protection: the nonce challenge

Authentication is a two-step challenge-response. The client calls `IssueNonce`, receives 32 bytes of
server-chosen randomness, and places it in the `SignatureHeader.Nonce` of the envelope it then presents
to `Authenticate`. Because the envelope's signature covers the whole marshaled payload — and the
`SignatureHeader` is part of that payload — the nonce cannot be substituted without invalidating the
signature.

The nonce is **consumed** when redeemed: `Authenticate` deletes the row and requires that exactly one
row was removed, so a second presentation of the same envelope fails. That single `DELETE` is what
makes the guarantee atomic even when two redemptions race, and even across instances.

Nonces are held in the shared state database (`auth_nonces`), not in one instance's memory, because a
client behind a load balancer has no guarantee its `IssueNonce` and `Authenticate` calls reach the same
instance. Unredeemed nonces are swept on the same tick as expired tokens.

This is what makes a captured envelope worthless rather than merely short-lived: the freshness window
and the certificate binding remain as defence in depth, but replay is closed by the nonce itself.

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
  They forward the caller's token (and TLS certificate hash) to `Authorize`; a stream binds the
  *token* to its session and renews the decision from it. Health checks (`grpc.health.v1.Health`) are
  exempt. The interceptors never inspect the request body: a decision depends only on the token, the
  certificate on the connection, and the method name.
- **Client side — `TokenSource`**: a `credentials.PerRPCCredentials` that fetches a nonce, authenticates
  once, caches the token, refreshes it before expiry, and attaches it to every outgoing RPC.

## Configuration

- **`AuthService`** (`cmd/config/samples/auth.yaml`): `signing-key-path` (a shared PEM EC key across
  instances; ephemeral if empty), `token-ttl`, `envelope-freshness-window`, `nonce-ttl`,
  `config-refresh-interval`, `token-cleanup-interval`, `challenge-requests-per-second` /
  `challenge-burst`, and the state `database`. Use `mtls` for the server TLS mode so tokens are
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
- **Replay resistance.** The single-use nonce is the primary guard (see *Replay protection* above).
  Behind it: an authentication envelope is scoped to this channel and must carry an empty payload, so an
  ordinary transaction - which shares the envelope's header type and channel but always carries a
  payload - cannot be replayed to `Authenticate` to mint a token in its signer's name, a necessary guard
  because any channel reader can observe committed transactions. The freshness window bounds how long an
  unredeemed envelope stays presentable, and under mutual TLS the certificate binding makes a captured
  envelope useless without the signer's private key.
- **Streaming re-authorization is token-based.** A stream binds the *token* it was established with. On
  every receive and send the wrapper checks whether its cached decision has lapsed and, if so,
  re-`Authorize`s with that token: the token is resolved to its record (catching expiry) and the
  resulting identity re-evaluated against the latest configuration (catching a policy change,
  such as the identity's organization being removed). A valid decision is reused until it lapses, so the
  common case costs no round trip - checking per message would put `AuthService` latency on the data
  path of every block and batch. A decision is never reused past `stream-revalidate-interval`, and never
  past the bound token's own expiry, which the resource server enforces locally.
- **Rate limiting the front door.** `IssueNonce` and `Authenticate` are reachable without a token, and
  each costs the service real work - a database row for a nonce, a signature verification and MSP
  resolution for an authentication - so they share a token-bucket limit
  (`challenge-requests-per-second` / `challenge-burst`, default 200/s burst 50) and return
  `ResourceExhausted` above it. This is deliberately separate from the server-wide `rate-limit`:
  `Authorize` is called once per protected RPC by the resource servers, so its rate tracks the whole
  cluster's traffic and must not share a bucket with the two unauthenticated RPCs. The limit is global
  per instance, not per client, so it caps total load rather than isolating one caller; mTLS is what
  restricts who can reach the service at all.
- **No revocation.** A token is valid until its `exp`, and `token-ttl` is the only lever on how long a
  compromised token or a withdrawn authority remains usable. Deleting a record is deliberately not
  offered: each instance fronts the store with a read-through cache, so a delete on one instance would
  not be observed by another before the token expired anyway. Expiry itself is unaffected by the cache,
  because `Authorize` verifies the JWT's `exp` before consulting the store.
- **Namespace scope is deferred.** Restricting a token to particular namespaces is future work, not part
  of this iteration. Only `GetRows` and `StreamAllTransactions` name the namespaces they touch; block
  query and block delivery return whole blocks spanning every namespace, and a block cannot be filtered
  to a subset without breaking the verification clients perform on it. A scope enforceable on two
  resources and meaning "denied entirely" on the rest is a poor primitive, and the obvious
  implementation fails open, since a request naming no namespaces means *every* namespace. See the RFC's
  "Future work: namespace scoping".
- **Bootstrap.** Until the first configuration block is committed and observed, the `AuthService`
  returns `Unavailable`; protected APIs reject calls until enforcement becomes active.
