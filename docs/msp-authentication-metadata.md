<!--
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

# MSP Authentication and ACL Enforcement (Signed Envelope in gRPC Metadata)

## Overview

Committer-X's API-exposing services — the **query service** and the **sidecar**
(block query, block delivery, and notifications) — enforce Access Control Lists (ACLs) on
their gRPC APIs. Every exposed RPC is a resource mapped to a channel policy (for example
`/Channel/Application/Readers`); a client's MSP identity is evaluated against that policy
before the call proceeds.

Every request carries its own credential: a freshly-signed Fabric `common.Envelope`
attached to the gRPC call's **metadata** under the binary key `fabric-auth-envelope-bin`. A
server interceptor extracts and verifies the envelope on every call, then evaluates the
caller's MSP identity against the channel-config policy for the requested resource. Because
verification is fully self-contained in the request, **any service instance can authenticate
any request independently** — there is no per-connection or per-instance authentication
state to share, and no session or identity cache to keep synchronized across replicas. This
makes ACL enforcement **stateless and load-balancer-safe**: it works unmodified behind a
`round_robin` client policy or any other scheme that spreads calls (or even a single stream's
messages) across multiple instances.

This design differs from the `acl-with-auth-service` reference design (Option B), which binds
identity **once per connection** via a dedicated `Authorize` RPC and reuses it for every
subsequent call on that connection. This design instead re-authenticates **every call**. The
trade-offs:

- **No proto changes, no new RPC.** The credential is Fabric's existing `common.Envelope`,
  carried entirely in gRPC metadata. There is no `Authorize` RPC, no request wrapping, and no
  changed RPC signatures.
- **No connection binding, no fork dependency.** There is no mutable per-connection
  `AuthInfo`, no custom `credentials.TransportCredentials`, and no dependency on a forked
  `fabric-x-common` for an `AuthService`/`AuthorizeRequest` proto.
- **Cost:** every call pays for a fresh signature verification (and, for streams, freshness
  and cert-hash checks are done once at open, with policy re-evaluated per message against
  the cached identity). This is the price paid for statelessness — see
  [Cost / trade-off](#cost--trade-off) below.

Internal services (coordinator, verifier, validator-committer, mock orderer) do not enforce
ACL; they remain exempt as before.

## Authentication flow (per request)

Each call carries its own envelope, built and verified independently:

```
client interceptor                             server interceptor
------------------                             ------------------
build envelope:                                read metadata[fabric-auth-envelope-bin]
  ChannelId   = channel                        parse Payload + ChannelHeader + Data
  Timestamp   = now                            1. freshness:  |now - Timestamp| <= window
  TlsCertHash = hash(client cert)               2. method:     Data(StringValue) == info.FullMethod
  Data        = StringValue(info.FullMethod)    3. cert-hash:  TlsCertHash == hash(peer cert)  (mTLS only)
  Creator     = serialized MSP identity          4. identity:   deserialize + Validate + Verify(sig)
  Signature   = sign(Payload)                    5. policy:     evaluate identity vs. resource policy
attach to outgoing metadata  ───────────────▶  on success → handler(); else codes.*
```

1. **Client interceptor** builds a signed Fabric `common.Envelope` for the call about to be
   made: the caller's MSP identity goes in `SignatureHeader.Creator`, the exact gRPC full
   method (e.g. `/committerpb.QueryService/GetRows`) goes into the *signed* `Payload.Data` as
   a `google.protobuf.StringValue`, and `ChannelHeader.Timestamp` / `ChannelHeader.TlsCertHash`
   are set as usual. The whole `Payload` — header and method-bearing data together — is
   signed, so the bound method, timestamp, and cert hash are all tamper-proof. The envelope is
   marshaled and attached to the outgoing metadata under the `fabric-auth-envelope-bin` key;
   the `-bin` suffix makes gRPC base64-encode it on the wire automatically.
2. **Server interceptor** reads the envelope back out of incoming metadata and validates it in
   cheapest-first order: freshness, then method binding, then (under mTLS) TLS cert-hash
   binding, and only then the cryptographic identity checks (deserialize the creator identity,
   validate it against the channel's MSPs, and verify the envelope's signature). A rejection at
   any of the first three steps avoids paying for a signature verification.
3. On successful authentication, the server evaluates the resolved identity against the
   channel policy for the requested method (see
   [Policy resolution](#policy-resolution-fail-closed)) and, if authorized, invokes the
   handler.

Unary calls repeat this whole sequence on every RPC. Streaming calls verify once at stream
open (metadata is only sent at stream establishment) and then behave as described in
[Streaming and config changes](#streaming-and-config-changes).

## The three anti-replay defenses

A per-request envelope is a bearer credential, so replay resistance matters even though there
is no session to hijack. Three independent, stateless defenses apply:

1. **Method binding (the security enhancement in this design).** The signed envelope's
   `Payload.Data` carries the exact gRPC full method the envelope was signed for. The server
   rejects the call unless it equals `info.FullMethod`. A captured envelope is therefore usable
   only for the *exact* method it was signed for — an attacker who captures a read-only
   envelope (e.g. for `GetRows`) cannot replay it against a different RPC. This is a
   meaningful improvement over designs that bind identity once per connection: there, a
   captured `Authorize` envelope grants access to *every* RPC on that connection, whereas here
   each envelope is scoped to one method.
2. **Timestamp freshness (always).** `ChannelHeader.Timestamp` must fall within
   `DefaultEnvelopeFreshnessWindow` (±5 minutes) of the server's clock. A captured envelope goes
   stale and cannot be replayed once the window elapses, regardless of TLS mode. The check
   rejects out-of-range or missing timestamps up front, so a pathological far-future timestamp
   cannot overflow the skew arithmetic and slip past the window.
3. **TLS cert-hash binding (under mTLS).** When the connection presents a client certificate,
   `ChannelHeader.TlsCertHash` must equal the SHA-256 hash of that certificate (read directly
   from the connection's verified peer chain). A captured envelope cannot be replayed from a
   different connection, because the attacker cannot reproduce the victim's TLS private key.

### Accepted residual risk

**An attacker who steals both the client's TLS private key and a live envelope can replay
that envelope for its *same* method, from a connection using the stolen key, within the
freshness window.** Method binding limits the blast radius to one method; cert-hash binding
requires the attacker to also hold the private key; freshness bounds the replay window to a
few minutes — but none of them, alone or together, detect *reuse* of an envelope that is
otherwise still valid.

Closing this gap would require a server-side nonce or seen-envelope cache, which reintroduces
per-instance state and breaks statelessness under load balancing across replicas (the whole
point of this design). We deliberately reject a nonce cache and accept this residual risk:
method binding + freshness + cert-hash binding is the accepted bound, matching the same
trade-off the connection-binding reference design makes for its `Authorize` envelope. This
combination is materially stronger than "no anti-replay defenses at all," but it is not
equivalent to a stateful replay-proof scheme.

## Streaming and config changes

For streaming RPCs (block delivery, notifications), the envelope is authenticated **once**, at
stream open — gRPC only sends the initiating metadata at stream establishment, so subsequent
messages on the same stream carry no new envelope. The resolved identity is cached on the
wrapped stream. On every subsequent `RecvMsg`/`SendMsg`, the interceptor compares the cached
channel-config sequence against the provider's current bundle:

- If the sequence is unchanged, the check is a cheap in-memory comparison — no cryptographic
  work is repeated.
- If the sequence has advanced (a new configuration block/row has been processed), the cached
  identity is re-evaluated against the *new* bundle's policy. If the identity is no longer
  authorized — for example, the client's organization was removed from the channel's Readers
  policy — the stream is terminated immediately.

This means a mid-stream configuration change can revoke a client's continued access to an
already-open stream without requiring the client to reconnect or re-authenticate, while still
avoiding a full re-verification of the envelope on every message.

## Policy resolution (fail-closed)

For a given `info.FullMethod`, the resource-to-policy lookup order is:

1. The channel configuration bundle's `ACLs` section (`APIPolicyMapper`).
2. The hard-coded `DefaultACL` map (`utils/auth/default_acl.go`), which enumerates every
   protected Sidecar/Query method (currently all mapped to the Readers policy,
   `/Channel/Application/Readers`) — this is also the complete set of method names a client
   may legitimately bind into an envelope.

If neither defines a policy for the resource, the request is denied
(`codes.PermissionDenied`). A newly-added RPC that no one has mapped is therefore unreachable
until an explicit policy is declared, rather than silently allowed.

Exempt methods — gRPC health checks and reflection — bypass enforcement entirely so that
health probes work without an envelope. There is no `Authorize` RPC to exempt in this design.

## Error semantics

- Missing or garbled metadata envelope on an enforced method → `codes.Unauthenticated`.
- Stale timestamp, method mismatch, cert-hash mismatch, or invalid signature →
  `codes.Unauthenticated` (authentication failed).
- Identity valid but the policy denies it → `codes.PermissionDenied`.
- ACL enforcement is on but the channel-configuration bundle has not loaded yet →
  `codes.Unavailable` (a retryable condition during the bootstrap window).
- Non-enforced service, or an exempt method (health/reflection) → passthrough, no envelope
  required.

## Configuration

There is no server-side ACL config flag. The ACL interceptors are **always installed** on every
gRPC server; whether they *enforce* is decided at call time by the server's `ACLProvider`, not by
configuration. This is the optimistic model: enforcement is opt-in per service, controlled solely
by whether — and how — the owning service registers an `ACLUpdater` via `serve.RegisterACLUpdater`.

| Registration | Enforces? | Who |
| :--- | :--- | :--- |
| No `ACLUpdater` registered | No — passthrough | Internal services (coordinator, verifier, validator-committer) |
| `RegisterACLUpdater(..., requiresACL: false)` | No — passthrough (dynamic TLS CA refresh only) | Mock orderer |
| `RegisterACLUpdater(..., requiresACL: true)` | Yes | Sidecar, query service |

A service that enforces (`requiresACL: true`) is additionally gated on a **loaded
channel-configuration bundle**. The bundle (MSP definitions + policies) is populated dynamically
from configuration blocks/rows as they are processed — see [Bootstrap](#bootstrap). Until the
first bundle is loaded, an enforcing service returns `codes.Unavailable` on protected calls.

The **channel is never configured server-side** — it is derived from the signed envelope itself:
the caller's serialized MSP identity in the envelope is deserialized and validated against the
loaded bundle's MSPs, so the effective channel is whatever channel that bundle belongs to. There
is no `channel-id` to set on the server.

Client-side, a signer identity (an `msp.SigningIdentity`) is required to attach envelopes to
outgoing calls, along with the `ChannelID` that goes into the envelope's channel header. A `nil`
signer makes the client interceptors no-op passthroughs, so the same dial path is shared by ACL
and non-ACL deployments without a separate code path.

## Bootstrap

ACL evaluation needs the channel-configuration bundle, which each service builds from the
configuration data it already tracks for dynamic TLS CA refresh:

- **Sidecar** extracts the bundle from each config block delivered by the ordering service, via
  the same block-processing pipeline that already extracts the dynamic TLS client CAs
  (`serialization.ExtractAppBundle`, called alongside `ExtractAppTLSCAsFromEnvelope`).
- **Query service** extracts the bundle from the config-namespace row it polls from the state
  database (`ExtractAppBundle` on the stored config transaction envelope).

Both feed the extracted bundle into `ACLUpdater.UpdateBundle`, which installs it only if its
config sequence is **strictly newer** than the one currently held. This enforces monotonicity
at the sink: a transient stale read (for example replica lag or follower reads in a
distributed SQL backend) cannot roll the effective policy set backward and silently reinstate
access that a newer configuration already revoked. Until the first bundle is installed, an
ACL-enforcing service fails closed with `codes.Unavailable` on protected calls; clients should
treat this as retryable.

## Operational guidance

- **Run mutual TLS (`tls.mode: mtls`) wherever ACL enforcement is a security boundary.**
  Without mTLS, the TLS cert-hash defense does not apply — the envelope carries no certificate
  to bind to — leaving timestamp freshness as the sole anti-replay guard, and (in `mode: none`)
  the transport is also unencrypted, so an on-path observer could capture an envelope in the
  first place. The shipped sample configurations (`cmd/config/samples/sidecar.yaml`,
  `cmd/config/samples/query.yaml`) already run `mtls`. Non-mTLS modes are intended for testing
  or trusted-network deployments where ACL is advisory rather than a hard boundary.
- **Certificate revocation is re-checked at policy-evaluation granularity, not per call.** The
  client certificate and MSP identity are fully validated (deserialize, `Validate()`, signature
  verify) on every call, but that validation does not re-run certificate chain/CRL checks — it
  trusts the TLS layer's handshake-time verification for the connection's certificate. A
  certificate revoked via CRL, without a corresponding channel-config change, therefore keeps
  working on existing connections until they close. Operators who rely on CRL-based revocation
  should bound connection lifetime — for example via the gRPC server's `MaxConnectionAge`
  keepalive setting (`server.keep-alive.params.max-connection-age`) — which forces periodic
  reconnection and therefore a fresh TLS handshake and certificate validation.
- **A newly-added RPC is unreachable until it has a policy.** Because policy resolution is
  fail-closed, remember to add an entry to `DefaultACL` (or the channel's `ACLs` section) when
  exposing a new client-facing method on the sidecar or query service, or every call to it will
  be denied with `codes.PermissionDenied`.

## Cost / trade-off

Per-request signature verification, MSP identity deserialization, and policy evaluation run on
every unary call (and once per stream open). This is strictly more cryptographic work per call
than a design that authenticates once per connection and reuses the result — that is the price
paid for statelessness. In exchange, no service instance holds any per-connection or
per-client authentication state: any instance can serve any request, `round_robin` load
balancing across multiple sidecar/query replicas works without special handling, and there is
no session state to leak, expire, or synchronize across instances. For the request volumes and
RPC shapes this system serves (query/delivery reads, not a high-frequency internal RPC), this
trade-off favors simplicity and horizontal scalability over shaving per-call CPU cost.
