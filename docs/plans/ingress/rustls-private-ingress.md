# Private Rustls Ingress Plan and Manual-Implementation Inventory

**Status:** design and migration plan; no ingress code has been changed by this
document.  
**Reviewed:** 2026-07-21

## Decision summary

Replace the current *plaintext loopback-only* client ingress with a Rustls
protected HTTP forward-proxy ingress. The first implementation must keep the
existing Tor bridge, Pingora HTTP service, destination policy, isolation store,
capacity controls, and fail-closed behavior. It must **not** combine this
security migration with a rewrite to Hyper/Tower, a switch away from Arti, or a
cache redesign.

The production protocol will be an HTTP/1.1 forward proxy carried inside TLS:

```text
customer proxy client
  -- TLS 1.3 + mTLS --> private-ingress.example:443
  -- HTTP/1.1 CONNECT or absolute-form HTTP --> Rustls ingress
  -- existing private paths --> Pingora / Tor bridge / Arti / Tor network
```

For a destination HTTPS request, this creates two separate TLS layers:

1. Client-to-proxy TLS protects proxy credentials and the CONNECT request.
2. Client-to-destination TLS starts *after* a successful CONNECT and remains
   opaque to this proxy.

The service is therefore an encrypted **forward proxy**, not an HTTPS reverse
proxy and not a TLS-intercepting proxy. It must never decrypt destination TLS
or fall back to a direct connection.

### Selected authentication model

Use two independent controls for production:

1. **mTLS client certificates** identify an approved customer device or
   connector at the network boundary.
2. **`Proxy-Authorization` API keys** identify the account/workspace and are
   revocable without replacing a device certificate.

Either mechanism alone is insufficient for the intended commercial boundary:
TLS server authentication alone does not identify the customer, and a bearer
API key sent over plaintext would expose the key. Local development may allow a
test CA and a deliberately configured no-mTLS mode, but production must fail to
start when client-certificate verification is required but trust roots are
missing.

## Current state and why it is not a private ingress yet

The relevant current topology is:

```text
client (only local today)
  -- plaintext HTTP --> 127.0.0.1:8080 public listener
                           |-- CONNECT --> embedded Arti/Tor bridge
                           `-- ordinary HTTP --> 127.0.0.1:8081 Pingora

metrics --> 127.0.0.1:9090
internal Tor bridge --> /tmp/proxy-bridge.sock (0600)
```

Evidence in the current code:

- `PUBLIC_PROXY_ADDR`, `INTERNAL_PROXY_ADDR`, and `PROMETHEUS_ADDR` are fixed
  to `127.0.0.1:8080`, `127.0.0.1:8081`, and `127.0.0.1:9090` respectively
  (`src/main.rs:65-82`).
- `Bridge::run_bridge` binds a `TcpListener` directly and accepts a plaintext
  `TcpStream` (`src/main.rs:1655-1751`).
- `handle_public_connection` hand-parses the first HTTP request, handles
  CONNECT, or copies the plaintext connection to Pingora (`src/main.rs:1754-1787`).
- The README correctly says the listener must not be directly exposed and that
  commercial deployment requires encrypted private access, account
  authorization, limits, revocation, and suspension (`README.md:25-36`,
  `README.md:162-184`).

The existing loopback binding is a good development default. The missing piece
is a deliberate public/private TLS boundary with authentication, certificate
management, resource limits, audit-safe observability, and a deployable
configuration surface.

## Target architecture

```text
                         Internet or customer private network
                                           |
                       TCP 443, TLS 1.3, ALPN http/1.1 only
                                           |
                 +-------------------------v-------------------------+
                 | Rustls private ingress                             |
                 | - handshake semaphore + deadline                  |
                 | - server certificate + required client certificate |
                 | - peer certificate fingerprint lookup             |
                 | - Proxy-Authorization API-key verification        |
                 | - header size / request deadline                  |
                 +-----------+---------------------------+-----------+
                             |                           |
               HTTP CONNECT  |                           | ordinary HTTP
                             |                           |
                    existing Bridge              existing loopback Pingora
                             |                           |
                             +------------+--------------+
                                          |
                        private Unix bridge -> embedded Arti
                                          |
                                      Tor network

          metrics stays loopback/private; it is never served through ingress
```

### Required protocol contract

- Bind the TLS ingress to a configurable `SocketAddr`; use `:8443` in staging.
  For `:443`, use a systemd socket unit or another reviewed mechanism so the
  application stays non-root. Do not give the proxy broad capabilities.
- Configure Rustls for TLS 1.3 only at launch, using Rustls safe defaults and a
  maintained crypto provider. Do not hand-pick cipher suites.
- Advertise only ALPN `http/1.1`. The current ingress is an HTTP/1 parser;
  advertising `h2` would promise a protocol that has not been implemented or
  tested for forward-proxy CONNECT semantics.
- Apply a handshake deadline and a separate bounded handshake semaphore before
  reading any application bytes. This limits TLS slowloris and CPU exhaustion.
- On handshake failure, close the connection without sending a plaintext HTTP
  response. Log only a stable error class and peer-network metadata allowed by
  the retention policy.
- After TLS, apply the existing 16 KiB header limit and add a first-request
  deadline. No plaintext listener may be reachable from an untrusted network.
- Validate mTLS first; then require proxy authentication before resolving
  isolation or making any upstream/Tor attempt.
- Strip `Proxy-Authorization`, the isolation headers, and any other ingress-only
  headers before ordinary HTTP reaches Pingora or a destination can observe
  them. The current implementation only strips isolation headers.
- Derive isolation from authenticated tenancy, not solely from a client-supplied
  header. The desired session input is an opaque value based on account,
  workspace, and canonical destination; strict mode still generates a fresh
  value for every stream.
- Preserve the existing invariant that a downstream `200 Connection
  Established` is sent only after the Tor stream is established.

## Recommended crate decisions

The versions below are the current release lines reviewed on 2026-07-21. Pin
compatible versions in `Cargo.lock`; do not copy a version string blindly into
`Cargo.toml` without resolving it against the chosen Rust toolchain.

| Crate | What it already provides | Decision |
|---|---|---|
| [`rustls`](https://docs.rs/rustls/latest/rustls/) | TLS protocol, `ServerConfig`, certificate verification, and TLS cryptography; it intentionally does not own TCP I/O. | **Add for ingress.** Use it for server configuration and required client-certificate verification. |
| [`tokio-rustls`](https://docs.rs/tokio-rustls/latest/tokio_rustls/) | Async `TlsAcceptor` and `TlsStream` over Tokio I/O. | **Add for ingress.** It is the direct replacement for the missing TLS accept step. |
| [`rustls-pemfile`](https://docs.rs/rustls-pemfile/latest/rustls_pemfile/) | PEM parsing for server certificates, private keys, and CA roots. | **Add for file-backed certificates.** Keep file permissions and secret distribution outside the process. |
| [`arc-swap`](https://docs.rs/arc-swap/latest/arc_swap/) | Atomic replacement of read-mostly `Arc` values without stopping readers. | **Add only with certificate/config reload.** Use an `ArcSwap<ServerConfig>` or equivalent snapshot to make new handshakes use reloaded credentials while existing tunnels continue. |
| [`rustls-acme`](https://docs.rs/rustls-acme/latest/rustls_acme/) | ACME certificate acquisition, renewal, cache support, and a Tokio-compatible incoming TLS stream. | **Optional.** Use only for a public DNS name and an ACME-managed server certificate. It does not replace mTLS, API-key authentication, or durable certificate-cache handling. |
| [`hyper`](https://docs.rs/hyper/latest/hyper/) + [`hyper-util`](https://docs.rs/hyper-util/latest/hyper_util/) | Correct HTTP/1 and HTTP/2 parsing/server primitives, HTTP upgrades, Tokio adapters, and client/server utilities. | **Evaluate later, do not add in the TLS migration.** It can replace the manual HTTP-header read/dispatch only in a separately tested ingress rewrite. |
| [`tower`](https://docs.rs/tower/latest/tower/) + [`tower-http`](https://docs.rs/tower-http/latest/tower_http/) | Composable HTTP middleware such as tracing, request-body limits, validation, and request-level timeouts. | **Later with Hyper.** Do not put a blanket Tower timeout around a long-lived CONNECT tunnel; use it only around request admission/setup. |
| [`governor`](https://docs.rs/governor/latest/governor/) | Keyed and direct GCRA rate limiting with in-memory state. | **Add with account authentication.** It covers per-account request admission, not tunnel lifetime, Tor circuit capacity, or billing. |
| [`metrics`](https://docs.rs/metrics/latest/metrics/) + [`metrics-exporter-prometheus`](https://docs.rs/metrics-exporter-prometheus/latest/metrics_exporter_prometheus/) | Instrumentation facade and a Prometheus scrape endpoint, including histograms and endpoint allowlisting. | **Recommended after ingress is stable.** It can replace the custom Prometheus renderer/HTTP endpoint, while privacy-safe metric names and labels remain application policy. |
| [`tracing`](https://docs.rs/tracing/latest/tracing/) + `tracing-subscriber` | Structured asynchronous spans/events and configurable log subscribers. | **Recommended.** Replace hand-built JSON strings, but keep the current privacy rules: no URL, account ID, API key, isolation value, or destination as a default label/field. |
| [`moka`](https://docs.rs/moka/latest/moka/) | Concurrent bounded caches with TTL/TTI, size bounds, and eviction. | **Optional only if replacing Pingora cache or `IsolationStore`.** It does not decide tenant/isolation policy for us. |
| [`ipnet`](https://docs.rs/ipnet/latest/ipnet/) | IPv4/IPv6 CIDR network types and containment checks. | **Optional.** It makes configured denied/allowed CIDRs clearer, but hostname handling, remote DNS, port rules, and SSRF policy remain custom. |
| [`backoff`](https://docs.rs/backoff/latest/backoff/) | General retry/backoff primitives. | **Do not add yet.** Retry eligibility, deadline sharing, and isolation rotation are proxy/Tor policy and are currently clearer as explicit code. |

`rustls` plus `tokio-rustls` are required for the work requested here. The
others are deliberately classified so that the ingress migration does not turn
into a dependency-driven rewrite.

## Phased implementation plan

### Phase 0 — Define the ingress contract and deployment facts

1. Create a typed `IngressConfig` in `src/main.rs` with explicit values for:
   listen address, certificate/key/CA locations, mTLS mode, hostname(s), TLS
   handshake timeout, first-request timeout, maximum concurrent handshakes,
   client connection cap, ALPN list, and development-mode guard.
2. Do not use a permissive default such as `0.0.0.0:8080`. Production must
   explicitly select the TLS address; development defaults may remain loopback.
3. Decide server-certificate source:
   - public name: ACME or a certificate issued by the chosen provider;
   - private customer network: private CA or enterprise-issued server cert.
4. Create a small private customer CA/process for issuing per-device mTLS
   certificates. Store only a stable certificate fingerprint and account/device
   mapping in the account store; do not treat a mutable certificate subject as
   the account identifier.
5. Record the systemd, firewall, cloud-security-group, IPv4/IPv6, management,
   and certificate-renewal facts required by the
   [firewall egress-hardening plan](../firewall/egress-hardening.md) before any
   production firewall change.

**Exit gate:** a reviewed protocol document includes an example client command,
the trust model, revocation/rotation procedure, and exact production port.

### Phase 1 — Add isolated TLS configuration and unit tests

1. Add `rustls`, `tokio-rustls`, and `rustls-pemfile` with minimal feature sets.
2. Implement a fallible loader that reads the leaf/server certificate chain,
private key, and client CA roots from explicitly configured paths. Reject:
   missing files, multiple ambiguous keys, malformed PEM, empty root stores, and
   certificate/key mismatch.
3. Build `rustls::ServerConfig` with required authenticated client certificates.
   Enable TLS 1.3 and ALPN `http/1.1` only.
4. Add a test-only CA, server certificate, authorized client certificate, and
   unauthorized client certificate. Keep these fixtures test-only; never add a
   production private key to the repository.
5. Add deterministic tests for successful server TLS, no client certificate,
   untrusted certificate, wrong private key, and unsupported application
   protocol.

**Exit gate:** `cargo check --locked`, `cargo test --locked`, and
`cargo build --locked` pass without opening a public listener.

### Phase 2 — Introduce the bounded Rustls accept loop

1. Replace the public plaintext `TcpListener` path with a configurable TCP
   listener followed by `TlsAcceptor::accept`.
2. Add `MAX_CONCURRENT_TLS_HANDSHAKES` separate from the existing connection,
   active-tunnel, and circuit-build semaphores. Acquire it before the TLS
   handshake and release it immediately after handshake completion or failure.
3. Wrap only `accept()` in the configured handshake timeout. A successful TLS
   connection then proceeds to the existing request processing path.
4. Refactor `handle_public_connection` into a generic ingress handler over
   `AsyncRead + AsyncWrite + Unpin` so it can accept `TlsStream<TcpStream>`.
   Keep `handle_connect_request` generic as it already is.
5. Preserve the buffered bytes after the CONNECT header. TLS decryption changes
   the stream type, not the HTTP bytes delivered to `read_proxy_request`.
6. Keep the old plaintext listener disabled for public use. It may be retained
   as a loopback-only development/test endpoint temporarily, guarded by an
   explicit development configuration flag.

**Exit gate:** an authenticated test client can use an HTTPS proxy connection;
plaintext traffic to the production ingress port fails; HTTP and HTTPS flows
still traverse Tor.

### Phase 3 — Bind TLS identity to proxy authorization and isolation

1. Add `AccountId` and `IngressIdentity` to the request context. The identity
   must carry only account/device references, never raw secrets.
2. Parse `Proxy-Authorization: Basic base64(api_key:)` after TLS and mTLS. Hash
   the high-entropy API key before lookup, compare in constant time where
   applicable, and never log it.
3. Return a standards-compatible `407 Proxy Authentication Required` with a
   `Proxy-Authenticate` challenge for missing/invalid keys. Return a distinct
   denial for inactive accounts.
4. Require the mTLS device record and API-key account to agree. A certificate
   may be restricted to an account, workspace, or source policy.
5. Derive session isolation from authenticated account/workspace plus canonical
   destination. Do not accept a caller-provided `X-Proxy-Isolation` as the sole
   tenant boundary. Preserve strict mode as a fresh per-operation isolation
   input.
6. Remove `Proxy-Authorization` and all internal identity/isolation headers
   before forwarding ordinary HTTP to Pingora. Assert the same property in a
   CONNECT integration test.

**Exit gate:** valid mTLS with an invalid/missing API key cannot reach Tor;
different accounts cannot share a session isolation group; sensitive headers
cannot reach a controlled origin.

### Phase 4 — Apply ingress-specific abuse and reliability limits

1. Add a first-request/header-read deadline after successful TLS. The existing
   bounded header parser remains in force.
2. Add per-account request rate limits using `governor` and a bounded cleanup
   policy. Return `429` and a retry hint when applicable.
3. Keep explicit Tokio semaphores for active tunnels and circuit builds. Tower
   or Governor must not replace the circuit-build admission policy because the
   permit scope and metrics are specialized.
4. Enforce a per-account maximum for concurrent tunnels before beginning Tor
   connection work.
5. Add a hard maximum TLS connection lifetime only for pre-authenticated or
   idle clients; do not impose a short total lifetime on active CONNECT tunnels.
6. Make error responses protocol-aware: before TLS handshake, close; after TLS
   but before a valid HTTP request, send only bounded HTTP errors; after a
   CONNECT succeeds, tunnel teardown remains raw TCP/TLS behavior.

**Exit gate:** slow handshakes, slow headers, invalid certificates, invalid
credentials, rate-limit exhaustion, circuit capacity exhaustion, and active
tunnel exhaustion all fail predictably without process growth or direct egress.

### Phase 5 — Production deployment and certificate lifecycle

1. Run the Rust process under a dedicated non-root user. Prefer systemd socket
   activation for port 443 so the application has no `CAP_NET_BIND_SERVICE`.
2. The host firewall/cloud firewall may expose only the chosen TLS ingress port
   and approved management access. Do not expose 8080, 8081, 9090, Arti, or
   internal Unix sockets.
3. Keep the proxy-to-Arti fail-closed egress work described in the
   [firewall egress-hardening plan](../firewall/egress-hardening.md)
   independent of TLS termination. TLS ingress does not prevent direct egress
   leaks.
4. Add an explicit reload path (for example, systemd `ExecReload` plus signal
   handling) that validates replacement certificates before atomically swapping
   the configuration. Existing TLS connections must drain normally; only new
   handshakes use the replacement.
5. If using ACME, persist its account/certificate cache in a dedicated
   owner-only directory, monitor renewal failures, test against staging first,
   and do not make ACME reachability a reason to weaken mTLS.
6. Rotate server certificates, client CAs, and client device certificates with
   overlap windows. Support immediate account/API-key suspension. For emergency
   client-certificate revocation, reject the stored fingerprint at the
   application boundary and replace the CA/configuration on the normal reload
   path.

**Exit gate:** reboot, certificate reload, expired/rotated client certificate,
and stopped Arti all produce the intended behavior; no internal port is
reachable externally.

### Phase 6 — Validate before replacing more code

Run a controlled test matrix on the actual deployment:

| Case | Required result |
|---|---|
| TLS 1.3, trusted mTLS certificate, valid API key | HTTP and CONNECT proxy traffic succeeds through Tor |
| Plain TCP to TLS port | Closed/rejected; it is never interpreted as HTTP |
| Missing/untrusted/expired client certificate | TLS handshake fails or is rejected before proxy dispatch |
| Valid mTLS but missing/invalid key | `407`; no Tor attempt and no isolation allocation |
| Suspended account | Denial; no Tor attempt |
| HTTP/2-only ALPN offer | No usable proxy session until HTTP/2 support is deliberately added |
| Oversized/slow header | Bounded timeout/error; no unbounded task or buffer |
| CONNECT bytes delivered with header | Preserved and flushed into the Tor stream |
| Controlled ordinary HTTP origin | Never receives proxy credentials or isolation headers |
| Repeated same account/domain session | Uses the intended isolation group |
| Different accounts/workspaces | Never share a session isolation group or upstream pool |
| Stop Arti | New requests fail closed; packet capture shows no direct destination/DNS egress |
| Metrics port from outside | Refused/filtered |
| Certificate reload | New connections use replacement; established tunnels are not interrupted |

Do not advertise the new ingress until this matrix passes, the existing
deployment runner passes against the TLS endpoint, and a packet capture verifies
the proxy identity has no direct egress.

### Phase 7 — Optional later HTTP-server cleanup

Only after the Rustls ingress has been stable should we consider replacing the
manual request reader and public dispatch with Hyper 1 + Hyper Util (and
optionally Tower). That project should be separately scoped because it changes
HTTP framing, connection reuse, upgrades, error semantics, and test coverage.

The desired end state for that optional phase is:

```text
Tokio TcpListener -> Tokio Rustls -> Hyper HTTP/1 server -> Tower policy stack
                                                |              |
                                                |              `- auth, request limits, tracing
                                                `- CONNECT upgrade -> existing Tor bridge
```

Do not enable Hyper HTTP/2 solely because Hyper supports it. Forward-proxy
HTTP/2 CONNECT behavior, client compatibility, and per-stream isolation would
need their own design and tests.

## Manual implementation inventory

This inventory covers the functional subsystems authored in `src/main.rs`; it
does not count trivial glue such as `format!` calls individually. “Manual” here
means the repository owns the policy/orchestration even when it correctly uses a
Tokio, Pingora, `http`, or `httparse` primitive underneath.

| Current manual subsystem | Evidence | Existing crate support | Recommendation |
|---|---|---|---|
| Plain TCP public ingress accept loop and task spawning | `Bridge::run_bridge`, `src/main.rs:1655-1751` | `tokio-rustls` adds TLS over Tokio; Hyper can own HTTP connection servicing later. | **Replace the public edge with Rustls; retain explicit admission/task lifecycle.** |
| First-request buffering and HTTP header completion loop | `read_proxy_request`, `src/main.rs:660-682` | `httparse` already parses headers; Hyper can own full HTTP parsing/framing. | **Keep for the incremental TLS migration; replace only in a dedicated Hyper rewrite.** |
| CONNECT/non-CONNECT dispatch and buffered-byte preservation | `parse_proxy_request`, `handle_public_connection`, `src/main.rs:530-566`, `1754-1787` | Hyper upgrades can help later, but no crate implements this product’s Tor routing decision. | **Keep policy manual.** Test it through `TlsStream`. |
| Raw HTTP error response byte constants | `src/main.rs:83-87` | `http`/Hyper can build typed responses. | **Keep temporarily; replace with typed response helpers in the later HTTP rewrite.** Add `407` support now. |
| Isolation-header validation and removal | `src/main.rs:300-327`, `477-527` | No generic crate can establish this tenant/isolation policy. | **Keep/extend manually.** Stop treating a caller header as an account boundary. |
| Ephemeral isolation store with TTL, capacity, LRU-like eviction, rotation, and group keys | `IsolationStore`, `src/main.rs:121-211` | Moka provides concurrent bounds and expiration. | **Keep the policy wrapper.** Evaluate Moka only if lock contention or maintenance becomes a demonstrated problem. |
| Destination authority parsing/canonicalization | `src/main.rs:355-399`, `580-615` | `http::uri::Authority` is already used; Hyper also uses `http` types. | **Keep custom normalization/policy.** Do not switch parsers unnecessarily. |
| Local/private-address and hostname suffix blocking | `connect_destination_allowed`, `src/main.rs:617-658` | `ipnet` helps configurable CIDR membership; no crate provides safe business-specific SSRF policy. | **Keep custom policy; optionally use `ipnet` for explicit configured CIDRs.** Preserve remote Tor DNS. |
| Conservative HTTP cache eligibility/key policy | `src/main.rs:369-457`, `1490-1518` | Pingora already supplies cache storage, lock, and eviction; Moka only supplies a generic cache. | **Keep policy manual.** Disable/partition cache in multi-tenant privacy mode rather than rewrite it during ingress work. |
| Cache status mapping and response mutation | `src/main.rs:459-466`, `1530-1559` | Pingora handles the response pipeline; no replacement needed now. | **Retain.** |
| Session-scoped upstream pool partitioning | `peer.group_key`, `src/main.rs:1385-1438` | Pingora provides upstream pooling; Hyper would require a new pool design. | **Retain.** This is security-sensitive isolation logic. |
| Prometheus histograms, counters, rendering, and mini HTTP server | `CircuitMetrics`, `append_histogram_metrics`, `render_prometheus_metrics`, `serve_prometheus_connection`, `src/main.rs:748-1041` | `metrics` + `metrics-exporter-prometheus` offer counters/histograms and a scrape endpoint. | **Recommended later replacement.** Preserve bounded labels/privacy policy; do not expose it through ingress. |
| Structured JSON-ish `eprintln!` logs | `src/main.rs:855-857`, `1080-1093`, `1590-1610` | `tracing` + `tracing-subscriber`. | **Replace with tracing after ingress is working.** Explicitly mark credentials and isolation values as sensitive/absent. |
| Connection, active-tunnel, and circuit-build admission | `Semaphore` fields and acquire helpers, `src/main.rs:1118-1279`, `1634-1652` | Tokio already provides semaphores; Tower concurrency limits and Governor rate limits cover different scopes. | **Keep explicit semaphores and custom status/metric accounting.** Add Governor only for per-account request rate limits. |
| RAII permit and gauge cleanup | `RateLimitGuard`, `ActiveTunnelPermit`, `AtomicGaugeGuard`, `src/main.rs:724-739`, `861-876`, `1043-1053` | Tokio permits are already cancellation-safe; no extra crate needed. | **Retain.** Simplify names only when refactoring. |
| Bidirectional tunnel copy, flush, half-close, idle timeout, and byte counters | `copy_one_direction` and `copy_bidirectional_with_idle_timeout_and_counters`, `src/main.rs:1145-1252` | Tokio offers `copy_bidirectional`, but not this exact idle/activity/counter/error-normalization policy. | **Keep manual wrapper.** It is one of the few justified custom I/O pieces. |
| Tor-connect deadline, one retry, isolation rotation, and Arti error classes | `connect_with_retry`, `src/main.rs:1800-1857` | Generic retry crates exist, but not correct Tor/isolation semantics. | **Keep manual.** Any refactor must preserve one total deadline and no direct fallback. |
| Destination circuit breaker | `CircuitBreaker`, `src/main.rs:220-298` | Circuit-breaker crates exist, but bounded destination keys, cooldown, and error categories are product policy. | **Retain initially.** Re-evaluate only after a measurable operational need. |
| CONNECT lifecycle/error mapping and only-after-connect `200` | `handle_connect_request`, `src/main.rs:1859-1984` | No generic crate combines this with Tor, admission, isolation, and privacy-safe metrics. | **Keep manual.** Make stream type generic for TLS ingress. |
| Private Unix bridge socket creation and permissions | `src/main.rs:1655-1666` | Tokio provides Unix sockets; Unix permissions come from the standard library/OS. | **Retain.** Do not expose or replace it during ingress work. |
| Embedded Arti bootstrap and dedicated runtime | `TorCircuit`, `src/main.rs:1293-1328` | Arti provides the client; systemd can supervise a separate service later. | **Out of ingress scope.** Follow the [firewall egress-hardening plan](../firewall/egress-hardening.md) for the separate-process migration. |
| Configuration through compile-time constants | `src/main.rs:50-87` | `serde`/`toml`/`figment`/`clap` can parse config, but no crate supplies safe defaults. | **Replace with a small typed config layer in this migration.** Keep secrets in owner-only files, not command-line arguments. |
| Unit tests and controlled-origin test matrix | `src/main.rs:2099+`, test scripts | Tokio test utilities and Rust’s test harness are already sufficient. | **Extend tests; no test framework change is needed.** |

### Important distinction: what is already external

The repository is not implementing everything from scratch. It already relies on
well-established components for the hard mechanics:

- Tokio for async sockets, tasks, timeouts, semaphores, I/O traits, and Unix
  sockets.
- `httparse` for low-level HTTP header parsing.
- `http` for authority/header/request types.
- Pingora for ordinary HTTP forwarding, upstream pooling, cache plumbing, and
  response hooks.
- Arti for Tor bootstrap, circuit creation, name resolution through Tor, and
  stream opening.

The code that should remain repository-owned is the security and product policy:
who may connect, which tenant owns a request, which destinations are allowed,
which streams may share a circuit, when to reject work, and which data may be
observed or retained.

## Explicit non-goals for this change

- Do not expose the current 8080 listener publicly as an interim step.
- Do not put a reverse proxy in front merely to terminate TLS and call the
  ingress solved; the Rust service must understand the authenticated private
  proxy boundary or a separately reviewed frontend must do so.
- Do not add HTTP/2, HTTP/3, QUIC, transparent proxying, destination TLS MITM,
  browser-facing web UI, or an onion-service ingress in this migration.
- Do not remove current destination filtering, isolation behavior, circuit
  admission, retry limits, timeout behavior, buffered-byte handling, or
  fail-closed Tor routing.
- Do not use client certificate subjects, destination names, raw API keys, or
  isolation strings as Prometheus labels or default log fields.
- Do not activate firewall rules or production certificate issuance from a code
  change without the deployment facts, rollback plan, and explicit approval
  required by the [firewall egress-hardening plan](../firewall/egress-hardening.md).

## Definition of done

The Rustls private ingress is complete only when all of these are true:

1. Untrusted clients can reach the proxy only through a TLS endpoint with the
   documented authentication requirements.
2. Plaintext proxy traffic cannot reach the production ingress.
3. TLS handshake and header reads are bounded by independent limits/timeouts.
4. Valid client certificate and valid API key are both required before any Tor
   connection or isolation state is allocated.
5. Account/workspace identity scopes session isolation and upstream reuse.
6. Proxy credentials and internal isolation metadata cannot reach an origin.
7. Ordinary HTTP and HTTPS CONNECT continue to work through Tor; destination
   TLS remains end-to-end.
8. The proxy remains fail-closed when Arti is unavailable and has no direct
   egress route under its production identity.
9. Metrics and administrative/internal listeners remain private.
10. Certificate reload/rotation, device/API-key revocation, restart, and rollback
    procedures have been exercised in a controlled deployment.
