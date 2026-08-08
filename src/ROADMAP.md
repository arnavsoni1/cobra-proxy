# Roadmap

This roadmap is the high-level sequencing source of truth. Detailed acceptance
criteria, security constraints, and verification matrices live under `docs/`.
Do not begin a later phase merely because an earlier phase compiles; complete
its documented verification gate first.

## Documentation structure

```text
docs/
  plans/ingress/   future client-ingress and transport-security work
  plans/firewall/  future egress containment and network-boundary work
  architecture/    current verified architecture, added when needed
  runbooks/        tested operational procedures, added when needed
```

Current detailed plans:

- [Rustls private ingress](../docs/plans/ingress/rustls-private-ingress.md)
- [Firewall egress hardening](../docs/plans/firewall/egress-hardening.md)

## Phase 0 — Preserve the verified core

**Status:** ongoing

- Keep `src/main.rs` as the runtime core while the surrounding ingress and
  deployment boundaries are improved.
- Preserve current HTTPS CONNECT, ordinary HTTP forwarding, destination
  validation, isolation, cache policy, circuit admission, retry, metrics, and
  fail-closed behavior.
- Run `cargo check --locked`, `cargo test --locked`, and the controlled
  deployment verification appropriate to the change before advancing a phase.
- Keep the existing loopback-only listeners private until the Rustls ingress
  passes its test and deployment gates.

## Phase 1 — Design and test the Rustls private ingress

**Status:** implemented

**Source of truth:** [Rustls private ingress plan](../docs/plans/ingress/rustls-private-ingress.md)

- Add typed ingress configuration and test-only certificate fixtures.
- Define TLS 1.3, mTLS, API-key, ALPN, timeout, handshake-capacity, and
  certificate-rotation requirements.
- Add deterministic tests for trusted/untrusted client certificates, malformed
  certificate material, and unsupported protocol negotiation.

**Gate:** TLS configuration is validated by tests without opening a public
listener.

## Phase 1A — Make shutdown production-grade

**Status:** planned

The current bounded shutdown prevents Pingora's default five-minute grace
period from overrunning the local deployment runner, but it is not the final
production lifecycle. Complete this phase before relying on graceful shutdown
for deployments with active requests or long-lived `CONNECT` tunnels.

### Lifecycle and shutdown ordering

- Define explicit `accepting`, `draining`, `stopping`, and `terminated` states,
  and make every shutdown transition idempotent.
- On `SIGTERM`, mark the instance unready and stop accepting new public
  connections before beginning the drain period.
- Stop allocating new tunnel, circuit-build, and connection permits once
  draining starts.
- Keep the internal Tor bridge available long enough for already-accepted
  Pingora HTTP requests to finish opening or using their existing bridge
  connections; close the internal listener only after that work has drained.
- Stop the metrics listener at the documented point in the sequence while
  retaining enough shutdown telemetry for the supervisor or log collector to
  determine the outcome.
- Remove the Unix bridge socket only after its listener is closed, and make
  cleanup safe when startup was partial or shutdown is requested more than
  once.

### Task ownership and bounded draining

**Status:** implemented; retain the verification work below as an ongoing
regression requirement.

- Replace detached connection tasks with an owned task registry such as
  `JoinSet`, `TaskTracker`, or an equivalent structured-concurrency mechanism.
  Track public ingress, internal bridge, metrics, Tor connection attempts, and
  active tunnel-copy tasks.
- Allow tracked requests and tunnels to complete naturally during a
  configurable drain period. Choose and document a production default based on
  measured workloads, initially evaluating a 30-120 second range rather than
  the current one-second test-oriented value.
- At the drain deadline, cancel or abort only the remaining tracked tasks,
  close their streams, release all admission permits, and wait for task
  termination within a separate bounded force-stop timeout.
- Preserve tunnel half-close behavior during natural draining and distinguish
  completed, deadline-cancelled, and failed tunnels in privacy-safe metrics and
  structured logs.
- Do not report a successful bridge shutdown until all tracked tasks have
  completed or the forced-stop result has been recorded.

### Runtime and signal handling

- Replace the final unconditional `run_forever()` process exit with a lifecycle
  that returns control to `main`, drops all Arti client clones, and explicitly
  shuts down the dedicated Arti Tokio runtime with a bounded timeout.
- Define and document signal behavior: `SIGTERM` starts graceful draining,
  `SIGINT` requests a fast local shutdown, and a second termination signal
  escalates an in-progress drain without leaving tasks or sockets behind.
- Make the drain period, force-stop timeout, and Arti runtime timeout typed
  deployment configuration rather than hard-coded constants.
- Configure systemd, containers, and deployment runners so their stop timeout
  exceeds the application's complete drain budget by a documented safety
  margin. A test harness deadline must not dictate an unsafe production drain
  period.
- Ensure normal graceful termination exits with status zero, while startup
  failure, runtime failure, forced deadline expiry, and external `SIGKILL`
  remain distinguishable.

### Observability and operations

- Expose privacy-safe shutdown phase, active tracked task count, drain duration,
  naturally completed task count, forced cancellation count, and Arti runtime
  shutdown outcome.
- Emit one structured event for shutdown start and one final event containing
  the terminal phase and result; never include destinations, isolation
  identities, credentials, or client addresses.
- Add a runbook covering normal deploys, rollback, stuck drains, repeated
  signals, supervisor timeout selection, verification of released ports and
  sockets, and recovery after a forced stop.

### Verification matrix

- Add deterministic tests for every lifecycle transition, repeated shutdown
  requests, task registration races, permit release, listener closure, Unix
  socket cleanup, and deadline cancellation.
- Add subprocess tests that send `SIGTERM` to the exact release-binary PID and
  verify a zero exit status without `SIGKILL`.
- Verify shutdown with no traffic, an ordinary HTTP request, an active
  `CONNECT` tunnel that completes inside the drain window, and an intentionally
  stuck tunnel that is cancelled only after the deadline.
- Verify that new public connections are rejected after draining begins while
  already-accepted HTTP and tunnel work can complete.
- Verify that ports and the Unix socket can be reclaimed immediately by a new
  instance, no task or child process survives, and repeated start/stop cycles do
  not leak file descriptors, memory, permits, or Arti background work.
- Exercise supervisor-driven shutdown on the target Linux environment and
  retain timestamps, final events, exit status, and process/socket ownership as
  deployment evidence.

**Gate:** the exact release binary passes the complete shutdown matrix on the
target Linux host; normal `SIGTERM` exits within the configured budget without
`SIGKILL`, active work either drains or is classified at the deadline, the Arti
runtime terminates explicitly, and a replacement instance can immediately bind
all required listeners and the Unix socket.

## Phase 2 — Implement authenticated private ingress

**Status:** implemented in the runtime; controlled deployment verification pending
**Source of truth:** [Rustls private ingress plan](../docs/plans/ingress/rustls-private-ingress.md)

- Add Rustls/Tokio-Rustls around the public ingress while keeping the current
  CONNECT/Tor bridge behavior.
- Bound TLS handshakes and first-request reads independently from active tunnel
  and circuit-build capacity.
- Require mTLS plus `Proxy-Authorization` before allocating isolation or opening
  a Tor stream.
- Scope session isolation and upstream pooling by authenticated account and
  workspace; strip internal/credential headers before origin forwarding.

The production runtime now loads explicit TLS/account configuration, bounds
handshakes and first headers separately, requires a trusted client
certificate plus matching API-key scope, and carries an opaque authenticated
lease through `RequestCtx` and the internal hops. The default development
listener remains plaintext but is restricted to loopback.

**Gate:** TLS-protected ordinary HTTP and HTTPS CONNECT pass the controlled
matrix; plaintext access and unauthenticated access cannot reach Tor.

## Phase 3 — Apply account abuse controls and operational observability

**Status:** partially implemented

- Add per-account rate and concurrent-tunnel limits, revocation, and bounded
  usage accounting.
- Preserve low-cardinality, privacy-safe metrics and structured logs.
- Add certificate reload/rotation, health checks, and an alerting strategy.
- Keep the metrics and administrative interfaces private.

Per-account request rate, concurrent-tunnel admission, credential revocation,
atomic request-quota admission, and aggregate request/byte usage writes are now
connected to production ingress. The single-tier runtime now also enforces an
account-wide live byte cap across workspaces and checkpoints active usage every
MiB or five seconds. Cross-process quota coordination, certificate
reload/rotation, operational health checks, alerting, and the controlled
deployment matrix remain open.

**Gate:** suspension, quota, slow-handshake, slow-header, and capacity tests
fail predictably without a direct-egress path or unbounded resources.

## Phase 4 — Separate egress and enforce the firewall boundary

**Status:** planned  
**Source of truth:** [Firewall egress-hardening plan](../docs/plans/firewall/egress-hardening.md)

- Establish separate non-root identities for ingress/proxy and Arti.
- Move Arti behind a private local protocol and prove that the proxy has no
  direct Internet or DNS egress.
- Add reviewed host firewall policy, systemd hardening, safe activation, and
  rollback procedures.
- Keep all internal ports inaccessible from the public network.

**Gate:** packet capture and the documented firewall verification matrix prove
Tor-only egress for both IPv4 and IPv6, including failure and reboot cases.

## Phase 5 — Production proof and controlled rollout

**Status:** planned

- Run the exact release binary through the full deployment and controlled-origin
  matrix on the target host.
- Verify certificate reload, client/API-key revocation, Arti outage/recovery,
  restart, backup/restore of account data, and rollback.
- Operate a small, verified-customer pilot before opening any broader service.

**Gate:** retained evidence shows every documented acceptance criterion passed;
product claims are limited to measured, controlled results.

## Experimental phases — not on the production critical path

Experimental phases may depend on production components, but they do not relax,
replace, or block the gates above. They must remain disabled in normal
deployments until their own security and leak-testing gates pass.

### Experimental Phase E1 — macOS TCP-over-Tor client

**Status:** planned; experimental

**Prerequisites:** Complete the Phase 2 authenticated private-ingress gate
before connecting a macOS client to this service. Complete the relevant Phase 3
account controls before any external pilot.

#### Goal and supported traffic

- Provide a macOS Network Extension that captures application TCP flows and
  forwards them through the authenticated private ingress, Arti, and a Tor
  circuit.
- Treat this as a TCP-only, VPN-like client. Do not describe it as a general IP
  VPN or claim support for arbitrary `utun` traffic.
- Support IPv4 and IPv6 TCP destinations without locally resolving destination
  hostnames when the original hostname is available.
- Explicitly reject or contain unsupported UDP, QUIC, ICMP, multicast, and raw
  IP traffic. Unsupported traffic must never silently bypass the tunnel.
- Do not intercept destination TLS or install a destination-signing CA. The
  client transports application TCP; end-to-end TLS remains between the
  application and its destination.

#### Proposed data path

```text
macOS application TCP flow
  -> Network Extension flow provider
  -> bounded per-flow adapter
  -> mTLS HTTP CONNECT to the private ingress
  -> authenticated account/workspace isolation
  -> Arti TCP stream
  -> Tor circuit
  -> destination
```

The preferred first implementation is a flow-oriented Network Extension such
as `NEAppProxyProvider`, or `NETransparentProxyProvider` where its routing
semantics are required and demonstrably fail closed. Each accepted
`NEAppProxyTCPFlow` maps to one independently authenticated CONNECT tunnel.

#### Track A — Flow-provider proof of concept

1. Create a minimal signed macOS host application and Network Extension target.
   Document the required Network Extension entitlement, supported macOS
   versions, provisioning method, installation path, and whether the intended
   distribution channel permits the selected provider type.
2. Define a small Rust flow service with explicit request, established,
   draining, failed, and closed states. Keep Apple framework integration at a
   narrow Swift or Objective-C boundary if direct Rust bindings make lifecycle
   correctness or platform review harder.
3. Establish TLS 1.3 with server verification and the Phase 2 mTLS plus
   `Proxy-Authorization` contract. Store client keys and API credentials in the
   Keychain; never place them in preferences, logs, crash metadata, or command
   lines.
4. Map one accepted TCP flow to one HTTP/1.1 CONNECT request. Carry the original
   hostname to the proxy when available so resolution occurs through Arti.
   Preserve already-buffered application bytes and TCP half-close behavior in
   both directions.
5. Add bounded connect, TLS-handshake, authorization, first-response, idle, and
   total setup deadlines. Apply separate limits to pending handshakes, pending
   Tor circuits, established flows, and buffered bytes.
6. Use Tower only at the flow-service boundary for admission, concurrency,
   readiness, load shedding, deadlines, cancellation, and privacy-safe
   instrumentation. Tower is not a TUN or TCP/IP implementation.
7. Keep Hyper optional. Introduce it only if it materially improves correctness
   of the CONNECT client or a later multiplexed ingress protocol; do not require
   a server-side HTTP rewrite for this experiment.
8. Exclude the private-ingress control connection and required Network
   Extension management traffic from capture so the provider cannot recursively
   tunnel its own connection.

#### DNS, routing, and fail-closed policy

- Prefer destination hostnames supplied by Network Extension flow metadata and
  resolve them through the proxy/Arti path.
- Intercept, synthesize, or block DNS paths that would otherwise use local UDP.
  Define behavior for applications that provide only an IP address without
  inventing a hostname or performing a local reverse lookup.
- Disable direct fallback when authentication, TLS, the proxy, Arti, or the Tor
  circuit is unavailable. A provider error or restart must not change protected
  flows to direct connections.
- Block UDP/443 where necessary so QUIC cannot bypass policy and applications
  can retry over TCP. Do not claim UDP support merely because an Apple provider
  exposes UDP flow APIs.
- Cover IPv4 and IPv6 equally. A blocked IPv4 path with an unprotected IPv6
  fallback, or the reverse, fails the gate.
- Re-evaluate routes on Wi-Fi/cellular changes, captive portals, sleep/wake,
  interface replacement, and proxy address changes without briefly enabling a
  direct path.

#### Ownership, draining, and observability

- Own every accepted flow and copy task with structured concurrency; do not
  detach per-flow work.
- On provider stop, reject new flows, naturally drain existing flows within a
  configured budget, then cancel and join the remainder within a separate
  force-stop budget.
- Propagate cancellation through Network Extension, TLS, CONNECT, and copy
  layers. Release admission permits and close both sides even when startup was
  partial.
- Emit low-cardinality metrics for provider state, active and pending flows,
  setup outcome, bounded-buffer pressure, natural drain completion, forced
  cancellation, and unsupported-protocol rejection.
- Never log destination hostnames or addresses, DNS names, client addresses,
  account secrets, certificate material, application identity, or byte
  contents. Any application-level attribution must be explicitly justified and
  disabled by default.

#### Track B — Raw `utun`/packet-tunnel research

Do not begin this track merely because Darwin exposes `utun`. Start it only if
Track A cannot satisfy a documented routing requirement.

- Prototype through `NEPacketTunnelProvider` and `NEPacketTunnelFlow` rather
  than relying on an undocumented direct kernel-control contract.
- Treat packets from the virtual interface as raw IPv4/IPv6 packets. Budget for
  a maintained userspace TCP/IP stack, TCP reassembly and retransmission,
  fragmentation and path MTU, IPv6, DNS, routing-loop prevention, bounded
  buffering, and clean shutdown.
- Translate reconstructed TCP connections into authenticated CONNECT/Tor
  streams. Do not send raw packets to Arti: Arti supplies anonymized TCP
  streams, not a general IP transport.
- Keep the BoringTun comparison architectural only. WireGuard encapsulates IP
  to a remote peer over UDP; adding BoringTun would still require a trusted
  tunnel server and a separate IP/TCP-to-Tor translator. Normal IP forwarding
  at that server would bypass Tor.
- Reject the track if its TCP/IP dependency cannot be audited, bounded, tested
  on supported macOS releases, and maintained without weakening the
  fail-closed policy.

#### Experimental verification gate

- Unit-test flow state transitions, authority parsing, authentication
  redaction, timeout classification, bounded buffering, half-closes,
  cancellation, repeated provider-stop events, and route-exclusion logic.
- Integration-test ordinary HTTP, HTTPS over CONNECT, hostname-based remote DNS,
  IPv4, IPv6, concurrent flows, long-lived flows, proxy refusal, invalid mTLS,
  revoked credentials, Arti outage, Tor timeout, and private-ingress restart.
- Attempt UDP DNS, DNS-over-HTTPS, QUIC, ICMP, local-network access, IPv4/IPv6
  fallback, captive-portal probes, and direct sockets while the tunnel is
  starting, healthy, draining, failed, and restarting. Retain packet-capture
  evidence that protected traffic never exits directly.
- Test install, enable, disable, upgrade, uninstall, crash recovery, sleep/wake,
  interface changes, and repeated start/stop cycles on every supported macOS
  release. Verify that no extension process, route, flow, task, credential, or
  virtual interface remains orphaned.
- Verify destination-observed egress independently without hard-coding a public
  third-party test target into the client or test harness.

**Gate:** a locally signed proof of concept carries supported TCP traffic
through the authenticated ingress and Tor, fails closed for unsupported or
failed paths, leaks neither DNS nor IPv4/IPv6 traffic in the documented packet
capture matrix, and shuts down without orphaned flows or routes. Passing this
gate authorizes only a controlled experimental pilot; it does not make the
client or the proxy a general-purpose VPN.

## Deferred work — Explicitly separate projects

- Replacing the hand-written HTTP ingress with Hyper/Hyper Util/Tower.
- Replacing embedded Arti with an external Arti process or another Tor client.
- HTTP/2, HTTP/3, QUIC transport, general transparent proxying beyond the
  macOS experiment, destination TLS interception, or onion-service ingress.
- Multi-region deployment, public free tiers, and broad self-service onboarding.

Each deferred item needs its own plan and test matrix. It must not be silently
folded into the private-ingress or firewall phases.
