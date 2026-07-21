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

**Status:** planned  
**Source of truth:** [Rustls private ingress plan](../docs/plans/ingress/rustls-private-ingress.md)

- Add typed ingress configuration and test-only certificate fixtures.
- Define TLS 1.3, mTLS, API-key, ALPN, timeout, handshake-capacity, and
  certificate-rotation requirements.
- Add deterministic tests for trusted/untrusted client certificates, malformed
  certificate material, and unsupported protocol negotiation.

**Gate:** TLS configuration is validated by tests without opening a public
listener.

## Phase 2 — Implement authenticated private ingress

**Status:** planned  
**Source of truth:** [Rustls private ingress plan](../docs/plans/ingress/rustls-private-ingress.md)

- Add Rustls/Tokio-Rustls around the public ingress while keeping the current
  CONNECT/Tor bridge behavior.
- Bound TLS handshakes and first-request reads independently from active tunnel
  and circuit-build capacity.
- Require mTLS plus `Proxy-Authorization` before allocating isolation or opening
  a Tor stream.
- Scope session isolation and upstream pooling by authenticated account and
  workspace; strip internal/credential headers before origin forwarding.

**Gate:** TLS-protected ordinary HTTP and HTTPS CONNECT pass the controlled
matrix; plaintext access and unauthenticated access cannot reach Tor.

## Phase 3 — Apply account abuse controls and operational observability

**Status:** planned

- Add per-account rate and concurrent-tunnel limits, revocation, and bounded
  usage accounting.
- Preserve low-cardinality, privacy-safe metrics and structured logs.
- Add certificate reload/rotation, health checks, and an alerting strategy.
- Keep the metrics and administrative interfaces private.

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

## Deferred work — Explicitly separate projects

- Replacing the hand-written HTTP ingress with Hyper/Hyper Util/Tower.
- Replacing embedded Arti with an external Arti process or another Tor client.
- HTTP/2, HTTP/3, QUIC, transparent proxying, destination TLS interception, or
  onion-service ingress.
- Multi-region deployment, public free tiers, and broad self-service onboarding.

Each deferred item needs its own plan and test matrix. It must not be silently
folded into the private-ingress or firewall phases.
