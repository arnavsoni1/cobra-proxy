# Markdown implementation and conflict audit

**Date:** 2026-08-09

**Status:** Current repository snapshot

**Scope:** Every project-authored Markdown file present before this audit,
including ignored files under `src/`

## Result

The repository has a substantial implemented core, but several planning files
still describe older architecture or a different commercial model as if it
were current. The implementation is internally consistent at the application
layer: protected traffic is opened through embedded Arti, there is no direct
destination fallback, and libp2p is not a dependency. That is not yet proof of
a host-level egress kill switch or a production deployment.

This audit treats executable code, locked tests, and deployment configuration
as evidence of what exists. It treats plans as proposed work even when their
introductory prose is written in the present tense. It does not revalidate the
external legal or licensing sources linked from the README.

## Implemented inventory

### Tor data path and proxy behavior

- Embedded Arti bootstrap and destination stream creation are implemented in
  `TorCircuit` and `Bridge::connect_with_retry`.
- The only application-level destination connection path found uses Arti.
  There is no direct-connect or libp2p fallback.
- HTTPS `CONNECT` parsing, bounded headers, preservation of bytes received
  after the header, ordinary HTTP forwarding through Pingora, and the protected
  Unix bridge are implemented.
- A `200 Connection Established` response is sent only after an Arti stream is
  open. Established tunnels remain opaque and destination TLS is not
  intercepted.
- Destination validation, local/private-address blocking, remote Tor DNS,
  session isolation, pool partitioning, and removal of internal isolation
  headers are implemented.

### Capacity, recovery, cache, and lifecycle

- Bounded public connections, internal connections, connection tasks, active
  tunnels, and circuit builds are implemented with semaphores and deadlines.
- Connection establishment has a total deadline, one bounded retry with
  backoff and permitted isolation rotation, and a bounded destination circuit
  breaker.
- Ordinary HTTP caching has byte and object limits plus cacheability policy.
  CONNECT tunnels are not decrypted or cached.
- Bridge-owned tasks are tracked and have bounded drain and forced-stop
  behavior. The complete process lifecycle is not finished: `main` still ends
  in Pingora's unconditional `run_forever()`, and the dedicated Arti runtime is
  not explicitly shut down.

### Private ingress, accounts, and metering

- Development loopback ingress and authenticated production ingress are
  separate typed modes.
- The production path implements native Rustls TLS 1.3, required mTLS, API-key
  authorization, ALPN `http/1.1`, certificate/key validation, file-permission
  checks, handshake capacity, and first-request deadlines.
- SQLite account, workspace, limit, API-key, device-credential, and usage-period
  tables are implemented.
- API keys are stored as keyed BLAKE3 digests and compared in constant time.
  Account/workspace state, key rotation and revocation, device fingerprint
  scope, per-account request rates, tunnel limits, and byte/request quotas are
  enforced.
- Tunnel usage is checkpointed while a connection is active as well as at
  teardown, rather than only being aggregated after close.

### Observability and verification support

- Privacy-bounded structured events, in-process counters, and a loopback
  Prometheus endpoint are implemented.
- Linux deployment and bounded stress scripts, native macOS and Windows helper
  scripts, and an Ubuntu GitHub Actions workflow exist.
- On this snapshot, `cargo check --locked` passed, `cargo test --locked` passed
  with **81 passed, 0 failed, and 2 ignored**, and
  `cargo build --release --locked` passed with seven existing unused/dead-code
  warnings.

These local results do not prove live Tor behavior, firewall containment,
certificate rotation, supervisor integration, a deployed VPS/appliance, or
customer-visible performance.

## Remaining or deliberately absent work

- No libp2p dependency, peer network, custom peer routing, or libp2p alert path
  exists. This is intentional under the current adoption decision.
- A dedicated active-tunnel termination taxonomy and private out-of-band alert
  delivery are not implemented. Current stream failures close the affected
  tunnel and contribute only coarse observations.
- The external-Arti connector boundary, separate operating-system identities,
  systemd units, nftables/network-namespace policy, packet-capture proof, and
  host-level kill switch in the egress plan are not implemented.
- Live certificate reload, trust-overlap rotation, and controlled production
  ingress verification remain open.
- Full signal-driven process draining and explicit Arti runtime shutdown remain
  open even though bridge task ownership is implemented.
- SQLCipher or documented disk encryption, backups, Stripe integration,
  invoices, customer dashboard, production admin CLI, notification delivery,
  support policies, and a production supervisor are not implemented.
- The macOS Network Extension, tunnel provider, DNS strategy, packaging, and
  Apple entitlement work remain plans only.
- `src/request_scheduler.rs` contains an isolated scheduler and three tests, but
  the module is not declared by the crate. Its tests therefore are not part of
  the reported Cargo test run; the active admission implementation lives in
  `src/main.rs`.

## Conflict ledger

| ID | Severity | Conflicting points | Current resolution or required action |
|---|---|---|---|
| C1 | High | `README.md` describes a single private Linux VPS and hosted/managed terms; `PAID_PLAN.md` assumes a hosted free tier and centralized billing; the current decision assumes one customer-local appliance per customer. | Treat one private, locally operated appliance per customer and no public free tier as current. Rewrite pricing, billing, deployment, and legal text together before choosing another model. |
| C2 | High | `README.md` says the original core is proprietary, while `PAID_PLAN.md` proposes open-sourcing the core and monetizing the hosted layer. | Proprietary core is current. Open sourcing requires a separate explicit licensing decision. |
| C3 | High | `PAID_PLAN.md` asks for account, timestamp, destination host, and byte logs; `README.md`, `TESTING_GUIDELINES.md`, the ingress plan, and the firewall plan prohibit account and destination identifiers in default telemetry. | Keep default operational telemetry privacy-bounded. Define any legally or operationally required audit store separately, with purpose, access, fields, encryption, retention, and deletion reviewed before implementation. |
| C4 | High | The firewall plan's target diagram places Caddy/nginx at public TLS ingress, while the implemented ingress and the Rustls plan use native Rustls with mTLS and API-key authorization. | Native Rustls is the current ingress. Caddy/nginx is not part of the architecture unless a later decision replaces or fronts it and repeats the trust-boundary review. |
| C5 | High | Some prose calls the proxy fail closed, but the firewall plan correctly requires operating-system enforcement and packet-capture evidence. | Current proof is application-level only: code has no direct destination fallback. Do not claim host-level leak prevention until the firewall/namespace plan is implemented and independently verified. |
| C6 | Medium | `PAID_PLAN.md` calls per-domain Tor isolation the entire differentiator versus Tor/VPN products. The README and current product reasoning treat isolation as an implementation mechanism, not a novel Tor primitive or complete value proposition. | Position the product around a managed policy boundary, authenticated isolation, controls, evidence, and operations; do not claim ownership of the underlying Tor isolation concept. |
| C7 | Medium | The ingress plan says phases 1-4 are implemented, but its "current state" and inventory still describe a plaintext-only public path and older `main.rs` line numbers. | Retain its acceptance criteria, but mark the plaintext section as historical and regenerate the implementation inventory before using it for new work. |
| C8 | Medium | `FIX_PLAN.md` presents resolved raw-CONNECT, cache, isolation, admission, retry, breaker, and metrics defects as current failures. | Treat phases 1-5 as implemented historical remediation. Phase 6 remains an evidence gate, not proof that controlled live tests were run. |
| C9 | Medium | `SCHEDULER.md` describes `MemoryCache` token storage, one VPS, log-only metrics, and no metrics endpoint. Current code uses a dedicated isolation store, broader admission controls, and Prometheus. | Treat the document as the historical rationale for circuit-build semaphore Option A, not a current component specification. |
| C10 | Medium | `src/AGENTS.md` says all development must remain in `main.rs`, points to an empty architecture file, says warnings may be ignored, and forbids commits. Current code has supported modules, verification records warnings, and repository work requires intentional commits. | The file is ignored and is not a durable source of truth. Remove or rewrite it before relying on repository-local agent instructions. |
| C11 | Medium | Roadmap Phase 1A correctly says full shutdown is planned, while broader "graceful shutdown" wording can be read as complete. | Distinguish implemented bridge task draining from the unimplemented process/signal/Arti-runtime lifecycle. |
| C12 | Low | `README.md` records 75 passing tests and a 20 July 2026 review date; the current locked run has 81 passing and 2 ignored, and later ingress/account work is documented. | Replace hard-coded counts with the latest evidence or a dated evidence link. Refresh the document status when the README is next reconciled. |
| C13 | Low | The firewall document is titled a runbook but identifies itself as an implementation plan and lives under `docs/plans/`. | Keep it classified as a plan until its commands, ownership, verification, and rollback have been exercised on the target environment. Rename it or reserve the runbook label for the verified artifact. |
| C14 | Low | `src/ARCHITECTURE.md` and `src/SKILLS.md` are empty and ignored, even though `src/AGENTS.md` refers to the former as required context. | Either create reviewed, tracked content under `docs/architecture/` or remove the dead references; do not treat empty ignored files as governance. |

## Per-document reconciliation

| Markdown file | Reconciliation |
|---|---|
| [`README.md`](../../README.md) | Best broad current-state description. Runtime, security-boundary, cache, metrics, and known-limit claims largely match code. Product model, test count, and review date need reconciliation under C1, C5, and C12. |
| [`FIX_PLAN.md`](../../FIX_PLAN.md) | Phases 1-5 are now implemented. Phase 6's deterministic tooling exists, but live controlled evidence is not established by this audit. Its opening defect table is historical (C8). |
| [`PAID_PLAN.md`](../../PAID_PLAN.md) | Account/auth/rate/metering/Rustls checkboxes are substantially implemented. Storage operations, billing, dashboard, policies, and production operations remain open. Its product, licensing, telemetry, and value-proposition sections conflict under C1-C3 and C6. |
| [`SCHEDULER.md`](../../SCHEDULER.md) | The chosen global circuit-build semaphore behavior is implemented, with additional tunnel and connection admission. Internal implementation and observability prose is stale (C9). |
| [`TESTING_GUIDELINES.md`](../../TESTING_GUIDELINES.md) | Closest current verification source. Script interfaces and local test workflow match the repository. It correctly states that smoke, stress, and unit results are not live deployment or performance proof. |
| [`docs/README.md`](../README.md) | Navigation and lifecycle rules are current after this audit adds decisions and audits. |
| [`docs/decisions/libp2p-adoption-boundary.md`](../decisions/libp2p-adoption-boundary.md) | Matches the current dependency graph and Tor-stream limitation. libp2p is intentionally absent; alert taxonomy and delivery are recorded as future work. |
| [`docs/plans/ingress/rustls-private-ingress.md`](../plans/ingress/rustls-private-ingress.md) | Phases 1-4 match implemented modules and tests. Controlled deployment, reload/rotation, and operations remain open; the old plaintext inventory conflicts with its own status (C7). |
| [`docs/plans/firewall/egress-hardening.md`](../plans/firewall/egress-hardening.md) | Almost entirely unimplemented future work. It defines the missing host-level evidence gate, but its public-ingress topology and runbook label conflict under C4, C5, and C13. |
| [`src/ROADMAP.md`](../../src/ROADMAP.md) | Most status labels match code: ingress/account foundations implemented, deployment verification pending, commercialization partial, firewall and macOS planned. Full lifecycle work remains open under C11. |
| `src/AGENTS.md` | Ignored local guidance, not tracked documentation. It conflicts with current repository structure and workflow under C10. |
| `src/ARCHITECTURE.md` | Empty and ignored; it supplies no architecture evidence (C14). |
| `src/SKILLS.md` | Empty and ignored; it supplies no project guidance (C14). |

Cargo generated two identical 482-line `rust_decimal` README copies below
`target/debug/build/` and `target/release/build/`. They were inspected but are
third-party build output, not project-authored documentation or a source of
proxy requirements. They should remain excluded from documentation governance.

## Recommended reconciliation order

1. Resolve C1-C4 together in `README.md` and `PAID_PLAN.md`: deployment model,
   source model, telemetry, and ingress topology affect every commercial and
   privacy promise.
2. Keep all production fail-closed wording qualified as application-level
   until C5's host controls and evidence exist.
3. Mark `FIX_PLAN.md`, `SCHEDULER.md`, and the old inventory sections of the
   ingress plan as historical so they cannot be mistaken for current design.
4. Replace the ignored `src/` governance placeholders with tracked material
   only when there is reviewed content to preserve.
5. Run the controlled deployment matrix and attach its evidence before changing
   any "verification pending" status.
