# Testing Coverage and Security Gap Audit

- **Audit date:** 2026-08-24
- **Scope:** Current working tree, including uncommitted changes
- **Purpose:** Explain what the repository's test runners actually prove, what
  they do not prove, and which tests should be added before production or scale
  claims are made.

This is a test-plan and coverage audit. It does not claim that the proposed
tests exist, that the target host is hardened, or that a production deployment
has passed them.

## Evidence reviewed

The audit covers:

- [`test-proxy-unix.sh`](../../test-proxy-unix.sh), plus the Linux and macOS
  wrappers.
- [`test-proxy-windows.ps1`](../../test-proxy-windows.ps1) and its CMD wrapper.
- [`stress-test.sh`](../../stress-test.sh).
- [`test-deployment.sh`](../../test-deployment.sh).
- [Linux CI](../../.github/workflows/linux.yml).
- The registered Rust tests in `src/main.rs`, `src/account_management.rs`, and
  `src/private_ingress.rs`.
- The test and security boundaries documented in
  [`TESTING_GUIDELINES.md`](../../TESTING_GUIDELINES.md),
  [`src/ROADMAP.md`](../../src/ROADMAP.md), and the cache, destination, ingress,
  and firewall plans under `docs/plans/`.

Checks run while writing this audit:

- `cargo test --locked`: **87 passed, 0 failed, 2 ignored**.
- `cargo test --locked -- --list`: **89 registered tests**.
- Bash syntax parsing for all five shell runners: passed.

The live smoke, deployment, production-mTLS, macOS, Windows, firewall, scale,
and failure-injection matrices were not run as part of this documentation
audit. Those remain environment-specific evidence gates.

## Executive result

The repository has useful deterministic coverage for account authentication,
mTLS configuration, isolation, quotas, tunnel copying, shutdown bookkeeping,
cache policy, and metrics. The deployment runner also exercises a good
single-process functional path and retains evidence.

The largest gap is between **application logic tests** and **production
security proof**. The current scripts do not prove:

- The proxy process is unable to bypass Tor using direct IPv4, IPv6, or DNS.
- The current destination policy prevents port abuse and all alternate local
  address encodings.
- Real production certificates, API keys, revocation, rotation, and account
  limits work on the deployed host under adversarial conditions.
- Cache data and cold-fetch locks remain isolated across accounts, workspaces,
  isolation subdivisions, rotations, and concurrent bursts in a live service.
- Capacity, latency, resource bounds, fairness, or stability at sustained load.
- Multi-process or multi-host correctness, rolling deployment, failover,
  backup/restore, reboot ordering, or rollback.
- Metrics, internal listeners, logs, and test artifacts remain private in the
  deployed network and filesystem environment.

A green current suite supports a **single-process functional claim**. It is not
yet enough for a production-security, anonymity, high-availability, or scale
claim.

## Current runner inventory

### Unix smoke runners

Files:

- [`test-proxy-linux.sh`](../../test-proxy-linux.sh)
- [`test-proxy-macos.sh`](../../test-proxy-macos.sh)
- [`test-proxy-unix.sh`](../../test-proxy-unix.sh)

What they cover:

1. Reject running the Linux wrapper on macOS or the macOS wrapper on Linux.
2. Check for `cargo` and `curl`.
3. Run the locked compiler check, normal deterministic tests, and release build.
4. Start the release binary in development mode.
5. Wait for TCP port `127.0.0.1:8080`.
6. Send one HTTPS request through the proxy to Tor Check.
7. Require `"IsTor": true`.
8. Require a later scheduler log sample showing at least one completed circuit
   attempt and no permit held at sample time.
9. Stop the test-owned process and delete temporary logs.

What they miss:

- Production TLS, mTLS, API-key authentication, revocation, quota, and rate
  controls.
- Plain HTTP, cache behavior, destination rejection, malformed requests, and
  concurrency.
- A controlled origin; Tor Check is an external availability dependency.
- Retained evidence and structured machine-readable results.
- A bounded cleanup deadline. `kill` followed by `wait` can hang if shutdown
  regresses.
- Host service-manager behavior, filesystem ownership, non-root execution,
  firewall policy, or external port exposure.
- Proof that every outbound path uses Tor. One successful Tor Check request
  does not exclude a different direct-egress path.

### Windows compatibility runner

Files:

- [`test-proxy-windows.ps1`](../../test-proxy-windows.ps1)
- [`test-proxy-windows.cmd`](../../test-proxy-windows.cmd)

What it is designed to cover:

- Native Windows check, tests, release build, process startup, one Tor Check
  request, scheduler-log detection, and cleanup.
- A specific explanation when compilation fails because the current internal
  bridge uses Unix sockets and `/tmp/proxy-bridge.sock`.

Current evidence boundary:

- Native Windows is not a supported runtime path in the current architecture.
  This runner is primarily an early compatibility detector until the Unix
  bridge dependency is replaced or abstracted.
- It is not run by CI, has no retained evidence, force-stops the process, and
  has no production-ingress or security-negative matrix.

### Bounded stress runner

File: [`stress-test.sh`](../../stress-test.sh)

What it covers:

1. Positive-integer and maximum-load argument validation.
2. A safety ceiling of 512 requests and 64 concurrent workers unless an
   explicit override is supplied.
3. The `circuit_`-filtered deterministic tests unless skipped.
4. Locked check and release build when it owns the proxy.
5. Local startup or reuse of a running proxy.
6. Batches of independent curl processes up to the configured concurrency.
7. Classification into successful `2xx/3xx`, HTTP `503`, and other failures.
8. Detection of a proxy process that exits during the request phase.
9. A scheduler-log sample when the runner owns the process.

What it does **not** currently provide:

- A capacity benchmark. It has no target throughput or latency SLO.
- Sustained concurrency. It uses a batch barrier: the next batch starts only
  after every worker in the current batch finishes.
- Ramp, constant-rate, spike, soak, or recovery workloads.
- Latency percentiles, connect/TLS timings, requests per second, or byte
  throughput.
- CPU, memory, file-descriptor, socket, Tokio-task, or host-network measurements.
- Large uploads/downloads, long-lived CONNECT tunnels, half-closed tunnels,
  connection reuse, or mixed destination behavior.
- Multiple accounts, workspaces, isolation modes, or fairness assertions.
- Production mTLS and API-key input comparable to the deployment runner's curl
  config.
- A controlled origin requirement. The default targets `example.com` through
  the public Tor network.
- Retained per-request artifacts; the temporary result directory is always
  deleted.
- A success floor. A run in which every request returns `503` currently passes.
- Proof that a `503` came from controlled proxy admission rather than the origin
  or an unrelated intermediary.
- An assertion that observed completions equal the requested count.
- A required metrics delta or a required Tor Check result.

The script is useful for detecting crashes and unexpected status classes under
small bounded concurrency. It must not be used to state production capacity.

### Deployment end-to-end runner

File: [`test-deployment.sh`](../../test-deployment.sh)

What it covers well:

- Local build/start mode and running-deployment mode.
- Argument and URL-scheme validation.
- Locked check, deterministic tests, and release build in normal local mode.
- Preflight of local public and metrics ports.
- Metrics-based readiness and a basic Prometheus metric contract.
- Retained per-case logs, proxy logs, response samples, metric snapshots, PID,
  run log, and summary.
- Rejection of one loopback CONNECT target.
- Rejection of one malformed isolation identity.
- One session-isolated Tor Check request.
- One strict-isolation HTTPS request.
- One ordinary plain-HTTP request.
- Optional authenticated running-mode cache validation using identical bodies,
  a controlled-origin counter, a cache-hit metric increase, and removal of the
  client-visible cache-status header.
- Final metric activity and liveness checks.
- Bounded local shutdown followed by a forced stop if needed.

Important limitations:

- Local mode uses unauthenticated development ingress. It cannot prove the
  production mTLS/API-key/account boundary.
- Running mode can supply a successful production curl config, but does not run
  missing, invalid, revoked, suspended, expired, or rotated credential cases.
- The script describes the curl config as owner-only but checks only that it is
  readable. It does not enforce owner or mode and the file can contain private
  keys and API keys.
- The `metrics_path_scope` case proves that a non-`/metrics` path returns `404`.
  It does not prove that the metrics listener is private or blocked externally.
- Destination policy coverage is one literal: `127.0.0.1:443`.
- The optional cache case exercises only one authenticated scope twice. It does
  not prove cross-tenant, cross-workspace, rotation, strict-mode, stampede, TTL,
  stale, eviction, or malicious-exit isolation.
- Readiness proves that metrics respond, not that every security dependency is
  healthy.
- `deployment_survived` checks process existence and metrics availability; it
  does not repeat a Tor request after faults or load.
- A forced stop during cleanup emits a warning but does not fail a previously
  green functional matrix. Real graceful drain is therefore not an E2E gate.
- Local endpoint preflight covers ports 8080 and 9090, but not internal port
  8081 or the Unix socket.
- Running mode does not verify the binary checksum, source revision, effective
  configuration, service identity, or service-manager unit being tested.
- Metrics deltas on a shared instance can be caused by unrelated traffic.
- Artifact directories are not explicitly created with `0700` permissions.
  They can contain response bodies, headers, logs, metrics, and a Tor exit IP.
- There is no artifact redaction scan, retention limit, or secure deletion
  policy.

### Linux CI

File: [`.github/workflows/linux.yml`](../../.github/workflows/linux.yml)

What it covers:

- Ubuntu 24.04 checkout.
- A minimal stable Rust installation.
- Locked `cargo check --all-targets`.
- Locked `cargo test --all-targets`.
- Locked release build.
- Read-only repository contents permission, a 30-minute timeout, and
  cancellation of superseded runs.

What it misses:

- No live Tor, smoke, deployment, or controlled-origin job.
- No macOS or Windows matrix.
- No shell or PowerShell lint and no tests of the test runners themselves.
- No pinned Rust toolchain version; `stable` can change independently of code.
- No formatting or Clippy gate. Formatting first needs a deliberate baseline
  cleanup because the current source is not repository-wide rustfmt clean.
- No dependency vulnerability, license/policy, secret, or static-analysis gate.
- No sanitizer, Miri, concurrency-model, fuzz, property, or code-coverage job.
- No SBOM, release checksum/provenance, or reproducibility check.
- GitHub actions use version tags rather than immutable commit SHAs.

### Registered Rust tests

The normal locked suite currently runs 87 tests and ignores two opt-in tests.

Strong deterministic areas include:

- Account/API-key hashing, revocation, rotation, suspension, usage accounting,
  quotas, rate limits, concurrent-tunnel limits, database migration, and file
  permissions.
- Production configuration validation, TLS key/certificate loading, mTLS trust,
  TLS 1.3 HTTP/1.1 handshake, unsupported protocol rejection, handshake
  capacity, and slow-handshake timeout behavior.
- CONNECT parsing, pipelined bytes, ingress-header stripping, isolation
  validation/rotation/bounds, admission semaphores, circuit breaker behavior,
  tunnel flush/half-close/idle timeout, shutdown task draining, byte accounting,
  metric rendering, and metric path routing.
- Conservative cache configuration, scoped keys and locks, request/response
  admission, TTL cap, stale disablement, and cache-status stripping.

The two ignored tests are:

- A controlled-origin functional matrix requiring a separately running
  development proxy.
- An in-memory established-tunnel benchmark. It does not use Tor, a real
  network, production TLS, or a deployment host.

One important test-discovery issue remains: `src/request_scheduler.rs` contains
three tests, but the module is not declared by the crate. Those tests are not
part of the 89 registered tests. The active admission implementation is tested
inside `src/main.rs`, but the isolated scheduler file must either be wired in,
removed through an explicit decision, or excluded from coverage claims.

## Cross-suite coverage matrix

`Strong` means meaningful deterministic or live assertions exist. `Partial`
means only a narrow happy path or single fixture exists. `None` means the
current suite does not establish the property.

| Area | Rust tests | Smoke | Stress | Deployment E2E | Overall |
|---|---|---|---|---|---|
| Locked compile/test/release build | Strong | Strong | Partial | Strong in local mode | Strong on Linux |
| Plain HTTP forwarding | Partial | None | None by default | Strong happy path | Partial |
| HTTPS CONNECT through Tor | Partial transport logic | One request | Repeated requests | Session and strict happy paths | Partial |
| Tor-only egress / no direct fallback | Partial logic | None | None | None | None at host boundary |
| Isolation parsing and token semantics | Strong | None | None | One session and one strict path | Partial live proof |
| Production mTLS and API-key auth | Strong fixtures | None | None | One optional success path | Partial |
| Revocation, suspension, rotation | Strong logic | None | None | None | No live proof |
| Rate, tunnel, request, and byte quotas | Strong logic | None | Status-only overload | None | No live concurrency proof |
| Destination safety and port policy | Minimal | None | None | One loopback literal | Weak |
| Cache admission and scoped keys | Strong logic | None | None | One optional same-scope hit | Partial live proof |
| Cross-tenant cache isolation | Strong key distinction | None | None | None | No E2E proof |
| Metrics contract and privacy | Strong rendering | Log sample | Log sample | Contract and activity | Partial host privacy proof |
| Graceful shutdown and half-close | Strong deterministic | Cleanup only | Cleanup only | Bounded cleanup, not pass gate | Partial E2E proof |
| Crash/fault recovery | None | None | Process-exit detection | Basic survival only | None |
| Resource exhaustion / DoS | Some bounded components | None | Small request burst | None | Weak |
| Measured capacity and latency SLO | Local ignored microbenchmark | None | None | None | None |
| Soak and leak detection | None | None | None | None | None |
| Multi-process / multi-host scale | None | None | Running mode reaches one URL | One endpoint | None |
| Firewall, namespace, DNS leak, reboot | None | None | None | None | None |
| Backup, restore, rollback | Some DB persistence | None | None | None | None |
| Supply-chain and release provenance | None | None | None | None | Locked dependencies only |
| Linux platform | Strong | Manual | Manual | Manual | CI build/test only |
| macOS platform | Portable unit intent | Manual script | Possible manual | Possible manual | Not continuously proven |
| Windows platform | Known compile boundary | Manual detector | Unsupported | Unsupported | Not supported |

## Priority 0: security and release-blocking additions

These should be completed before a public or paid production-security claim.

### P0.1 Prove fail-closed Tor-only egress

Current gap:

- Embedded Arti and application logic make direct fallback unlikely, but the
  host does not yet provide retained proof that the proxy identity cannot use
  direct TCP, IPv4, IPv6, UDP DNS, TCP DNS, or a local DNS stub.

Add a privileged target-host test that:

1. Runs proxy and Arti under separate non-root identities.
2. Attempts controlled direct IPv4 and IPv6 connections as the proxy identity.
3. Attempts UDP/TCP DNS and local-stub resolution as that identity.
4. Confirms allowed HTTP and HTTPS still work through Arti.
5. Stops Arti and verifies requests fail closed without any destination or DNS
   packet from the proxy identity.
6. Restarts Arti and verifies bounded recovery.
7. Scans internal and metrics ports from an external network namespace/host.
8. Reboots the host and proves firewall ordering before service acceptance.
9. Records firewall counters and packet capture, not only curl failures.

Pass gate: no unauthorized packet is observed for either IP family, Tor traffic
still works, and policy survives reboot and rollback.

### P0.2 Complete adversarial destination-policy testing

Current gap:

- The runtime rejects common local literals but accepts arbitrary nonzero ports
  and accepts ordinary domain names without a configured port policy.
- The live runner tests only `127.0.0.1:443`.
- IPv4-mapped/compatible IPv6, translation prefixes, ambiguous numeric hosts,
  special-purpose ranges, SMTP ports, and parser edge cases are not covered by
  the active test matrix.

Add table-driven, property, fuzz, and E2E cases for:

- Ports `0`, `1`, `22`, `25`, `53`, `80`, `443`, `465`, `587`, `8080`, `8443`,
  `65535`, and `65536` under explicit allow/deny policy.
- Every denied IPv4/IPv6 range boundary.
- IPv4-mapped and compatible IPv6 spellings, NAT64/translation prefixes, zone
  identifiers, compressed/expanded/case variants, and trailing root dots.
- Decimal, octal-like, hexadecimal-like, and shortened numeric-host forms.
- Userinfo, whitespace, control bytes, bracket errors, duplicate authorities,
  and Host/absolute-URI disagreement.
- Public CONNECT, ordinary HTTP, and the internal bridge path, with a fake Tor
  connector proving rejected input never reaches cache, admission, breaker, or
  Arti.

Pass gate: only canonical approved targets can construct a Tor connection and
the evaluator never panics on arbitrary input.

### P0.3 Run a real production-ingress identity matrix

Add a target-host suite using ephemeral test accounts and certificates:

- Valid client certificate plus valid API key succeeds.
- Missing certificate, untrusted CA, expired/not-yet-valid certificate, wrong
  server name, unsupported protocol, and malformed TLS fail before proxy work.
- Missing, malformed, incorrect, revoked, and rotated API keys fail with the
  documented status.
- Certificate fingerprint and API-key device binding must select the same
  account/workspace.
- Suspended account/workspace and exhausted request/byte/tunnel limits fail.
- Rate-limit and quota counters remain atomic under concurrent connections.
- Slow handshake and slow first-header clients release capacity after timeout.
- Key and CA rotation overlap is exercised, followed by removal of old trust.
- Logs and artifacts are scanned for raw API keys, authorization headers,
  account IDs, isolation tokens, private keys, and certificate secrets.

Pass gate: every negative case fails before a Tor connection is attempted and
no secret appears in retained evidence.

### P0.4 Prove live tenant and cache isolation

Use a controlled origin with deterministic counters and response markers.

Required matrix:

1. Same account/workspace/isolation/generation gets one cold fetch and one hit.
2. Different account gets a separate fetch and cannot receive the first body.
3. Different workspace gets a separate fetch.
4. Different isolation subdivision gets a separate fetch.
5. Isolation rotation makes the old generation inaccessible.
6. Strict mode always bypasses cache and performs separate origin fetches.
7. Concurrent cold requests in one scope coalesce once.
8. Concurrent cold requests in different scopes do not share a lock or body.
9. TTL expiry forces a new fetch and stale content is never served on error.
10. Eviction pressure and process restart preserve isolation invariants.
11. A malicious controlled response injects very large freshness, stale
    directives, cookies, `Vary`, and `X-Proxy-Cache`; policy remains bounded and
    no cache oracle reaches the client.

Pass gate: origin counts, bodies, and aggregate metrics jointly prove each
scope boundary. Timing or an exit-IP comparison alone is insufficient.

### P0.5 Test the deployed service lifecycle and rollback

Add a runner for the exact service-manager deployment:

- Verify non-root identity, unit dependencies, sandboxing, file modes, limits,
  environment/config ownership, and internal listener binding.
- Send `SIGTERM` with active short and long tunnels; require bounded drain and
  no new acceptance after shutdown begins.
- Test forced kill, restart, stale Unix socket handling, database recovery, and
  bounded loss from in-flight usage checkpoints.
- Test certificate/config reload behavior explicitly; if reload is unsupported,
  verify the documented restart procedure.
- Test rolling binary/config upgrade and rollback as one atomic operation.
- Test account database backup, restore, corruption detection, and permission
  preservation.
- Fill or make the log/data filesystem read-only in a disposable environment
  and verify fail-safe behavior.

Pass gate: retained evidence proves startup, drain, crash recovery, reboot,
backup/restore, upgrade, and rollback on the intended host image.

### P0.6 Add tests for the test runners themselves

The recently found unscoped-Bash-`wait` defect demonstrates that harness code
needs deterministic tests.

Use fake `cargo`, `curl`, metrics, and proxy processes to cover:

- Argument validation and mode-specific prerequisites.
- Readiness success, timeout, and early process exit.
- Waiting only for request workers, not the owned proxy.
- Partial and missing worker result files.
- Mixed `2xx`, `3xx`, proxy `503`, origin `503`, curl timeout, TLS error, and
  connection-reset classifications.
- Cleanup deadlines, signal handling, `--keep-running`, and stale listeners.
- Evidence-directory collision, permissions, summary accuracy, and redaction.
- Every documented option in `--help` and `TESTING_GUIDELINES.md`.

Change the stress pass criteria so that requested completions must match actual
completions and an explicit minimum success ratio / maximum controlled-503 rate
is required.

## Priority 1: scale, resilience, and abuse testing

### Dedicated controlled-origin and fault-injection service

Do not load-test `example.com`, Tor Check, or another public service. Add an
authorized origin capable of:

- HTTP and HTTPS success responses with deterministic IDs and counters.
- Configurable body sizes, upload echo, delays, chunking, half-close, reset,
  partial headers/body, invalid TLS, and status codes.
- Cacheable, personalized, variant, oversized, and malicious cache responses.
- Per-run counters that distinguish accounts/scopes without exposing production
  identity data.

This service makes functional, security, cache, and performance results
repeatable and attributable.

### Replace the bounded stress check with a real load suite

Keep `stress-test.sh` as a quick developer check. Add a separate load harness
with these profiles:

| Profile | Purpose | Required observations |
|---|---|---|
| Baseline | Establish one-client behavior | Connect latency, first-byte latency, throughput, errors |
| Ramp | Increase toward declared capacity | p50/p95/p99, queue depth, 503 rate, CPU, RSS, FDs |
| Steady state | Hold expected production load | SLO compliance and stable resources |
| Spike | Sudden burst above capacity | Controlled rejection, no crash, bounded recovery |
| Soak | Run for hours, preferably through rotations | Memory/task/FD leaks, cache bounds, DB growth |
| Long tunnel | Hold many CONNECT streams | Fairness, idle timeout, drain, byte accounting |
| Bulk transfer | Large upload and download | Throughput, quota boundary, backpressure |
| Mixed tenants | Heavy and light accounts together | No starvation or cross-tenant limit bypass |
| TLS churn | Repeated production handshakes | Handshake cap, CPU bound, timeout cleanup |
| Degraded Tor | Delay/fail/restart Arti | Breaker/admission behavior and recovery |

The load generator should run on a separate host or namespace so generator CPU
does not distort proxy measurements.

Before a capacity run, define versioned pass criteria for:

- Minimum success ratio at expected load.
- Maximum proxy-generated `503` ratio and zero origin-generated false positives.
- p50, p95, and p99 latency for connection establishment and completed requests.
- Sustained requests/second and bytes/second.
- Maximum CPU, RSS, file descriptors, sockets, queue depth, and active tasks.
- No panic, crash, direct-egress packet, secret leak, or unbounded metric label.
- Fairness between accounts and recovery to baseline after a spike.

Without numeric SLOs, a load run is observational data, not a pass/fail capacity
test.

### Multi-process and multi-host deployment matrix

Scale-out is not just “start two copies.” The following semantics need an
explicit design and tests:

- Account request, tunnel, and byte limits across processes. The roadmap still
  identifies cross-process quota coordination as open.
- SQLite locking, migration ownership, crash recovery, and backup while more
  than one process is active.
- Session-isolation consistency when a load balancer sends related requests to
  different instances.
- Process-local cache, circuit breaker, isolation store, and metrics behavior.
- Health checks that reflect Arti and database readiness, not only an open port.
- L4 load balancing that preserves end-to-end mTLS, or an explicitly reviewed
  alternative trust boundary.
- Connection draining during rolling upgrade and node loss.
- Per-instance and aggregate metrics without high-cardinality tenant labels.
- Arti topology: per-instance versus shared service, capacity, isolation, and
  failure domain.

Pass gate: limits and isolation remain correct with at least two instances,
loss of one instance is controlled, and rolling deployment does not drop more
traffic than the declared SLO permits.

### Network and protocol abuse matrix

Add real-socket tests for:

- Slow TLS handshakes and slow first headers at the configured limits.
- Many idle clients, partial CONNECT headers, one-byte fragmentation, maximum
  header size/count, and clients that disconnect at every parse boundary.
- Duplicate/conflicting headers, request smuggling candidates, pipelining, and
  unexpected methods.
- Many long-lived tunnels intended to exhaust account and global capacity.
- Downstream and upstream half-close/reset races.
- Circuit-build timeouts, breaker transitions, queue cancellation, and retry
  storms under real concurrency.
- File-descriptor and ephemeral-port exhaustion in a disposable host.

### Database, quota, and time-failure matrix

Add tests for:

- Concurrent writers and readers across processes.
- Database busy/locked, disk full, I/O error, corruption, and schema mismatch.
- Crash between usage reservation, transfer, checkpoint, and commit.
- The documented maximum uncheckpointed byte loss after forced termination.
- Period-boundary rollover, clock steps, and restart around a boundary.
- Backup during traffic, restore into a clean host, and permission verification.

### Observability and privacy operations

Add tests that:

- Scan structured logs and evidence artifacts for credentials and raw tenant,
  isolation, destination, URL, and certificate data.
- Exercise every error class and ensure labels remain bounded.
- Generate high traffic and assert metric cardinality and memory remain bounded.
- Verify alerts for Arti unavailable, queue saturation, breaker activity,
  account database failures, service restart, and firewall rejects.
- Verify log rotation, disk limits, retention, and access permissions.
- Check metrics and administrative listeners from both the host and an external
  network location.

## Priority 2: continuous assurance and defense in depth

### Parser property and fuzz testing

Add persistent fuzz targets for proxy request parsing, CONNECT authorities,
isolation headers, cache origin configuration, cache keys, and response cache
directives. Seed them with every regression case and require no panic, excessive
allocation, or policy bypass.

### Memory and concurrency tools

Add scheduled or pre-release runs using appropriate Rust sanitizers/model tools
for:

- Unsafe/memory errors in native dependencies.
- Race and cancellation behavior in task registries, counters, cache locks, and
  admission guards.
- Undefined behavior in supported targets.

These jobs may need a separate nightly toolchain; they should not silently
replace the stable locked build.

### Supply-chain and release CI

Add:

- A pinned Rust toolchain file and an explicit supported-version policy.
- Dependency vulnerability and license/policy review.
- Secret scanning and static analysis.
- Immutable commit pinning for CI actions.
- SBOM, release checksum, binary provenance, and reproducibility checks.
- A dependency-update job that reruns deterministic and controlled integration
  tests.
- Code coverage as a trend signal, without treating percentage alone as a
  security gate.

### Platform matrix

- Run check/test/build continuously on supported Linux versions.
- Add macOS CI for compilation and deterministic tests; keep live Tor smoke as a
  controlled scheduled/manual job.
- Keep Windows as an expected-failure compatibility job until the internal
  transport is ported, then promote it only after the complete runtime and leak
  matrix passes.

## Recommended implementation order

### Phase 0 — Make test results trustworthy

1. Add deterministic tests for every shell/PowerShell runner.
2. Add a controlled origin/fault injector.
3. Secure evidence directories with restrictive permissions and add redaction.
4. Make success/503/completion thresholds explicit and machine-readable.
5. Resolve the unregistered `request_scheduler.rs` test island.

**Gate:** harness regressions and false-green results are caught without Tor or
network access.

### Phase 1 — Close security-boundary gaps

1. Implement and test the complete destination policy.
2. Add the production-ingress credential matrix.
3. Add the multi-scope cache isolation and malicious-exit matrix.
4. Add fail-closed egress/firewall verification with packet evidence.

**Gate:** rejected traffic cannot reach cache/admission/Arti, credentials fail
closed, cache scopes cannot cross, and direct egress is impossible on the target
host.

### Phase 2 — Prove production operations

1. Test the exact service manager, identities, filesystem policy, and listeners.
2. Test SIGTERM, forced termination, Arti restart, reboot, backup/restore,
   upgrade, and rollback.
3. Exercise alerts, log rotation, artifact retention, and external exposure.

**Gate:** a retained target-host bundle proves recoverable, least-privilege
operation.

### Phase 3 — Establish capacity

1. Define numeric SLOs and the intended single-instance topology.
2. Run baseline, ramp, steady, spike, bulk, long-tunnel, and soak profiles.
3. Tune only from retained measurements.

**Gate:** the exact release meets declared SLOs with bounded resources and
controlled overload behavior.

### Phase 4 — Validate scale-out if required

1. Resolve shared state and isolation semantics.
2. Test at least two instances, the chosen load balancer, Arti topology, rolling
   deployment, and node loss.
3. Repeat security and capacity gates in the scaled topology.

**Gate:** scale-out does not weaken authentication, isolation, quotas, egress
containment, observability, or recovery.

## Evidence required for every release or performance claim

Record:

- Source revision and whether the working tree was dirty.
- Binary checksum and build/toolchain versions.
- Host image, kernel, CPU, memory, limits, and network topology.
- Effective non-secret configuration and service-manager unit checksum.
- Test account/certificate lifecycle used, with secrets redacted.
- Controlled-origin ownership and configuration.
- Start/end timestamps, duration, workload profile, and generator location.
- Per-status/error counts, latency percentiles, throughput, and host resources.
- Relevant application metrics, firewall counters, and packet-capture summary.
- Artifact path, owner/mode, redaction result, retention deadline, and final
  summary.

## Claims the suite should never make

Even after the additions above:

- A Tor Check response does not prove anonymity against global traffic
  correlation, endpoint fingerprinting, browser state, or account correlation.
- Different exit IPs do not prove independent circuits, and the same exit IP
  does not prove circuit reuse.
- A vulnerability scanner or dependency audit does not prove runtime security.
- A local benchmark does not establish customer-visible or Tor-network
  performance.
- A single-host pass does not establish multi-host behavior.
- A successful response does not prove no direct-egress attempt; firewall and
  packet evidence are required.
