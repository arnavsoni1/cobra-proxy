# Testing Guidelines

This guide is the entry point for testing the proxy during development, before a release, and after deployment. It documents every test script in the repository, the Rust test suite, the output each workflow produces, and the conclusions that can and cannot be drawn from a passing run.

The scripts themselves remain the source of truth for exact defaults. Run a script with `--help` where supported whenever this guide and a recently changed script disagree.

## Choose the right test

| Goal | Command | Typical use | Network/Tor required? | Retains artifacts? |
|---|---|---|---:|---:|
| Fast compiler feedback | `cargo check --locked` | During editing | No | Cargo output only |
| Deterministic automated tests | `cargo test --locked` | During editing and before every merge | No, ignored live tests are not run | Cargo output only |
| Hosted Ubuntu CI | `.github/workflows/linux.yml` | Every push, pull request, or manual dispatch | No | GitHub Actions logs and cache |
| Linux native smoke test | `./test-proxy-linux.sh` | Before shipping Linux changes | Yes | No |
| macOS native smoke test | `./test-proxy-macos.sh` | Check the macOS development path | Yes | No |
| Windows compatibility check | `test-proxy-windows.cmd` or `test-proxy-windows.ps1` | Detect native Windows support gaps | Only if compilation succeeds | No |
| Scheduler/load behavior | `./stress-test.sh` | Intentional concurrency testing | Yes | No |
| Full deployment verification | `./test-deployment.sh` | Before release and on a deployed VPS | Yes | Yes |
| Controlled-origin cache matrix | E2E `--cache-url` or the ignored Rust test | Validate cache behavior against an origin you own | Yes | E2E only |
| Local transport microbenchmark | Ignored Rust benchmark | Diagnose in-memory copy performance | No | Console output only |

For ordinary development, use the smallest test that can catch the change you made. Do not use the stress test as a substitute for unit tests or the deployment test.

## Prerequisites and runtime assumptions

The Linux and macOS shell workflows require:

- Bash, including `/dev/tcp` support.
- Rust and Cargo compatible with the checked-in toolchain and `Cargo.lock`.
- `curl` with HTTP and HTTPS support.
- Network access sufficient for Arti to bootstrap and reach the Tor network.
- Permission for Arti to create and update its persistent state in the current user's data directories.
- Free local listeners where applicable: public proxy `127.0.0.1:8080`, internal Pingora service `127.0.0.1:8081`, and metrics `127.0.0.1:9090`.
- Permission to create the bridge socket at `/tmp/proxy-bridge.sock`.

The Windows workflow requires PowerShell, Cargo, and `curl.exe`. Native Windows is not currently expected to compile because the bridge uses Tokio Unix sockets and `/tmp/proxy-bridge.sock`. The Windows test is still useful: it produces a direct explanation when this compatibility boundary is reached and will become a real smoke test when the bridge transport is ported.

All commands should be run from the repository root. Scripts change to their own directory internally, so invoking an absolute script path is also safe.

### Test-origin safety

Smoke and deployment checks are deliberately low volume. Stress testing is different. Prefer an HTTP(S) origin you own or are explicitly authorized to test, even when using conservative request counts. Never use the load-limit override merely to test what the proxy can do against an unrelated public service.

A controlled cache origin should:

- Be plain HTTP because only ordinary HTTP responses are cacheable by this proxy.
- Return a successful response.
- Return `Cache-Control: public` with a positive `max-age` or `s-maxage`.
- Avoid `Set-Cookie`, `Vary`, personalized content, and request requirements such as cookies or authorization.
- Return a body small enough for the configured cache object limit.
- Use a stable path during the two-request assertion.

## Recommended development workflow

### While editing

Run the compiler check first:

```bash
cargo check --locked
```

Then run either a targeted test or the full deterministic suite:

```bash
cargo test --locked circuit_
cargo test --locked cache_
cargo test --locked
```

The substring after `cargo test --locked` is a name filter, not a test group declaration. For example, `circuit_` can match circuit-breaker tests as well as circuit-admission tests. Check Cargo's list of executed tests rather than assuming a filter covered an entire subsystem.

### Before merging or handing off

Use this order:

```bash
cargo check --locked
cargo test --locked
cargo build --release --locked
./test-proxy-linux.sh
```

Use the platform-specific smoke wrapper on macOS or Windows. On the production Linux target, finish with the deployment runner:

```bash
./test-deployment.sh
```

Run the stress test only when the change affects admission control, concurrency, circuit creation, tunnel lifetime, retries, or resource limits, and only with a suitable target.

### Before a production release

Run the deployment test against the exact release binary and environment that will be used in production. Then run it in `running` mode on the deployed host. Because the service listeners are loopback-only, running the test on the host avoids exposing the proxy or metrics endpoint publicly.

Do not promote a release based only on unit tests, a Tor Check response, or an in-memory benchmark.

## Rust compiler and automated tests

### Hosted Ubuntu CI

GitHub Actions runs `.github/workflows/linux.yml` on Ubuntu 24.04 for every push and pull request, and it can also be started manually with `workflow_dispatch`. The job installs the current stable Rust toolchain, checks all targets against the locked dependency graph, runs the deterministic test suite, and builds the release binary.

The hosted job deliberately does not run `test-proxy-linux.sh`. That script depends on live Tor bootstrap and an external Tor Check endpoint, so it remains an explicit smoke test rather than a required merge check. A passing hosted job proves that the project compiles, tests, and release-builds on a clean Ubuntu runner; it does not validate Tor reachability, host firewall rules, public ingress, or a deployed service manager.

### Compiler check

```bash
cargo check --locked
```

This checks that the code and locked dependency graph compile without creating an optimized release artifact. Warnings do not make the command fail. Compiler errors, a stale lockfile, missing native build requirements, and platform-incompatible imports do.

### Deterministic test suite

```bash
cargo test --locked
```

The normal suite covers these areas without requiring a live proxy:

- CONNECT and ordinary HTTP request parsing, incomplete input, destination ports, and preservation of bytes read after the header.
- Destination canonicalization and rejection of local or non-routable targets.
- Isolation-header validation, header stripping, session-token reuse and expiry, and strict-isolation uniqueness.
- Circuit-breaker behavior and bounded storage.
- Retry classification and timeout behavior.
- Active-tunnel and circuit-build admission, permit release, cancellation cleanup, queue metrics, semaphore closure, and `503` response bytes.
- Bidirectional copy, half-close behavior, idle timeout, and byte counters.
- Cache keys and conservative cache admission for public, non-personalized responses.
- Prometheus rendering, bounded labels, and the `/metrics` endpoint path.

Cargo prints the authoritative passed, failed, ignored, and filtered counts at the end. The exact count may grow as tests are added, so automation and release notes should read the reported result rather than rely on a count copied into documentation.

Useful commands include:

```bash
# Show test output even for passing tests
cargo test --locked -- --nocapture

# Run one named test
cargo test --locked circuit_acquire_timeout_writes_service_unavailable_response

# List tests without running them
cargo test --locked -- --list
```

### Ignored controlled-origin functional matrix

`controlled_origin_functional_matrix` is ignored by the normal suite because it needs a separately running proxy, `curl`, and authorized external origins. It checks plain HTTP, session-isolated HTTPS, strict HTTPS, and a second cache request reporting `X-Proxy-Cache: HIT`.

Start the proxy in one terminal and wait for it to become ready:

```bash
cargo run --release --locked
```

In another terminal, provide all three controlled endpoints and run only the ignored test:

```bash
PROXY_TEST_HTTP_URL=http://origin.example/plain \
PROXY_TEST_HTTPS_URL=https://origin.example/secure \
PROXY_TEST_CACHEABLE_URL=http://origin.example/cacheable \
cargo test --locked controlled_origin_functional_matrix -- --ignored --nocapture
```

The test always uses the proxy at `127.0.0.1:8080`. Prefer the deployment runner's `--cache-url` workflow when retained logs and response evidence are needed.

### Ignored local transport benchmark

The benchmark copies a 1 MiB payload in each direction through Tokio in-memory duplex streams at several concurrency levels. It does not use Arti, Tor, the network, Pingora, or a real deployment.

Run it in release mode:

```bash
cargo test --release --locked benchmark_established_tunnel_transport -- --ignored --nocapture
```

It emits JSON-like records containing concurrency, bytes per direction, aggregate MiB/s, and p50/p95/p99 elapsed time. Use it to detect large local transport regressions. Do not publish its throughput as proxy or Tor performance.

## Native smoke tests

The native smoke tests answer a narrow question: can this platform check, test, build, start, route one HTTPS request through Tor, and emit a completed circuit scheduler sample?

They do not exercise plain HTTP, destination-policy failures, strict isolation, cache hits, the Prometheus endpoint, or load behavior.

### Linux

```bash
./test-proxy-linux.sh
```

`test-proxy-linux.sh` is a small wrapper around `test-proxy-unix.sh linux`. The shared script rejects the run unless `uname -s` reports Linux.

### macOS

```bash
./test-proxy-macos.sh
```

`test-proxy-macos.sh` delegates to `test-proxy-unix.sh macos`. The shared script rejects the run unless `uname -s` reports Darwin. This checks the current native development path; Linux remains the documented production target.

### Shared Unix smoke sequence

The shared Unix script performs these steps in order:

1. Requires `cargo` and `curl`.
2. Runs `cargo check --locked`.
3. Runs `cargo test --locked`; ignored tests remain skipped.
4. Runs `cargo build --release --locked`.
5. Starts `target/release/proxy`, with output redirected to a temporary `proxy.log`.
6. Waits for a TCP listener on `127.0.0.1:8080`. Because listeners start after Arti bootstrap, this is also an indirect bootstrap readiness check.
7. Sends an HTTPS request through the proxy to the Tor Check JSON endpoint.
8. Requires the compact response to contain `"IsTor": true`.
9. Waits for a periodic scheduler log where no circuit-build permit is in use and at least one build/connect attempt has completed.
10. Prints up to the last three scheduler metric samples and exits successfully.

Configuration is by environment variable:

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_URL` | `http://127.0.0.1:8080` | Proxy URL used by `curl`; readiness still checks fixed port 8080 |
| `TOR_CHECK_URL` | `https://check.torproject.org/api/ip` | JSON endpoint expected to report `IsTor=true` |
| `PROXY_START_TIMEOUT_SECONDS` | `180` | Maximum startup/readiness wait |
| `PROXY_REQUEST_TIMEOUT_SECONDS` | `90` | Maximum time for each Tor Check attempt |
| `PROXY_METRICS_TIMEOUT_SECONDS` | `35` | Wait for the periodic scheduler log sample, not the HTTP metrics endpoint |
| `TMPDIR` | Platform temporary directory | Parent directory for the temporary smoke-test directory |

Example with longer Tor timeouts:

```bash
PROXY_START_TIMEOUT_SECONDS=240 \
PROXY_REQUEST_TIMEOUT_SECONDS=120 \
./test-proxy-linux.sh
```

Use a custom `PROXY_URL` carefully: the script still starts a local process and checks readiness on port 8080, so the custom URL should identify that same intended deployment.

### Interpreting Unix smoke output

- `Checking, testing, and building` failures are source, test, dependency-lock, or release-build failures.
- `proxy exited before becoming ready` means the process ended during bootstrap or listener setup. The script prints the last 100 proxy-log lines.
- `did not listen ... within 180s` means the process remained alive but never reached public-listener readiness. Look for Arti bootstrap, filesystem, port-conflict, or bridge-socket errors.
- A curl failure reports the curl exit code and the last 100 proxy-log lines.
- A successful HTTP response without `IsTor=true` fails the test. Confirm the proxy URL and Tor Check endpoint before treating this as an isolation defect.
- `no completed circuit-build metrics sample` means the Tor request may have returned, but the expected periodic scheduler line did not appear before its separate metrics-log timeout.
- `Native ... smoke test passed` means the complete narrow sequence above passed.

The temporary directory and `proxy.log` are deleted on both success and failure. Failure logs printed to the terminal are therefore the only retained evidence unless the entire command output is captured externally:

```bash
set -o pipefail
./test-proxy-linux.sh 2>&1 | tee smoke-linux.log
```

`pipefail` preserves the smoke script's nonzero exit status instead of allowing a successful `tee` process to mask it.

### Windows

From Command Prompt:

```bat
test-proxy-windows.cmd
```

The CMD wrapper invokes PowerShell with an execution-policy bypass and propagates its exit status. From PowerShell, the direct form allows named parameters:

```powershell
.\test-proxy-windows.ps1 `
  -StartupTimeoutSeconds 240 `
  -RequestTimeoutSeconds 120 `
  -MetricsTimeoutSeconds 45
```

Available parameters are `StartupTimeoutSeconds`, `RequestTimeoutSeconds`, `MetricsTimeoutSeconds`, `ProxyUrl`, and `TorCheckUrl`, with defaults equivalent to the Unix smoke test.

The PowerShell sequence mirrors the Unix sequence: check, test, release build, process start, fixed-port readiness, Tor Check JSON parsing, periodic scheduler-log assertion, and cleanup. Standard output and standard error are captured separately in a temporary directory. Relevant standard error is printed on startup or metrics failures, and the directory is deleted in `finally`.

At present, `cargo check` is expected to explain that native Windows is unsupported because of `UnixListener`, `UnixStream`, and `/tmp/proxy-bridge.sock`. Treat this as a known platform gap. Once compilation succeeds, later failures should be interpreted like the Unix smoke stages.

## Stress test

`stress-test.sh` exercises bounded concurrency and classifies controlled overload separately from unexpected failures. It is not a benchmark harness and does not establish production capacity.

Show its current options:

```bash
./stress-test.sh --help
```

The default run is:

```bash
./stress-test.sh
```

It uses 64 total requests, concurrency 40, and `https://example.com/`. For routine development, prefer a smaller authorized run:

```bash
./stress-test.sh \
  --requests 20 \
  --concurrency 5 \
  --url https://your-authorized-origin.example/health
```

### Stress-test sequence

1. Validates positive integer request and concurrency values.
2. Reduces concurrency to the request count when concurrency is larger.
3. Rejects more than 512 requests or concurrency above 64 unless the explicit load override is set.
4. Runs tests whose names match `circuit_`, unless `--skip-scheduler-tests` is supplied.
5. Unless `--use-running-proxy` is supplied, runs `cargo check --locked`, builds the release binary, starts it, and waits on port 8080.
6. Sends requests in concurrent batches and records each response body, curl stderr, curl exit status, and HTTP status in a temporary directory.
7. Classifies results and prints a summary.
8. When it started the proxy, confirms the process survived and tries to print recent scheduler samples.
9. Deletes all temporary per-request results and the local proxy log during cleanup.

Options:

| Option | Default | Meaning |
|---|---:|---|
| `--requests N` | `64` | Total requests |
| `--concurrency N` | `40` | Requests launched per batch; reduced to total requests when necessary |
| `--url URL` | `https://example.com/` | Target URL |
| `--proxy-url URL` | `PROXY_URL` or local default | Proxy used by curl |
| `--use-running-proxy` | Off | Skip check/build/start and send to an existing proxy |
| `--skip-scheduler-tests` | Off | Skip Cargo tests filtered by `circuit_` |

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_URL` | `http://127.0.0.1:8080` | Default proxy URL before CLI override |
| `PROXY_START_TIMEOUT_SECONDS` | `180` | Local startup wait |
| `PROXY_REQUEST_TIMEOUT_SECONDS` | `90` | Per-request curl timeout |
| `ALLOW_HIGH_TOR_LOAD` | `0` | Set to `1` to bypass the 512-request/64-concurrency guard |
| `TMPDIR` | Platform temporary directory | Temporary result parent directory |

Even with `--use-running-proxy`, the current script still requires Cargo. It runs the filtered tests unless `--skip-scheduler-tests` is also supplied. It does not wait for, inspect, or stop the already-running process.

### Interpreting the stress summary

```text
Stress-test summary
  completed:             64
  successful HTTP:       60
  scheduler/proxy 503s:  4
  other failures:        0
  elapsed seconds:       42
```

- `completed` is the number of per-request status files produced. It should equal the requested total.
- `successful HTTP` requires curl exit status 0 and an HTTP status from 200 through 399.
- `scheduler/proxy 503s` counts HTTP `503` responses. These are accepted as controlled admission or breaker behavior.
- `other failures` includes curl/network failures and HTTP outcomes not classified as success or controlled `503`.
- `elapsed seconds` is wall-clock time for the request phase; it is not a stable throughput benchmark.

A stress-test pass can include some—or even all—`503` responses. A pass means the proxy survived and failures were controlled, not that it served every request successfully. Always evaluate the success and `503` counts against the objective of the run.

Any `other failures` make the script fail. It prints a `curl_status http_status count` breakdown and the last 100 proxy-log lines when it owns the process. Because the temporary directory is then deleted, rerun with terminal output captured when diagnosing intermittent failures.

The override form is intentionally explicit:

```bash
ALLOW_HIGH_TOR_LOAD=1 ./stress-test.sh \
  --requests 1000 \
  --concurrency 100 \
  --url https://your-authorized-load-origin.example/
```

Only use it after confirming the proxy host, Tor impact, test-origin capacity, and stop conditions.

## End-to-end deployment test

`test-deployment.sh` is the broadest test workflow. It supports a self-managed local release process and an already-running deployment, continues through independent functional failures, and keeps a timestamped evidence bundle.

### Local mode

```bash
./test-deployment.sh
```

Local mode runs the locked compiler check, full normal test suite, release build, endpoint preflight, process startup, and functional matrix. The binary currently has fixed endpoints, so local mode rejects proxy or metrics URLs other than `127.0.0.1:8080` and `127.0.0.1:9090/metrics`.

Reuse an already-built release binary during harness development:

```bash
./test-deployment.sh --skip-build
```

`--skip-build` skips the compiler check, automated tests, and release build. It should not be used as release evidence unless those phases were run separately against the same source.

### Running-deployment mode

Run this on the deployment host:

```bash
./test-deployment.sh --mode running \
  --proxy-url http://127.0.0.1:8080 \
  --metrics-url http://127.0.0.1:9090/metrics
```

Running mode does not build, start, stop, or collect the service's process log. It waits for the supplied metrics endpoint and sends the same functional requests through the supplied proxy. Obtain systemd, container, or supervisor logs separately if a case fails.

Run against a quiet, isolated instance when possible. On a shared service, unrelated traffic can change metrics between the baseline and final snapshot, making activity-delta checks less attributable to this run.

### Optional cache check

```bash
./test-deployment.sh \
  --cache-url http://your-authorized-origin.example/cacheable
```

The runner requests the same controlled URL twice with the same isolation identity and requires the second response to include `X-Proxy-Cache: HIT`. In running mode, the first request may already be a hit if the process cache was warm; the script asserts the second hit but does not require the first response to be a miss or compare the two bodies.

### Deployment options and environment

Run `./test-deployment.sh --help` for the current interface.

| Option | Meaning |
|---|---|
| `--mode local\|running` | Own a local process or test an existing deployment |
| `--proxy-url URL` | Proxy endpoint; custom values require running mode |
| `--metrics-url URL` | Full Prometheus `/metrics` endpoint |
| `--tor-check-url URL` | HTTPS JSON endpoint expected to report `IsTor=true` |
| `--http-url URL` | Plain-HTTP forwarding target |
| `--https-url URL` | HTTPS strict-isolation target |
| `--cache-url URL` | Optional plain-HTTP controlled cache target |
| `--startup-timeout N` | Readiness wait in seconds |
| `--request-timeout N` | Per-request timeout in seconds |
| `--skip-build` | Local mode only; reuse `target/release/proxy` |
| `--keep-running` | Local mode only; leave the test-owned process running |
| `--artifacts-dir PATH` | Override the evidence directory |

Equivalent defaults can be set with `PROXY_URL`, `PROXY_METRICS_URL`, `TOR_CHECK_URL`, `PROXY_TEST_HTTP_URL`, `PROXY_TEST_HTTPS_URL`, `PROXY_TEST_CACHEABLE_URL`, `PROXY_START_TIMEOUT_SECONDS`, and `PROXY_REQUEST_TIMEOUT_SECONDS`. Explicit CLI options take precedence over environment defaults.

For a local test-owned process, the deployment, Unix smoke, and stress runners set
`PROXY_SHUTDOWN_DRAIN_SECONDS` and
`PROXY_SHUTDOWN_FORCE_STOP_SECONDS` from the test-only
`PROXY_TEST_SHUTDOWN_DRAIN_SECONDS` and
`PROXY_TEST_SHUTDOWN_FORCE_STOP_SECONDS` inputs. Both test inputs default to
one second so cleanup remains quick; the runner derives its exact-PID fallback
deadline from them. These test defaults do not alter the binary's production
defaults of a 30-second natural drain and a five-second force-stop wait.

When `--keep-running` is selected, the evidence bundle contains `proxy.pid` and the final console output reports the PID. The developer is responsible for stopping that exact test-owned process. Without this option, cleanup allows a bounded graceful period and then force-stops only the PID the runner started.

### Deployment case matrix

Setup failures stop the matrix because later checks would not have a valid target. After setup succeeds, independent functional cases continue even if an earlier case fails, giving one run a fuller diagnostic picture.

| Case ID | What it checks | Pass condition | Common failure meaning |
|---|---|---|---|
| `cargo_check` | Source and locked graph compile | `cargo check --locked` exits 0 | Compiler, dependency, or platform problem |
| `cargo_test` | Normal deterministic suite | `cargo test --locked` exits 0 | Unit/integration regression |
| `cargo_build` | Release artifact | Optimized locked build exits 0 | Release-only compilation or link problem |
| `deployment_preflight` | Local public and metrics ports | Ports 8080 and 9090 are free | Another process owns a fixed endpoint; no process is killed |
| `deployment_start` | Release process and metrics readiness | Process stays alive and expected metrics appear | Tor bootstrap, Arti state, port 8081, bridge socket, or listener failure |
| `deployment_ready` | Existing deployment readiness | Expected metrics appear before timeout | Wrong URL, unavailable deployment, or incompatible metrics contract |
| `metrics_contract` | Core Prometheus families | Required `HELP` lines exist | Wrong service/version or metrics regression |
| `metrics_path_scope` | Non-metrics path behavior | A sibling path returns 404 | Metrics HTTP routing regression; this does not prove loopback binding |
| `destination_policy` | SSRF baseline | CONNECT to `127.0.0.1:443` returns 403 | Local destination was not rejected or request bypassed the proxy |
| `invalid_isolation` | Isolation validation | Invalid identity returns CONNECT status 400 | Header validation or proxy-routing regression |
| `tor_session` | Session isolation and Tor egress | Tor Check returns JSON containing `IsTor=true` | Tor path, TLS, endpoint, isolation, or wrong-proxy problem |
| `strict_https` | Strict-isolation HTTPS | Configured origin returns 2xx or 3xx | Strict stream, TLS, Tor exit, or origin problem |
| `plain_http` | Public ingress → Pingora → bridge → Tor | Configured HTTP origin returns 2xx or 3xx | HTTP dispatch, bridge, Tor, exit, or origin problem |
| `controlled_cache` | Repeat cache lookup | Second controlled response says `X-Proxy-Cache: HIT` | Ineligible origin response or cache pipeline problem; skipped without a cache URL |
| `metrics_activity` | Observable effects of this run | Tor-received bytes and isolation-token count increase from baseline | No completed data path, stale/wrong metrics, or noisy shared deployment |
| `deployment_survived` | Final health | Local process still exists when owned, and metrics respond | Crash or health endpoint loss during the matrix |

### Evidence bundle

The default directory is:

```text
artifacts/deployment-e2e/<UTC timestamp>-<runner PID>/
```

`artifacts/` is ignored by Git. An override can be absolute or relative to the repository root:

```bash
./test-deployment.sh --artifacts-dir /tmp/proxy-release-candidate-1
```

Use a new or empty override directory for each run; fixed override directories can contain files left by an earlier execution.

| File | Contents | How to use it |
|---|---|---|
| `summary.txt` | Overall `PASS`/`FAIL`, mode, endpoints, and passed/failed/skipped case IDs | Start here; a skipped optional cache case is not a failure |
| `run.log` | Console-level phase progress and failure excerpts | Reconstruct the order and top-level result |
| `cases/<case>.log` | Full stdout/stderr for one case | Primary case-specific diagnostic; successful cases may be empty |
| `proxy.log` | Test-owned process stdout/stderr in local mode | Correlate proxy events and scheduler samples with failures |
| `proxy.pid` | PID started in local mode | Process ownership evidence, especially with `--keep-running` |
| `metrics.before.prom` | Metrics baseline after readiness and contract validation | Compare counters and gauges before traffic |
| `metrics.after.prom` | Metrics snapshot after functional traffic | Confirm activity and classify failures |
| `tor-check-session.json` | Tor Check response body | Verify `IsTor` and inspect the returned exit IP; may be absent/partial on curl failure |
| `http-response.headers` / `.body` | Plain-HTTP origin response | Inspect origin status, cache headers, and returned content |
| `https-response.headers` / `.body` | Strict HTTPS origin response | Inspect origin status and content when TLS succeeds |
| `cache-first.*` / `cache-second.*` | Optional cache responses | Compare `X-Proxy-Cache` and origin behavior |

Response artifacts can contain origin content and the Tor exit IP. They are Git-ignored but should still be handled according to the project's data-retention and privacy practices.

### Reading the result

- `result: PASS` and exit status 0 mean every required case passed. Optional cache coverage may still be skipped; read `skipped_cases`.
- `result: FAIL` and exit status 1 mean at least one required case failed or setup could not complete.
- A setup failure produces a shorter artifact set because no functional cases were run.
- A local process can remain healthy while all outbound requests fail. `deployment_survived` passing does not override `tor_session`, `strict_https`, or `plain_http` failures.
- A Tor Check pass verifies that request's observed exit was Tor. It does not prove that different isolation identities received distinct circuits or distinct exit IPs.

## Interpreting proxy logs and metrics

### Periodic circuit scheduler line

The proxy periodically writes a line shaped like:

```text
[bridge] circuit metrics: permits_in_use=0 queued_circuit_builds=0 active_tunnels=0 queued_tunnels=0 rejected_tunnels=0 completed_tunnels=3 acquire_timeouts=0 circuit_build_count=3 average_build_latency_ms=2450.12
```

| Field | Meaning | What to watch |
|---|---|---|
| `permits_in_use` | Circuit/stream establishment slots currently held | Sustained values at the configured maximum indicate saturation |
| `queued_circuit_builds` | Requests waiting for circuit-build admission | Sustained growth means the build cap is the current bottleneck |
| `active_tunnels` | Tunnels holding active-tunnel permits | Compare with expected long-lived connections |
| `queued_tunnels` | Requests waiting for active-tunnel capacity | Nonzero values indicate total-tunnel pressure |
| `rejected_tunnels` | Cumulative immediate connection/task rejections | Increases indicate hard local capacity pressure |
| `completed_tunnels` | Cumulative attempts that acquired and later released active-tunnel capacity | This includes attempts that later failed; it is not a success count |
| `acquire_timeouts` | Cumulative circuit-admission wait timeouts | Corresponds to controlled circuit-capacity `503` behavior |
| `circuit_build_count` | Completed Arti connect/build attempts, including failures and retries | This is not guaranteed to equal newly constructed three-hop circuits because Arti can reuse circuits |
| `average_build_latency_ms` | Cumulative average establishment-attempt latency since process start | Compare across equivalent workloads; it is not a rolling window |

A single sample is a snapshot. Use several samples and request outcomes before changing concurrency limits.

### Structured request events

CONNECT handling writes events such as:

```json
{"event":"tunnel","method":"CONNECT","status":200,"latency_ms":1234.567,"error_class":"none"}
```

Ordinary HTTP handling writes events such as:

```json
{"event":"http_request","method":"GET","status":200,"latency_ms":456.789,"cache":"HIT","error":false}
```

Interpretation:

- `status` is the proxy or origin-facing HTTP result recorded for that path.
- `latency_ms` is end-to-end time for that observation, not only circuit construction.
- Tunnel `error_class` values distinguish local validation/capacity, Tor timeouts, destination failures, idle timeout, and stream-copy failures.
- HTTP `cache` is typically `HIT`, `MISS`, `STALE`, or `BYPASS`.
- HTTP `error=true` means Pingora completed logging with an internal proxy error; inspect nearby bridge lines.
- Detailed `[bridge] ingress connection error:` and `[bridge] internal connection error:` lines contain the error chain for failed public and Unix-bridge connections.

The normal operational log intentionally omits full URLs, paths, isolation identities, and destination names. Curl response artifacts can still contain identifying data.

### Prometheus metrics

The deployment runner captures the endpoint rather than requiring Prometheus. Important families are:

| Group | Metrics | Interpretation |
|---|---|---|
| Requests | `proxy_requests_total{method,status}` | Outcomes by bounded method and status labels |
| Latency | `proxy_request_duration_seconds`, `proxy_tunnel_duration_seconds`, `proxy_tor_connect_duration_seconds`, `proxy_cache_lock_wait_seconds` | Cumulative histograms; compare `_count`, `_sum`, and buckets |
| Admission | `proxy_active_tunnels`, `proxy_queued_tunnels`, `proxy_queued_circuit_builds`, `proxy_circuit_acquire_timeouts_total`, `proxy_rejected_tunnels_total` | Current pressure and cumulative overload behavior |
| Builds and retries | `proxy_circuit_build_attempts_total`, `proxy_circuit_build_latency_microseconds_total`, `proxy_connect_timeouts_total`, `proxy_retries_total` | Establishment volume, latency total, and recovery attempts |
| Breaker and failures | `proxy_circuit_breaker_rejections_total`, `proxy_circuit_breaker_entries`, `proxy_arti_failures_total{class}` | Destination protection and stable Tor failure classes |
| Traffic | `proxy_bytes_to_tor_total`, `proxy_bytes_from_tor_total` | Payload copied in each direction; successful traffic should advance both as appropriate |
| Cache | `proxy_cache_hits_total`, `proxy_cache_misses_total`, `proxy_cache_stale_hits_total`, `proxy_cache_bypasses_total`, `proxy_cache_insertions_total` | Cache decisions and admission |
| Cache storage | `proxy_cache_entries`, `proxy_cache_bytes`, `proxy_cache_evictions_total`, `proxy_cache_evicted_bytes_total` | Current in-memory cache size and cumulative eviction activity |
| Upstream reuse | `proxy_upstream_connections_reused_total`, `proxy_upstream_connections_fresh_total` | Pingora connection reuse behavior |
| Isolation | `proxy_isolation_tokens` | Current bounded, expiring in-memory token entries; identities are not exposed |

Counters normally only increase during a process lifetime; gauges can rise and fall. Compare snapshots from the same process. A restart resets in-memory counters and cache state.

### HTTP statuses

| Status | Proxy meaning |
|---:|---|
| `400` | Malformed request, authority, or isolation metadata |
| `403` | Destination rejected by local safety policy |
| `503` | Local admission exhausted or destination circuit breaker open; inspect `Retry-After`, queues, and rejection counters |
| `504` | Tor establishment exceeded its deadline |
| `502` | Other Tor, DNS, exit-policy, destination-connect, bridge, or upstream failure |

An origin can independently return the same statuses. Correlate public request events, tunnel events, curl output, and metrics rather than classifying a status in isolation.

### Common curl exit codes

The scripts print curl's exit code when transport setup fails. Common values include:

| Curl code | Meaning in these tests | Next evidence to inspect |
|---:|---|---|
| `7` | Could not connect to the configured proxy or metrics endpoint | Endpoint, readiness, listener ownership, firewall/tunnel |
| `22` | HTTP failure with `--fail` | Captured HTTP status, response headers, proxy log |
| `28` | Operation timed out | Startup/request timeout, Tor health, admission queues, origin |
| `35` | TLS handshake failed | Whether CONNECT reached 200, tunnel error, byte counters, Tor exit/origin TLS behavior |
| `52` | Empty reply | Process/stream closure and nearby bridge errors |
| `56` | Receive failure, often after a rejected CONNECT | Expected CONNECT status for negative tests or unexpected stream reset |

The exit code identifies the curl layer, not necessarily the root cause.

## Troubleshooting by failure stage

### Check, test, or build fails

Run the failing Cargo command directly without the surrounding script. Fix compiler errors and failed deterministic tests first. Warnings are worth reviewing but do not explain a nonzero result unless warnings are explicitly denied by the environment.

### Startup or readiness fails

Check, in order:

1. Arti bootstrap and persistent-state permission errors in `proxy.log`.
2. Existing listeners on ports 8080, 8081, or 9090.
3. Ownership and stale state around `/tmp/proxy-bridge.sock`.
4. Network access to Tor directory authorities and guards.
5. Whether the process exited or merely failed to expose metrics/public ingress.

The deployment preflight protects ports 8080 and 9090 but does not preflight port 8081 or the Unix socket; those conflicts appear in `deployment_start` logs.

### Tor Check fails but readiness passes

Read `cases/tor_session.log`, the session response if present, `proxy.log`, and the before/after Tor failure metrics. Confirm the test used the intended proxy. Distinguish:

- No CONNECT success: destination policy, admission, breaker, DNS, or Tor establishment.
- CONNECT 200 followed by curl code 35/52/56: the tunnel was accepted but TLS/data transfer failed.
- Valid JSON with `IsTor=false`: wrong proxy/endpoint, bypass, or unexpected routing; do not accept the run.

### Plain HTTP returns 502

Inspect the `http_request` event and nearby internal bridge error. The ordinary HTTP path includes public ingress, internal Pingora TCP, the Unix bridge, Arti, Tor, and the origin. Compare `proxy_bytes_to_tor_total` and `proxy_bytes_from_tor_total` to see whether application bytes moved.

### Stress run has 503s

First decide whether controlled overload was the purpose of the run. Compare `503` count, queued circuit builds, active/queued tunnels, acquire timeouts, rejected tunnels, and establishment latency. A small controlled `503` count under a saturation test can be correct. The same count in a baseline reliability run is a capacity or timeout problem.

### Metrics activity fails

If functional requests also failed, zero byte movement is supporting evidence rather than a separate root cause. If functional cases passed, confirm both snapshots came from the same process and that unrelated deployment restarts or concurrent traffic did not invalidate the comparison.

### Cleanup hangs or ports remain occupied

The deployment runner uses bounded cleanup and an exact-PID force-stop fallback. The older Unix smoke and stress scripts wait for graceful process exit and do not preflight every fixed endpoint. Verify process ownership before stopping anything manually. Never use a broad `pkill` on a shared host.

## Exit codes and artifact retention

| Workflow | Success | Test/runtime failure | Configuration/prerequisite error | Retention |
|---|---:|---:|---:|---|
| Cargo commands | `0` | Nonzero | Nonzero | Terminal only unless redirected |
| Unix smoke | `0` | `1` | `2` for invalid platform/arguments or missing tools | Temporary logs deleted |
| Windows PowerShell/CMD | `0` | Nonzero exception/command status | Nonzero | Temporary logs deleted |
| Stress | `0` | `1` | `2` for arguments, safety limit, or missing tools | Temporary logs deleted |
| Deployment E2E | `0` | `1` | `2` for invalid options/URLs or missing tools | Evidence bundle retained |

CI should use exit status for gating and upload the deployment evidence directory on both success and failure. For smoke and stress workflows, capture terminal output because their temporary files are intentionally removed.

## What a passing suite does not prove

- It does not prove anonymity, immunity to traffic correlation, or browser-fingerprint resistance.
- Session or strict-isolation requests succeeding does not guarantee different exit IPs; independent Tor circuits can select the same exit.
- A Tor Check pass verifies one request, not all possible code paths or a no-bypass property under every failure.
- A smoke pass does not cover cache policy, plain HTTP, negative destination policy, or concurrency behavior.
- A stress pass does not require every request to succeed; controlled `503` responses are accepted.
- The local transport benchmark is not Tor, network, VPS, or customer-perceived performance.
- Tests against public endpoints can fail because of endpoint availability or Tor-exit blocking. Controlled origins are required for release-quality reliability claims.
- Running-mode metric deltas on a shared service can include unrelated traffic.
- Unit and local tests do not replace testing the actual service manager, filesystem permissions, network policy, and loopback exposure on the deployment host.

Record the exact command, source revision, platform, endpoint ownership, configuration overrides, summary, and evidence path whenever a result is used for a release decision or performance claim.
