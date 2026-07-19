# Task: Add Global Circuit Admission Control to the Tor Bridge

## Context

This is a Pingora-based forward proxy that tunnels CONNECT requests through Tor via `arti_client`. The relevant code lives in a single `main.rs` (paste below or point agent at the file). Key existing types:

- `Bridge` struct — holds `tor: Arc<TorClient<PreferredRuntime>>` and `token_store: Arc<MemoryCache<String, IsolationToken>>`. Its `handle_connect` method (associated fn on `Bridge`, called per accepted `UnixStream`) parses a CONNECT request, resolves/creates an `IsolationToken` per destination, opens a Tor stream via `tor.connect_with_prefs(target, &prefs)`, then runs `tokio::io::copy_bidirectional` between the client socket and the Tor stream.
- There is a currently-commented-out `RateLimitGuard` struct (a `Semaphore` + `SemaphorePermit<'static>` pair) and a `CircuitHandle<'session, Phase>` struct with `PhantomData` fields for phase/lifetime tracking, plus `Bridge::open_circuit`, which is unused. These were early sketches for exactly this feature — reuse/extend them rather than designing from scratch, unless there's a clean reason not to.
- Circuit **building** in Tor (multi-hop key negotiation) is the expensive, latency-heavy step. Uncontrolled concurrent circuit builds degrade latency for all in-flight connections and put unnecessary load on guard relays. We need a hard cap on concurrent circuit builds, separate from any per-account request-rate limiting (which is a different, already-planned feature — do not conflate the two).

## Goal

Implement a **global circuit admission control mechanism** (a scheduler) that:

1. Caps the number of concurrent Tor circuit *build/connect* operations across the whole process (not per-account — this is a shared resource limit).
2. Queues excess requests (FIFO) up to a bounded wait time, rather than either rejecting immediately or blocking forever.
3. Returns a clean `503 Service Unavailable` with a `Retry-After` header to the client if the wait times out.
4. Releases the slot automatically once the circuit is established (not held for the full lifetime of the bidirectional copy — see "Open Question" below, agent should flag this rather than assume).
5. Exposes basic metrics (current permits in use, total timeouts, and circuit build latency) so the cap can be tuned empirically later.

## Requirements

### 1. Core semaphore mechanism

- Add a `circuit_semaphore: Arc<tokio::sync::Semaphore>` field to `Bridge`.
- Initialize with a configurable capacity — add a constant `const MAX_CONCURRENT_CIRCUIT_BUILDS: usize = 32;` near the other existing constants (`CACHE_MAX_BYTES`, `MAX_CONNECT_HEADER_BYTES`, etc.) and use it to size the semaphore. Make this easy to find/tune (a comment noting "tune based on VPS bandwidth + observed build latency" is fine).
- Use `Semaphore::acquire_owned()` (not `acquire()`) so the resulting `OwnedSemaphorePermit` is `'static` and can be held across the `.await` inside `handle_connect` without lifetime friction. This directly resolves what the commented-out `SemaphorePermit<'static>` field was trying to do — either delete the old `RateLimitGuard`/`CircuitHandle` scaffolding if unused after this change, or wire it in as the actual permit holder type. Use judgment; leaving obviously-dead PhantomData-only structs around is worse than removing them, but if `CircuitHandle` is a reasonable home for the permit, adapt it rather than adding a parallel type.

### 2. Bounded wait + timeout behavior

- Before calling `tor.connect_with_prefs(...)` in `handle_connect`, acquire a permit with a timeout:
  ```rust
  const CIRCUIT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10); // tune later
  ```
- If the timeout elapses before a permit is available:
  - Write `HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n` to the client stream.
  - Return an `Err` from `handle_connect` with a clear message (e.g. `"circuit capacity exceeded, request timed out waiting for a slot"`), consistent with the existing error style in that function (it already does this pattern for malformed CONNECT requests and failed Tor connects — match that style).
  - Do **not** panic or let this become an unhandled task failure — `handle_connect` is spawned via `tokio::spawn` in `run_bridge`, so an `Err` here should already be caught and logged by the existing `if let Err(e) = Self::handle_connect(...)` wrapper. Confirm this still holds after the change.

### 3. Permit scope — flag the open question, don't silently pick

There are two reasonable designs and the agent should implement one but explicitly call out the tradeoff in a comment (and in its summary to me) rather than picking silently:

- **Option A (build-only):** Hold the permit only until `tor.connect_with_prefs(...)` resolves (success or failure), then drop it immediately — the semaphore governs circuit *construction* concurrency, not total concurrent tunnels. Once a circuit exists, the ongoing `copy_bidirectional` doesn't hold a slot.
- **Option B (full connection lifetime):** Hold the permit for the entire duration of the tunneled connection, capping total concurrent tunnels, not just build concurrency.

Default to **Option A** unless there's a strong reason otherwise — it directly targets the actual bottleneck (circuit build cost), and Option B would over-constrain long-lived low-bandwidth connections (e.g. a scraper holding a keep-alive) for no benefit. Implement Option A, but leave a clear comment explaining why, so it's easy to switch later if real-world usage shows total-tunnel-count is actually the constraint.

### 4. Metrics

Add minimal, cheap instrumentation — no external metrics crate required unless one is already a dependency:

- `AtomicUsize` counters (can live as fields on `Bridge` or in a small `CircuitMetrics` struct) for:
  - Current permits in use (or derive from `Semaphore::available_permits()` if simpler — prefer this, don't duplicate state the semaphore already tracks).
  - Total count of acquire timeouts (i.e. `503`s issued due to capacity).
  - Rolling or cumulative circuit build latency (time from "acquired permit" to "connect_with_prefs resolved") — a simple running count + sum is fine for now (avg = sum/count), no need for a full histogram.
- Log these periodically (e.g. every N seconds via a spawned interval task in `run_bridge`, or on every Nth request) so they're visible in server logs without needing a dashboard yet. A `/metrics`-style endpoint is out of scope for this task — just make the numbers observable via logs.

### 5. Tests

Add unit/integration tests covering:
- Semaphore correctly limits concurrency: spin up more concurrent fake acquire attempts than the configured capacity and assert the excess ones block until an earlier one releases.
- Timeout path: assert that an acquire attempt against a fully-saturated semaphore with no releases returns the timeout error within roughly the configured `CIRCUIT_ACQUIRE_TIMEOUT` (use a short timeout constant in the test, not the real 10s, to keep tests fast).
- The 503 response bytes are correctly written to the client stream on timeout (can be tested against an in-memory duplex stream rather than a real `UnixStream` — check what's already used in the existing `parse_connect_request`/`read_connect_request` tests for the project's testing conventions and match that style).

## Constraints / things to preserve

- Do not touch per-domain `IsolationToken` logic — that's a separate, already-correct concern (privacy/correlation isolation). This task is purely about *when* a circuit build is allowed to start, not which identity it uses.
- Do not add Redis, a job queue, or any external service — this must be entirely in-process (`tokio::sync::Semaphore` is sufficient and is the intended mechanism; don't over-engineer this into a distributed scheduler, this runs as a single process on one VPS).
- Keep the existing error-handling style (the `anyhow::anyhow!` / `anyhow::bail!` patterns already used in `parse_connect_request`, `read_connect_request`, `handle_connect`) — match it rather than introducing a new error type.
- Don't change the public `run_bridge` loop's accept/spawn structure beyond what's needed to pass the new semaphore into `handle_connect`.

## Deliverable

- Modified `main.rs` (or wherever this ends up living) with the semaphore field, timeout-guarded acquire logic wired into `handle_connect`, metrics counters + periodic logging, and the tests described above.
- A short written summary (a few sentences) explaining: which Option (A or B) was implemented and why, what `MAX_CONCURRENT_CIRCUIT_BUILDS` was set to and that it's a placeholder pending real tuning, and confirmation that spawned-task panics/errors are still caught after the change.
