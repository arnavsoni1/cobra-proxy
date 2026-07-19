# Proxy Remediation Plan

The observed failures are fixable, but HTTPS requires an ingress redesign rather than a configuration change. Work should proceed in dependency order: correct protocol handling first, cache correctness second, Tor isolation and reliability third, then benchmarking and advertising claims.

## Issue Summary

| Issue | Root cause | Fix |
|---|---|---|
| HTTPS returns HTTP 400 | Pingora permits `CONNECT`, but the current proxy forwards it as an HTTP request instead of creating a raw tunnel | Handle downstream `CONNECT` as a raw TCP tunnel |
| Cache never hits | `response_cache_filter` is not implemented, so Pingora applies its default uncacheable policy | Add a conservative response cache-admission policy |
| Isolation is ineffective | The request token never reaches the bridge; the bridge chooses tokens by destination | Pass an isolation identity through the internal `CONNECT` request and partition connection pools |
| Load degrades under concurrency | Same-destination traffic has shared circuit fate, bridge tasks are unbounded, and failures lack overload control or recovery | Add concurrency limits, timeouts, retries, circuit breaking, and metrics |
| Some origins return HTTP 403 | Many sites block or restrict Tor exits | Report the origin response accurately; allow explicit circuit rotation without promising site acceptance |

## Phase 1: Implement HTTPS CONNECT Tunneling

The setting below only permits `CONNECT` requests to enter Pingora. It does not implement RFC CONNECT tunneling:

```rust
http_options.allow_connect_method_proxying = true;
```

### Recommended ingress design

1. Move the Pingora HTTP service to an internal listener such as `127.0.0.1:8081`.
2. Add a Tokio TCP listener on the public proxy address, `127.0.0.1:8080`.
3. Read and validate the first HTTP request header without losing bytes that follow it.
4. Dispatch based on the method:
   - For `CONNECT`, create a raw tunnel over Arti.
   - For ordinary HTTP, forward the complete buffered request and connection to internal Pingora.
5. Disable `CONNECT` handling inside Pingora so a request cannot accidentally be forwarded as ordinary HTTP again.

### CONNECT flow

For a valid `CONNECT host:port` request:

1. Parse and validate the authority and port.
2. Apply destination and port policy. The default should at least reject invalid, zero, and unsafe destinations.
3. Determine the connection's isolation identity and configure `StreamPrefs`.
4. Call `TorClient::connect_with_prefs`.
5. If the Tor connection succeeds, write:

   ```http
   HTTP/1.1 200 Connection Established
   
   ```

6. Forward any TLS bytes that were received in the same read as the CONNECT header.
7. Run `tokio::io::copy_bidirectional` between the downstream client and the Tor stream.
8. Apply idle timeout, byte accounting, shutdown, and error classification around the tunnel.

Do not decrypt or cache tunneled HTTPS. TLS must remain end-to-end between the client and destination.

### Phase 1 verification

- `curl --proxy http://127.0.0.1:8080 https://example.com/` succeeds with normal certificate validation.
- A client that sends TLS data immediately after the CONNECT header succeeds.
- Large bidirectional transfers do not truncate.
- Concurrent tunnels remain isolated and close cleanly.
- Invalid authorities return HTTP 400.
- Tor connection failures return HTTP 502 or 504, not an origin-looking HTTP 400.

## Phase 2: Activate the HTTP Cache Safely

The proxy enables cache lookup for GET requests, but Pingora will not admit responses until `response_cache_filter` returns a cacheable `CacheMeta`.

### Cache admission policy

Implement `ProxyHttp::response_cache_filter` with Pingora's cache-control parser and response cacheability helper:

- `CacheControl::from_resp_headers`
- `filters::resp_cacheable`
- `CacheMetaDefaults`

Begin with a conservative shared-cache policy:

- Cache only `GET` requests.
- Cache only HTTP 200 responses.
- Require an explicit positive `Cache-Control: public, max-age=...` or `s-maxage=...` policy.
- Reject `private` and `no-store` responses.
- Reject requests containing `Authorization` or `Cookie`.
- Reject responses containing `Set-Cookie`.
- Reject `Vary` responses until proper variance keys are implemented. In particular, reject `Vary: *` unconditionally.
- Set a per-object size limit, initially 1-8 MiB.
- Retain the existing LRU eviction manager and process-local cache lock.

### Correct the cache key

The key must be canonical and must represent every request property allowed to affect a cached response. At minimum it should contain:

```text
scheme + lowercase host + effective port + path + query
```

Before using the key, verify that the absolute-form request URI agrees with the `Host` header. A disagreement should be rejected instead of producing a potentially poisonable cache entry.

Do not use `Debug` formatting of `Option<&str>` in a production cache key. Parse and normalize the authority explicitly.

### Cache observability

Add a downstream header such as:

```http
X-Proxy-Cache: HIT
```

Supported values should include `HIT`, `MISS`, `STALE`, and `BYPASS`. Derive this from `session.cache.phase()` or `session.cache.upstream_used()`.

The per-request `Server-Response-ID` can remain a downstream transformation. Pingora stores the original response before applying `response_filter`, so the identifier should be generated separately for every downstream response, including cache hits.

### Phase 2 verification

- The first cacheable request is a miss and the second identical request is a hit.
- The origin receives only one request during the hit test.
- Different hosts, ports, paths, and queries never collide.
- `private`, `no-store`, authenticated, and cookie-bearing traffic is not cached.
- Responses containing `Set-Cookie` are not cached.
- Unsupported `Vary` responses are not cached.
- A concurrent cold request produces one origin fetch because of the cache lock.
- Objects over the configured size limit bypass the cache safely.
- LRU eviction occurs near the configured 128 MiB capacity.

## Phase 3: Correct Tor Isolation

The current request context creates an `IsolationToken`, but that token is not passed to the bridge. The bridge instead stores one token under the destination string, causing traffic to the same destination to share an isolation group.

### Isolation identity transport

1. Define an opaque isolation identifier that is safe to serialize.
2. Obtain it from an explicit local proxy session mechanism, such as proxy authentication or a dedicated local-only header.
3. Strip the client-supplied identity header before forwarding the request to the origin.
4. Add the identifier to `CrateProxy.headers` in `upstream_peer`.
5. Extend the bridge CONNECT parser to read the internal isolation header.
6. Map the identifier to an `IsolationToken` in a bounded cache with an expiry.
7. Include the isolation identifier in Pingora's peer/proxy hash so an upstream connection cannot be reused by another isolation group.
8. Use the same isolation policy in the direct downstream CONNECT handler.

The Unix bridge socket is an internal trust boundary. It should remain inaccessible to untrusted users, and the internal isolation header must still be length-limited and validated.

### Supported isolation modes

#### Session isolation

Connections bearing the same explicit session identity may reuse Tor circuits and upstream connections. Different identities cannot share them. This offers a practical balance between unlinkability and performance.

#### Strict isolation

Use `StreamPrefs::isolate_every_stream()` and prevent Pingora upstream keepalive reuse. Each HTTP request or CONNECT tunnel receives a distinct Tor stream. This has substantially higher latency and circuit overhead and should be opt-in.

For ordinary HTTP, strict request isolation requires closing or partitioning the upstream HTTP connection. Generating a new Arti token alone is insufficient if Pingora reuses a previously established connection.

### Cache and isolation interaction

A shared cache creates potential cross-user response and timing correlation. Therefore either:

- cache only explicitly public, non-personalized content under the conservative policy above; or
- namespace the cache by isolation identity for the strongest privacy boundary.

The privacy mode and performance tradeoff must be documented instead of implied.

### Phase 3 verification

- The same session identity receives the same isolation group when session mode is enabled.
- Different identities never share tokens or upstream pooled connections.
- Strict mode creates a fresh Tor stream for every request or tunnel.
- Isolation headers never reach the destination.
- Token entries expire and the store remains within its configured bound.

## Phase 4: Make Concurrency and Failure Behavior Controlled

The bridge currently starts one unrestricted Tokio task for every accepted Unix connection. Under load this allows work and memory to grow without a defined capacity boundary.

### Concurrency control

- Add a semaphore limiting active Tor connection attempts and tunnels.
- Use a bounded wait duration for acquiring a permit.
- Return HTTP 503 when local capacity is exhausted.
- Start with a conservative limit and set the final value from controlled benchmarks rather than CPU count alone.
- Track active, queued, rejected, and completed tunnels.

### Timeouts

- Apply a total Tor connection-establishment timeout.
- Apply read/write or idle timeouts to inactive tunnels.
- Do not impose a short total lifetime on an otherwise active CONNECT tunnel.
- Preserve buffered bytes and half-close behavior when one side shuts down.

### Retry policy

- Retry at most once during connection establishment.
- Never retry after request or tunnel payload bytes have been sent upstream.
- Rotate the isolation token/circuit following exit timeout or `Stream not connected` when policy allows it.
- Add jittered backoff before the retry.

### Circuit breaker

Track repeated connection failures per destination or failure class. After a threshold:

- reject or delay new attempts briefly;
- return a clear HTTP 503/504 response;
- avoid repeatedly hammering a failing Tor exit or destination;
- automatically probe recovery after the cooldown.

Do not blindly restart the entire Arti client for isolated destination failures. Rebootstrap only when client-wide bootstrap or directory health indicates it is necessary.

### Error mapping

| Status | Meaning |
|---|---|
| `400 Bad Request` | Invalid CONNECT authority, headers, or destination |
| `403 Forbidden` | Local destination policy rejected the request |
| `503 Service Unavailable` | Local concurrency limit or circuit breaker is active |
| `504 Gateway Timeout` | Tor connection establishment timed out |
| `502 Bad Gateway` | Other Tor or origin connection failure |

An origin-generated HTTP 403 must pass through as an origin response. Many services block Tor exits; the proxy cannot guarantee that every destination will accept a given exit. Circuit rotation may be offered explicitly, but it must not be advertised as a guaranteed bypass.

## Phase 5: Add Production Observability

Expose a loopback-only Prometheus endpoint and add structured access logging.

### Required metrics

- Requests by method and final status.
- Request and tunnel latency histograms.
- Tor connection-establishment latency.
- Active and queued tunnel gauges.
- Rejection and timeout counters.
- Arti failure counters grouped by stable error class.
- Bytes transferred in each direction.
- Cache hits, misses, stale hits, bypasses, insertions, and evictions.
- Cache lock wait duration.
- Upstream connection reuse.
- Retry and circuit-breaker activity.
- Current token-store size.

Avoid logging complete URLs, credentials, isolation identifiers, client IPs, or destination data by default. Metrics must preserve the anonymity goals of the service.

## Phase 6: Verification and Benchmarking

Public test services and random Tor exits introduce substantial noise and can throttle or block traffic. Final advertising metrics must use a controlled public origin that the project is authorized to load test.

### Functional test matrix

- Plain HTTP pass-through.
- HTTPS CONNECT with certificate validation.
- Long-lived bidirectional HTTPS tunnel.
- Cacheable HTTP miss and hit.
- Non-cacheable and personalized HTTP responses.
- Session and strict isolation modes.
- Timeout, retry, overload, and recovery behavior.
- Graceful shutdown with active tunnels.

### Performance test matrix

Measure these as separate workloads:

1. Cold, uncached HTTP over Tor.
2. Warm HTTP cache hits.
3. HTTPS CONNECT establishment.
4. Sustained transfer through an established HTTPS tunnel.
5. Concurrent mixed destinations.
6. Same-destination concurrency.
7. A 30-60 minute reliability soak.

For each workload:

- test concurrency levels such as 1, 5, 10, 25, and 50;
- run for at least 60 seconds after warm-up;
- repeat at least three times;
- report request count, error rate, throughput, p50, p95, p99, CPU, RSS, and active connections;
- preserve the origin, payload size, host configuration, build profile, commit, and test timestamp with the result.

Warm cache throughput and uncached Tor throughput must never be combined into one headline number. HTTPS tunnel performance is Tor- and destination-bound and cannot benefit from HTTP response caching without breaking end-to-end TLS.

## Advertising Gate

Do not publish new performance or anonymity claims until all of the following are true:

- HTTPS CONNECT passes end-to-end tests.
- Cache hits are directly verified and cache poisoning tests pass.
- Isolation behavior is proven with automated tests.
- The selected concurrency level sustains an acceptable error rate during repeated runs.
- A soak test shows recovery from transient Tor failures.
- Metrics come from a controlled, authorized origin.
- Every published number states its workload, sample size, concurrency, hardware, and latency percentiles.

The first defensible high-throughput claim will likely concern warm plain-HTTP cache hits. Uncached and HTTPS traffic should be advertised in terms of privacy, correctness, and measured latency rather than conventional direct-network proxy throughput.
