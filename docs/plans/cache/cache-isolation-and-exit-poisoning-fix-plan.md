# Cache Isolation and Tor Exit Poisoning Fix Plan

- **Plan timestamp:** 2026-08-17T10:01:23Z
- **Status:** Runtime and deterministic tests implemented; authenticated
  controlled-origin deployment verification pending
- **Scope:** Ordinary HTTP response caching in `src/main.rs`
- **Security priority:** High
- **Constraint:** Caching must remain a supported, active feature. This plan does
  not remove the cache, replace it with unconditional bypass, or disable it for
  all production traffic.

## Purpose

This plan fixes two related security failures in the current ordinary-HTTP
cache:

1. The process-global cache key does not include authenticated tenant,
   workspace, isolation identity, or isolation generation. A cache hit can
   therefore cross boundaries that Tor circuit and upstream-pool isolation
   otherwise enforce.
2. A Tor exit can modify a plaintext HTTP response, add permissive cache
   directives, and cause the modified representation to persist and be replayed.
   The current admission policy has no hard freshness ceiling.

The target design retains the existing in-memory Pingora cache, process-local
cache lock, object-size limit, and LRU eviction. It changes who may use the cache,
how entries are partitioned, which origins may populate it, how long an entry
may remain usable, and what cache information is exposed to clients.

## Current implementation and root cause

### Global backend and key

`CACHE`, `CACHE_LOCK`, and `CACHE_EVICTION` are process-global `OnceLock`
instances. Keeping a shared physical backend is acceptable if every logical key
contains a trustworthy privacy scope.

The current key is:

```text
namespace = canonical scheme + host + effective port
primary   = path + query
user_tag  = empty string
```

`cache_key_callback` constructs it with:

```text
CacheKey::new(authority_namespace, path_and_query, "")
```

This omits account, workspace, caller subdivision, isolation material, and Tor
connection-pool generation. Pingora 0.8 includes `CacheKey.user_tag` in
`CompactCacheKey`, so the current dependency already provides an intended field
for a compact opaque scope. A new storage dependency is not required.

### Cache enablement happens after trusted context resolution

`request_filter` authenticates the production request and populates
`RequestCtx.ingress_identity`, `isolation_identity`, `isolation_group_key`, and
`strict_isolation` before `request_cache_filter` enables caching. This ordering
makes it possible to derive the cache boundary from trusted server-side context.

The fix must not derive its security boundary directly from
`X-Proxy-Isolation`. Under authenticated ingress that header is only an optional
subdivision inside the account/workspace boundary. In development mode it is
caller-controlled and is not sufficient to separate mutually untrusted users.

### Strict mode currently reaches the shared cache

`request_cache_filter` calls `request_cache_eligible(request)` without checking
`ctx.strict_isolation`. Strict mode creates a fresh Arti token and upstream group,
but a cache hit can complete before either is used. A strict request can
therefore receive bytes fetched under a different tenant, isolation identity,
circuit, or exit.

### Plaintext response admission trusts exit-modifiable metadata

Ordinary HTTP is sent without destination TLS after the Tor exit. The exit can
modify the response body and headers. The cache currently accepts a response
when it is HTTP 200, explicitly `public`, has a positive `s-maxage` or `max-age`,
and passes the existing cookie, authorization, `Set-Cookie`, and `Vary` checks.

Those checks are useful for accidental personalization, but `public` and
`max-age` are not authenticity signals when an on-path exit can inject them.
The origin-supplied freshness can also be extremely long. Origin-provided
`stale-while-revalidate` or `stale-if-error` can extend replay beyond the fresh
period unless stale serving is explicitly disabled or included in the same
ceiling.

### Client-visible cache status creates an oracle

`response_filter` adds `X-Proxy-Cache: HIT`, `MISS`, `STALE`, or `BYPASS` to every
ordinary HTTP response. Because the current cache is shared, a client can probe
an exact URL and learn whether another request populated it. Partitioning removes
the cross-tenant form of this oracle, but the status header should still not be
part of the production client contract.

## Security objectives

The implementation is acceptable only when all of these invariants hold:

1. A strict-isolation request never performs a cache lookup, waits on a cache
   lock, serves a cached object, or inserts an object.
2. An unauthenticated request never accesses the production HTTP cache.
3. Two accounts cannot address the same cache entry.
4. Two workspaces in the same account cannot address the same cache entry.
5. Two non-strict isolation subdivisions in the same workspace cannot address
   the same cache entry.
6. A rotated isolation/upstream generation cannot address entries populated by
   the prior generation.
7. Raw account IDs, workspace IDs, API keys, device IDs, isolation headers, and
   destination URLs are not placed in cache tags, metrics, or logs.
8. Only exact, locally configured HTTP origins may be looked up or inserted.
9. No cached response is fresh or serveable stale beyond the local absolute TTL
   ceiling.
10. An origin or Tor exit cannot cause a production `X-Proxy-Cache` status to be
    returned to the client.
11. Cache failures bypass caching or fail the request according to a documented
    local policy; they never weaken authentication or Tor routing.
12. Approved, authenticated, non-strict, cacheable traffic still produces real
    cache hits and avoids redundant origin requests.

## Non-goals and residual risk

This plan does not make arbitrary plaintext HTTP authentic. An allowlisted HTTP
origin is still reachable through an exit that can alter its response. The first
four controls below limit which users, origins, and time periods receive an
altered representation; they do not prove that the bytes came from the origin.

Cryptographic origin authenticity would require one of the following:

- End-to-end TLS, which remains opaque inside an HTTPS CONNECT tunnel and is not
  cacheable by this forward proxy without unacceptable TLS interception.
- An application-layer signature or trusted digest that the proxy can verify.
- A separate trusted fetch architecture with a reviewed authenticity boundary.

Do not describe the trusted-origin allowlist as proof of transport trust. It is
an operator decision that limited caching risk is acceptable for specified
public HTTP resources.

Per-tenant storage quotas and fairness are also outside these two fixes. The
global LRU prevents unbounded memory growth, but one tenant may still create
eviction pressure. That should be addressed in a separate resource-isolation
plan if observed.

## Target architecture

```text
authenticated ordinary HTTP GET
  -> resolve account/workspace and isolation policy
  -> strict? -------------------------------> bypass cache -> Tor
  -> authenticated non-strict?
       no -----------------------------------> bypass cache -> Tor
       yes
  -> exact canonical origin allowlisted?
       no -----------------------------------> bypass cache -> Tor
       yes
  -> derive opaque cache scope from trusted context
  -> v2 scoped cache lookup and scoped cache lock
       hit ----------------------------------> return cached response
       miss -> Tor exit -> plaintext origin response
                 -> conservative response checks
                 -> locally cap TTL and disable stale use
                 -> insert only into the same v2 scope
```

The physical `MemCache` remains shared. The security boundary is the opaque
scope embedded in every key and lock identity.

## Detailed design

### 1. Add a cache policy object

Create a validated immutable `CachePolicy` during startup and store it on
`Proxy`. Do not read environment variables per request.

Recommended initial fields:

```text
CachePolicy
  allowed_http_origins: exact canonical origin set
  configured_max_ttl:   Duration
  absolute_max_ttl:     Duration
```

Recommended settings:

| Setting | Initial value | Validation |
|---|---:|---|
| `PROXY_CACHE_ALLOWED_HTTP_ORIGINS` | Deployment-specific, non-empty in production | Comma-separated exact `http://host:port` origins; no wildcard, path, query, fragment, userinfo, private/local address, or unsupported scheme |
| `PROXY_CACHE_MAX_TTL_SECONDS` | `60` | Positive integer; must not exceed the compiled absolute maximum of `300` seconds |
| Compiled absolute TTL maximum | `300` seconds | Cannot be raised through deployment configuration |

The startup parser must canonicalize origins using the same host, case,
trailing-dot, IPv6-bracket, scheme, and effective-port rules as
`canonical_cache_key_parts`. Do not implement suffix matching. For example,
allowing `http://example.com:80` must not allow
`http://attacker-example.com:80` or `http://sub.example.com:80`.

Production startup should reject a malformed allowlist or TTL. Before rollout,
the deployment must explicitly populate at least one reviewed origin so caching
remains active. There must be no `*`, `all`, or unsafe-global compatibility mode.

Development ingress may continue forwarding ordinary HTTP, but it must bypass
the production cache because it lacks a trusted tenant boundary. Unit tests can
exercise the cache through synthetic trusted context; deployment cache tests
should use authenticated ingress.

### 2. Represent the trusted cache scope in `RequestCtx`

Add a field such as:

```text
cache_scope: Option<OpaqueCacheScope>
```

`None` means the request is not allowed to look up or insert cache entries.
Populate it only in `request_filter`, after authentication and isolation
resolution.

For authenticated non-strict requests, derive it using a keyed, domain-separated
BLAKE3 hash over:

```text
"proxy-http-cache-scope-v2\0"
account identity
workspace identity
resolved isolation identity
isolation group generation
```

The resolved isolation identity already incorporates the canonical destination
and optional caller subdivision inside the authenticated account/workspace. The
isolation group key changes when the in-memory Arti isolation material rotates,
so including it prevents a new upstream generation from using a representation
fetched under the old generation.

Do not include `api_key_id` or `device_credential_id`: credential rotation within
the same authorized workspace should not define content ownership. Authentication
and revocation must still execute before every cache lookup.

The resulting scope should be a fixed-length opaque string suitable for
`CacheKey.user_tag`. It must not be reversible to database identifiers. Use a
separate domain separator even if the existing tenant isolation hashing key and
helper are reused.

For strict or unauthenticated requests, leave `cache_scope` as `None`.

### 3. Centralize request cache access decisions

Keep `request_cache_eligible` for HTTP request semantics, but add one decision
function that combines request, context, and local policy. It should return a
bounded enum rather than a boolean so tests and metrics can distinguish reasons:

```text
CacheAccessDecision
  Eligible { scope, canonical_origin }
  BypassStrict
  BypassUnauthenticated
  BypassOriginNotAllowed
  BypassRequestPolicy
```

The decision order should be:

1. If `ctx.strict_isolation`, return `BypassStrict` immediately.
2. If `ctx.cache_scope` is absent, return `BypassUnauthenticated`.
3. Canonicalize and validate the request authority.
4. If the exact canonical HTTP origin is absent from the allowlist, return
   `BypassOriginNotAllowed`.
5. Require the existing conservative request policy: `GET`, no `Authorization`,
   no `Cookie`, and no request `private` or `no-store` directive.
6. Return `Eligible` with the already-derived scope and canonical origin.

`request_cache_filter` may call `session.cache.enable` only for `Eligible`.
Strict bypass must happen before cache enablement so it prevents reads, not only
writes.

Retain `CACHE_MAX_OBJECT_BYTES`, the shared eviction manager, and the shared
cache lock. Once `user_tag` is scoped, Pingora's compact key also scopes lock
coalescing. This must be verified rather than assumed.

### 4. Version and partition every cache key

Change `cache_key_callback` to require the trusted scope from `RequestCtx` and
construct a versioned key:

```text
namespace = "proxy-http-cache-v2\0" + canonical origin
primary   = path + query
user_tag  = opaque cache scope
```

The callback must return an internal error if it is invoked without a scope or
for strict mode. This is defense in depth against a future lifecycle regression.
It must never fall back to an empty tag.

Key versioning ensures entries created by the vulnerable global scheme are not
addressable after the change. The current backend is process-local memory, so a
normal restart clears old objects. The `v2` namespace is still required to make
the migration explicit and to protect a future persistent backend or hot worker
transition.

Required key properties:

- Same scope and same canonical URL produce the same key.
- Different account, workspace, resolved isolation identity, or isolation group
  generation produces a different compact key.
- Host case and default-port spelling normalize consistently.
- Different schemes, hosts, effective ports, paths, or queries do not collide.
- The key and debug representation contain no raw tenant identifier or caller
  header.

### 5. Apply the same scope and policy on insertion

`response_cache_filter` must use `ctx` instead of ignoring it. Return
`Uncacheable` if:

- The request is strict.
- The trusted cache scope is absent.
- The canonical origin is no longer allowed.
- The request fails the conservative request checks.
- The response is not HTTP 200.
- `Set-Cookie` or any `Vary` header is present.
- `Cache-Control` is missing, invalid, not explicitly `public`, `private`,
  `no-store`, or lacks positive `s-maxage`/`max-age` freshness.
- Pingora's standard response cacheability helper rejects it.

This duplicates critical boundary checks intentionally. A future refactor that
accidentally enables lookup must not make response insertion global.

The allowlist is a local admission prerequisite. An exit-injected
`Cache-Control: public` can never add an origin to it.

### 6. Enforce a local freshness ceiling

After Pingora produces cache metadata, cap freshness locally:

```text
effective_ttl = min(
  origin-derived positive TTL,
  configured_max_ttl,
  compiled_absolute_max_ttl
)

fresh_until <= local admission time + effective_ttl
```

Do not trust an origin or exit `Date`, `Age`, `Expires`, `s-maxage`, or `max-age`
to extend the entry beyond the local admission deadline. The existing policy
already requires explicit positive `s-maxage` or `max-age`; preserve that rule
rather than falling back to `Expires` or implicit defaults.

Construct or replace `CacheMeta` so that:

- `fresh_until` is bounded by the local deadline.
- `stale_while_revalidate_sec` is zero.
- `stale_if_error_sec` is zero.
- The response headers retained by Pingora's conservative filter are preserved.
- Arithmetic overflow returns `Uncacheable` rather than an effectively infinite
  lifetime.

Disabling stale serving is intentional for plaintext HTTP: serving an expired
representation during an origin error would extend the replay window that this
fix is meant to bound. A future stale policy requires a separate security review
and must remain inside the same total residency ceiling.

The initial configured TTL should be 60 seconds. Operators may increase it only
up to the compiled 300-second maximum after measuring hit rate and accepting the
larger poisoning window. Raising the compiled maximum requires code review,
tests, and an explicit threat-model decision.

### 7. Remove the client-visible cache oracle

Stop adding `X-Proxy-Cache` to downstream production responses. Also remove any
origin- or exit-supplied `X-Proxy-Cache` before the response is delivered so it
cannot spoof an internal diagnostic.

Do not replace it with another exact hit/miss header. Cache operation should be
verified through controlled-origin request counts and aggregate internal
metrics.

Keep aggregate cache status in structured logs and Prometheus metrics because
the current records do not include URL, destination, account, workspace, or
isolation identity. Rename metric help text that says “shared cache” to
“tenant-scoped cache” after the key migration.

Recommended additional bounded metrics:

- Cache bypasses by fixed reason: strict, unauthenticated, origin not allowed,
  request policy, response policy, invalid TTL.
- TTL caps applied.
- Cache insertions accepted.
- Cache metadata construction failures.

Do not label metrics with tenant scope, cache key, origin, URL, or isolation
generation.

Removing the header eliminates the explicit exact-URL oracle. Cache timing can
still differ between a hit and a miss, but after correct partitioning that signal
is limited to a caller already authorized for the same account, workspace,
isolation subdivision, and generation. Do not claim that all timing side channels
are eliminated.

### 8. Preserve useful caching

The final behavior must retain this positive path:

1. An authenticated client sends a non-strict `GET` for an exact allowlisted
   HTTP origin.
2. The request contains no authorization or cookie state and does not prohibit
   caching.
3. The origin returns HTTP 200 with explicit public positive freshness and no
   `Set-Cookie` or `Vary`.
4. The first request fetches through Arti/Tor and inserts into that request's
   opaque scope with a locally bounded TTL.
5. A second request in the same scope and isolation generation is served from
   memory without another origin fetch.

The cache is narrower, not removed. It continues to reduce duplicate fetches for
reviewed public resources while respecting the proxy's authenticated privacy
boundaries.

## Implementation phases

### Phase 0 — Freeze the contract with failing tests

Add focused tests that demonstrate the current failures before changing the
implementation:

1. Same URL and different authenticated accounts currently produce the same
   cache key.
2. Same URL and different workspaces currently produce the same key.
3. Strict context currently enables cache access.
4. A very large positive `max-age` currently produces freshness beyond the
   proposed ceiling.
5. A client currently receives `X-Proxy-Cache`.

These tests should fail against the vulnerable behavior and pass only after the
corresponding phase. Do not rely exclusively on source searches.

**Gate:** The tests faithfully reproduce both reported issues without using a
live Tor exit.

### Phase 1 — Add validated policy configuration

1. Add the immutable `CachePolicy` and startup parser.
2. Canonicalize and validate exact HTTP origins.
3. Add the configured and compiled TTL limits.
4. Wire policy into `Proxy` construction.
5. Fail production startup on malformed or unsafe cache configuration.
6. Update the controlled test origin to appear in the deployment allowlist.

**Gate:** Configuration unit tests cover missing, empty, valid, duplicate,
mixed-case, default-port, wildcard, suffix-confusion, userinfo, path, query,
fragment, non-HTTP, local/private, and oversized TTL inputs.

### Phase 2 — Partition cache lookup and locking

1. Add `cache_scope` to `RequestCtx`.
2. Derive it only from authenticated, server-resolved context.
3. Add the centralized access decision.
4. Bypass strict and unauthenticated requests before cache enablement.
5. Add the v2 namespace and opaque `user_tag` to `CacheKey`.
6. Make missing scope an error in the key callback.

**Gate:** Cross-account, cross-workspace, cross-isolation, cross-generation, and
strict-mode tests prove that neither lookup nor lock coalescing crosses a
boundary. Same-scope repeated requests still hit.

### Phase 3 — Restrict insertion and cap lifetime

1. Require the trusted scope and exact origin allowlist in
   `response_cache_filter`.
2. Preserve the existing conservative request and response checks.
3. Bound `fresh_until` by the local configured and absolute ceilings.
4. Disable both stale mechanisms.
5. Treat invalid/overflowing metadata as uncacheable.
6. Record bounded admission and TTL-cap metrics.

**Gate:** An injected `public, max-age=4294967295` response cannot remain fresh
past the configured ceiling, cannot be served stale, and cannot enter another
scope.

### Phase 4 — Remove cache-status disclosure

1. Remove downstream insertion of `X-Proxy-Cache`.
2. Strip any upstream value with that name.
3. Keep aggregate internal cache metrics and privacy-bounded logs.
4. Rewrite controlled deployment cache verification to compare origin request
   counts and metric deltas instead of client headers.

**Gate:** No hit, miss, stale, or bypass response contains `X-Proxy-Cache`, while
the controlled test still proves that the second same-scope request avoided the
origin.

### Phase 5 — Integration and adversarial verification

Use a controlled HTTP origin and an optional test sidecar that can rewrite
responses as a malicious exit would. Do not depend on finding or operating a
malicious public Tor exit.

Run the full verification matrix below, followed by:

```bash
cargo fmt --check
cargo check --locked
cargo build --locked
cargo test --locked
git diff --check
```

Run any opt-in network tests only with explicitly configured controlled origins.

**Gate:** All deterministic tests pass, the controlled cache still records real
hits, and the evidence bundle contains no credentials, raw tenant identifiers,
isolation values, or browsing URLs beyond the deliberately controlled fixtures.

### Phase 6 — Documentation and controlled rollout

Update:

- `README.md` to replace “conservative shared caching” with authenticated,
  tenant/isolation-generation scoped caching for allowlisted plaintext HTTP.
- `FIX_PLAN.md` to mark its old shared-cache advice as superseded.
- `TESTING_GUIDELINES.md` with the new cross-tenant and poisoning matrix.
- `test-deployment.sh` so cache success is proved without `X-Proxy-Cache`.
- Metrics help strings that still describe a shared cache.

Deploy with a reviewed non-empty allowlist and the 60-second configured ceiling.
Observe hit rate, bypass reasons, origin request counts, evictions, memory use,
and TTL-cap events before expanding the allowlist.

**Gate:** Documentation, configuration, runtime behavior, and deployment tests
describe the same cache boundary.

## Required test matrix

### Cache scope and key tests

| Case | Expected result |
|---|---|
| Same account, workspace, isolation identity, generation, and URL | Same v2 key and cache hit |
| Different account; everything else equivalent | Different key; independent origin fetch |
| Same account, different workspace | Different key; independent origin fetch |
| Same workspace, different optional isolation subdivision | Different key; independent origin fetch |
| Same resolved identity, rotated isolation group | Different key; old entry inaccessible |
| Strict request repeated twice | Cache disabled both times; two Tor/origin fetches |
| Unauthenticated development request | Cache disabled |
| Client forges another `X-Proxy-Isolation` value under production auth | Value remains only a subdivision inside its authenticated tenant; cannot select another tenant's scope |
| Raw account/workspace identifiers searched in compact key/debug output | Absent |
| Host/absolute-URI disagreement | Request rejected before key creation |

### Origin policy tests

| Case | Expected result |
|---|---|
| Exact canonical allowlisted origin | Eligible for later response checks |
| Same host with normalized case/default port | Same allowlist decision |
| Subdomain of allowed host | Bypass unless separately listed |
| Suffix-confusion hostname | Bypass |
| Different port | Bypass unless separately listed |
| HTTPS scheme | Not handled by ordinary HTTP cache |
| Wildcard or `all` configuration | Startup error |
| URL with userinfo, path, query, or fragment in allowlist | Startup error |
| Local, loopback, link-local, private, or multicast literal origin | Startup error |
| Origin removed from configuration after restart | Old namespace entry inaccessible/bypassed |

### Request and response policy tests

| Case | Expected result |
|---|---|
| Plain GET, public positive freshness, no personalization | Cacheable within scope |
| Non-GET | Bypass |
| `Authorization` or `Cookie` request | Bypass |
| Request `private` or `no-store` | Bypass |
| Non-200 response | Uncacheable |
| Missing or invalid `Cache-Control` | Uncacheable |
| `private`, `no-store`, or non-public response | Uncacheable |
| `Set-Cookie` | Uncacheable |
| Any `Vary`, including `Vary: *` | Uncacheable |
| Zero freshness | Uncacheable |
| `s-maxage` and `max-age` both present | Pingora precedence preserved, then local cap applied |
| Maximum `u32` freshness | Capped without overflow |
| `stale-while-revalidate` injected | Stored stale allowance remains zero |
| `stale-if-error` injected | Stored stale allowance remains zero |
| Origin/exit injects `X-Proxy-Cache` | Header stripped downstream and from diagnostic contract |

### End-to-end isolation tests

The controlled origin should expose a deterministic request counter and response
body generation. Use separately provisioned accounts and workspaces.

1. Tenant A requests the allowlisted URL twice in one non-strict scope. The
   origin count increases once and bodies match.
2. Tenant B requests the same URL. The origin count increases again; Tenant B
   cannot receive Tenant A's cached body.
3. A second workspace in Tenant A requests the same URL. The origin count
   increases again.
4. A second isolation subdivision in the same workspace requests the URL. The
   origin count increases again.
5. Strict mode requests the URL twice. The origin count increases twice.
6. The isolation material rotates. A subsequent non-strict request cannot use
   the prior generation's entry.
7. A concurrent cold burst in one scope produces one origin request through the
   scoped cache lock.
8. Concurrent cold bursts in two scopes do not share a lock or body.
9. No response exposes cache status.
10. Metrics report aggregate hits, misses, bypasses, insertions, and TTL caps
    without tenant or destination labels.

### Malicious-exit simulation

Configure the controlled sidecar to transform a response into:

```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=4294967295, stale-if-error=4294967295
X-Proxy-Cache: HIT
```

and replace the body with a unique poisoned marker.

Verify:

1. A disallowed origin is never cached, regardless of injected headers.
2. For an allowlisted origin, the marker is confined to the requesting cache
   scope.
3. Strict requests never receive the cached marker.
4. Other tenants, workspaces, subdivisions, and generations never receive it.
5. The entry expires no later than the configured local TTL.
6. It is not served stale after expiry or error.
7. The injected `X-Proxy-Cache` never reaches the client.
8. After expiry, a fresh Tor/origin request is required.

This simulation demonstrates bounded amplification. It does not prove the
allowlisted plaintext response is authentic.

## Migration and deployment procedure

1. Inventory the existing controlled cache test origin and any real HTTP
   resources for which caching is operationally required.
2. Review each origin. Exclude login, account, API, software-update, executable,
   configuration, security-policy, and other integrity-sensitive resources.
3. Configure exact canonical origins and start with a 60-second TTL ceiling.
4. Deploy the code with the v2 key namespace. Restart the process so the old
   in-memory global cache is destroyed.
5. Confirm production startup logs only the count of configured origins, never
   their names.
6. Run same-scope positive cache verification.
7. Run cross-account, cross-workspace, strict, disallowed-origin, and injected
   long-TTL negative verification.
8. Confirm no downstream `X-Proxy-Cache` header exists.
9. Observe aggregate metrics during a limited canary period.
10. Expand the allowlist only through reviewed configuration changes.

Do not perform a mixed-version rollout against a future shared persistent cache.
All workers using the same backend must understand the same versioned key and
scope contract.

## Rollback procedure

Rollback must not restore the vulnerable empty-user-tag global key.

If the new cache logic causes functional problems:

1. Remove only the affected origin from the allowlist and restart. Other reviewed
   origins continue using the scoped cache.
2. If the key derivation or metadata code is faulty, stop accepting public
   traffic and deploy a corrected v2 build.
3. Do not roll back to a binary that permits strict, unauthenticated, or
   cross-tenant cache access.
4. Preserve the v2 namespace on compatible rollback builds.
5. Re-run the cross-tenant and TTL-ceiling gates before restoring traffic.

An emergency request-level bypass is acceptable as fail-safe behavior when cache
metadata is invalid; it is not the intended steady-state architecture and does
not change the requirement that caching remain active for approved traffic.

## Definition of done

This plan is complete only when:

- The physical memory cache and LRU remain active for approved traffic.
- Production cache access requires successful authentication.
- Strict mode bypasses reads, locks, writes, and stale service.
- Keys include a versioned opaque account/workspace/isolation-generation scope.
- Different tenants, workspaces, subdivisions, and generations cannot collide or
  coalesce cache locks.
- Only exact locally allowlisted HTTP origins can be cached.
- Effective freshness is capped at the configured ceiling and the compiled
  absolute maximum.
- Stale serving is disabled for plaintext HTTP cache entries.
- `X-Proxy-Cache` is absent from downstream responses, including when injected
  upstream.
- Controlled tests demonstrate a real same-scope hit without a second origin
  fetch.
- Malicious-exit simulation demonstrates that poisoned content is scope- and
  time-bounded.
- Logs and metrics contain no raw tenant, isolation, origin, or URL labels.
- README, testing guidance, deployment scripts, and metrics describe the same
  behavior.
- `cargo fmt --check`, `cargo check --locked`, `cargo build --locked`,
  `cargo test --locked`, and `git diff --check` pass.

## Source locations for implementation

The line numbers below describe the code at the time this plan was written and
must be refreshed if `src/main.rs` moves:

| Area | Current location |
|---|---|
| Global cache, lock, eviction, and size constants | `src/main.rs:75-82` |
| Canonical authority and URL key parts | `src/main.rs:1094-1138` |
| Request eligibility and response admission | `src/main.rs:1140-1196` |
| Cache status mapping | `src/main.rs:1198-1206` |
| `RequestCtx` isolation and cache fields | `src/main.rs:1547-1560` |
| Plaintext ordinary-HTTP upstream selection | `src/main.rs:2866-2911` |
| Authenticated identity and isolation resolution | `src/main.rs:2929-3000` |
| Cache enablement | `src/main.rs:3002-3024` |
| Current unscoped cache key | `src/main.rs:3026-3034` |
| Response cache admission | `src/main.rs:3036-3050` |
| Downstream `X-Proxy-Cache` insertion | `src/main.rs:3066-3085` |
| Aggregate cache logging and metrics | `src/main.rs:3106-3134` |
| Current cache unit tests | `src/main.rs:5378-5436` |
| Header-based deployment cache test | `test-deployment.sh:471-495` |

## Superseded guidance

The cache section in root `FIX_PLAN.md` recommends a conservative shared cache
and a downstream `X-Proxy-Cache` header. Those recommendations predate
authenticated account/workspace isolation and are superseded by this plan. The
existing request/response eligibility, object-size, cache-lock, and LRU guidance
remains useful where it does not conflict with the scoped design above.
