# Destination Port and Address Policy Fix Plan

- **Plan timestamp:** 2026-08-17T10:48:21Z
- **Status:** Proposed; not implemented
- **Scope:** Destination authority parsing, TCP port abuse controls, IP-literal
  classification, and enforcement before Arti stream creation
- **Security priority:** High
- **Primary implementation file:** `src/main.rs`

## Purpose

The proxy currently accepts every syntactically valid, nonzero destination port.
It also treats an IPv4-mapped IPv6 literal as ordinary IPv6, allowing forms such
as `[::ffff:127.0.0.1]:443` to evade the IPv4 loopback and private-address
checks. This plan introduces one canonical destination-policy architecture that:

1. Allows only explicitly approved TCP destination ports.
2. Enforces a non-overridable deny floor for SMTP transfer and submission ports.
3. Rejects IPv4-mapped, deprecated IPv4-compatible, and other ambiguous
   IPv4-embedded IPv6 literals.
4. Rejects reviewed IPv4 and IPv6 special-purpose ranges through one typed
   classifier.
5. Applies the same final policy to public CONNECT tunnels and ordinary HTTP
   requests before `TorClient::connect_with_prefs`.
6. Returns stable client errors and privacy-safe rejection metrics without
   logging destinations.

The service must own this abuse boundary. Tor exit policies remain defense in
depth and are not a substitute for local authorization.

## Current implementation and weaknesses

### Any nonzero port is accepted

`parse_connect_destination` requires an explicit nonzero port, but
`connect_destination_allowed` does not evaluate it. Therefore ports associated
with SMTP transfer/submission, scanners, databases, administration protocols,
or any other TCP service are admitted whenever the selected Tor exit permits
them.

Authentication, quotas, rate limits, and Tor exit policies reduce some abuse
risk, but they do not answer the basic authorization question: which destination
ports is this product intentionally designed to reach?

### IPv4-mapped IPv6 bypass

The current address match calls IPv4-specific methods only for
`IpAddr::V4`. An address in the IPv4-mapped IPv6 range is parsed as
`IpAddr::V6`, then checked only for IPv6 loopback, unspecified, multicast,
unique-local, and link-local status.

For example:

```text
[::ffff:127.0.0.1]:443
```

is neither IPv6 loopback nor IPv6 unique-local, even though its embedded IPv4
address is `127.0.0.1`. Equivalent hexadecimal and expanded textual forms create
the same problem.

The IANA IPv6 Special-Purpose Address Registry marks IPv4-mapped addresses as
not valid globally reachable destinations. RFC 4291 also defines the mapped form
as a representation of IPv4 nodes, not an independent public IPv6 destination.

### Authority handling is fragmented

The current bridge parses the same destination separately in:

- `parse_connect_destination`, which creates a `TorAddr`.
- `canonical_connect_destination_key`, which creates a circuit-breaker key.
- `connect_destination_allowed`, which performs hostname and IP checks.

Separate parsing and normalization paths can disagree. A future fix in one
function may not protect the other two. The Tor target is also created before
the local policy result is known.

### The bridge is the final common enforcement point

Public CONNECT requests call `handle_connect_request` directly. Ordinary HTTP
requests enter Pingora, which asks the protected Unix-socket bridge for a CONNECT
stream to the origin; that internal request also reaches `handle_connect_request`.
Both paths therefore converge immediately before circuit-breaker admission,
capacity acquisition, and `TorClient::connect_with_prefs`.

The bridge must remain authoritative. Pingora should add an earlier check for
clear ordinary-HTTP `403` responses and to prevent disallowed cache lookups, but
an early check alone is insufficient because alternate or future ingress paths
could bypass it.

## Security objectives

The implementation is acceptable only when these invariants hold:

1. No Arti stream attempt occurs before destination syntax, port, hostname, and
   IP-literal policy succeed.
2. The circuit breaker, retry loop, and capacity semaphores receive only an
   already-approved canonical destination.
3. Port `0`, a missing port on CONNECT, and out-of-range ports are invalid.
4. Only configured exact ports are allowed; there is no `*`, `all`, or implicit
   “any nonzero port” mode.
5. TCP ports `25`, `465`, and `587` cannot be enabled by deployment
   configuration.
6. The default approved port set is limited to `80` and `443`.
7. All textual forms of an equivalent IP literal receive the same decision.
8. IPv4-mapped and deprecated IPv4-compatible IPv6 literals are rejected,
   including when the embedded IPv4 address is written in hexadecimal IPv6
   form.
9. Loopback, private, link-local, multicast, unspecified, documentation,
   benchmarking, reserved, and other locally reviewed non-public literal ranges
   are rejected for both address families.
10. A cached response cannot make a newly disallowed destination reachable.
11. Rejected destinations do not consume circuit-build or active-tunnel permits
    and do not create circuit-breaker entries.
12. Logs and metrics expose only a bounded rejection reason, never a hostname,
    IP address, port, authority, account, or URL.

## Non-goals and residual risk

A TCP port allowlist is an abuse-control boundary, not protocol detection. A
remote service can run SMTP or another abusive protocol on port 80 or 443. Keep
authenticated ingress, customer rate limits, quotas, concurrency caps, complaint
handling, and emergency account suspension as independent controls.

The proxy deliberately preserves remote DNS resolution through Arti. It must not
perform local DNS resolution merely to inspect the returned address because that
would leak destinations and could disagree with the Tor exit's resolution.
Consequently:

- This plan fully covers literal-address representations.
- It continues to reject local and special-use hostname suffixes.
- It does not prove that an arbitrary public-looking domain will never resolve
  to a non-public address at the exit.

If stronger domain-to-address enforcement becomes a requirement, use a separate
domain allowlist or a reviewed Tor-side resolved-address policy. Do not silently
introduce local DNS.

This plan also does not create per-account destination policies. The initial
single-tier service receives one global policy. Per-account or per-workspace
exceptions need separate authorization, persistence, audit, and product rules.

## Target architecture

```text
raw authority from public CONNECT or Pingora bridge CONNECT
  -> one strict authority parser
  -> canonical host + explicit nonzero u16 port
  -> immutable SMTP deny floor
  -> exact configured port allowlist
  -> canonical host classifier
       domain
         -> local/special suffix check
         -> ambiguous numeric-hostname check
       IPv4 literal
         -> reviewed special-purpose CIDR check
       IPv6 literal
         -> mapped/compatible/translation-form check
         -> reviewed special-purpose CIDR check
  -> AllowedDestination
       canonical authority
       canonical circuit-breaker key
       canonical TorAddr
  -> circuit breaker
  -> capacity admission
  -> Arti/Tor connect
```

Only `AllowedDestination` may cross the boundary into circuit and connection
code. Callers must not pass an unchecked string to `connect_with_retry`.

## Proposed types and ownership

### DestinationPolicy

Create one immutable, clonable policy parsed at startup:

```text
DestinationPolicy
  allowed_ports: sorted exact set of NonZeroU16
  hard_blocked_ports: compiled exact set
  additional_blocked_ports: sorted exact set
  denied_domain_suffixes: compiled normalized set
  ipv4_special_ranges: reviewed typed CIDR set
  ipv6_special_ranges: reviewed typed CIDR set
```

Wrap it in `Arc<DestinationPolicy>` and pass the same instance to:

- `Bridge`, for mandatory final enforcement on public and internal CONNECT.
- `Proxy`, for early ordinary-HTTP rejection before cache lookup and upstream
  selection.

Parse and validate the policy before bootstrapping Arti. Invalid security policy
must fail startup without opening public listeners.

### AllowedDestination

Replace the separate parse, canonical-key, and boolean-policy results with one
typed success value:

```text
AllowedDestination
  canonical_host: CanonicalHost
  port: NonZeroU16
  canonical_authority: String
  circuit_breaker_key: String
  tor_addr: TorAddr
```

`canonical_authority` and `circuit_breaker_key` may be the same normalized
authority initially, but keep access through methods rather than rebuilding the
string at call sites.

Construct `TorAddr` only after every local policy check passes. Construct it from
the canonical authority, not the raw client string.

### CanonicalHost

Use a typed host result:

```text
CanonicalHost
  Domain(normalized ASCII domain)
  Ipv4(Ipv4Addr)
  Ipv6(Ipv6Addr)
```

Do not make policy decisions using string prefixes after an address has parsed
as an IP literal.

### DestinationRejection

Return a bounded typed error:

```text
DestinationRejection
  InvalidAuthority
  MissingPort
  InvalidPort
  HardBlockedPort
  PortNotAllowed
  LocalHostname
  AmbiguousNumericHostname
  Ipv4MappedIpv6
  Ipv4CompatibleIpv6
  Ipv4TranslationLiteral
  SpecialPurposeIpv4
  SpecialPurposeIpv6
  TorAddressRejected
```

The client response and metric label come from the enum. The error's production
`Display` implementation must not include the raw destination. Tests may inspect
a separately constructed fixture description.

## Port abuse policy

### Exact allowlist

Add a startup setting:

| Setting | Default | Meaning |
|---|---|---|
| `PROXY_ALLOWED_DESTINATION_PORTS` | `80,443` | Comma-separated exact TCP ports allowed for both ordinary HTTP and CONNECT |
| `PROXY_ADDITIONAL_BLOCKED_DESTINATION_PORTS` | Empty | Optional exact ports blocked in addition to the immutable floor |

Initial parsing rules:

- Accept decimal integers only.
- Reject zero and values above `65535`.
- Reject empty elements, signs, hexadecimal, service names, ranges, whitespace
  inside a number, `*`, and `all`.
- Sort and deduplicate.
- Limit each configured set to at most 64 entries.
- Require at least one allowed port.
- Reject any overlap between allowed and blocked sets.
- Reject startup if the allowed set contains a hard-blocked port.

Exact values are intentionally less flexible than ranges. They are easier to
review and make it difficult to accidentally authorize thousands of services.

### Immutable SMTP deny floor

Hard-block at least:

| Port | Registered service | Local policy |
|---:|---|---|
| `25/tcp` | SMTP transfer | Never allowed |
| `465/tcp` | Message submission over TLS | Never allowed |
| `587/tcp` | Message submission | Never allowed |

These ports are registered for mail transfer or submission in the IANA Service
Name and Transport Protocol Port Number Registry. The code should name the
reason `email_delivery` in comments, but production metrics should use the
generic bounded reason `hard_blocked_port`.

Alternative or unregistered SMTP ports remain denied by the default exact
allowlist. If an operator proposes adding another port, that is an explicit
security review rather than an automatic exception.

Do not make the hard floor configurable through environment variables. Changing
it requires code review, tests, and an explicit product/legal abuse decision.

### Default and exceptional behavior

The default `80,443` set supports the product's ordinary web use case. A customer
requirement for another protocol or alternate web port must be handled by a
reviewed deployment configuration change.

The initial architecture is global: adding an allowed port enables it for every
authenticated tenant on that appliance. Do not add a port to satisfy one
customer if the same appliance serves unrelated tenants. If per-customer
exceptions become necessary, first add an authenticated policy identifier to
account/workspace state and make the bridge verify it through the existing
opaque identity lease.

## Canonical address policy

### Parse once

The evaluator must:

1. Parse the raw value as `http::uri::Authority`.
2. Require an explicit nonzero port at the bridge boundary.
3. Extract the host once.
4. Remove IPv6 brackets only as part of structured authority handling.
5. Normalize a domain by ASCII lowercase and one terminal root dot.
6. Parse the normalized host as `IpAddr`.
7. If it is not an IP, validate it as a domain and reject ambiguous numeric
   spellings.
8. Apply port and host policy.
9. Build one canonical authority and then `TorAddr`.

Do not call `TorAddr::from(raw_destination)` before local evaluation.

### Reject IPv4-mapped IPv6

Reject the complete IPv4-mapped IPv6 form, not only the dotted-decimal spelling.
Tests must include:

```text
[::ffff:127.0.0.1]:443
[::ffff:7f00:1]:443
[0:0:0:0:0:ffff:7f00:1]:443
[::ffff:8.8.8.8]:443
```

The public mapped form is also rejected. A client that genuinely wants a public
IPv4 literal can use its canonical IPv4 form. Rejecting the mapped form entirely
avoids dual interpretation between the HTTP parser, local policy, Arti, Tor
protocol, and exit operating system.

Use the standard library's structured IPv4-mapped detection where available.
Do not detect only the textual prefix `::ffff:` because expanded and hexadecimal
forms would bypass it.

### Reject deprecated IPv4-compatible IPv6

Reject deprecated IPv4-compatible forms in `::/96`, including:

```text
[::127.0.0.1]:443
[::7f00:1]:443
```

RFC 4291 deprecated this representation, and RFC 5156 says compatible and
mapped forms should not appear on the public Internet. There is no product need
to accept them when canonical IPv4 exists.

Take care not to classify `::` or `::1` as acceptable embedded IPv4; they are
already rejected as unspecified and loopback.

### Reject standardized IPv4-translation literals

Reject literal destinations in the standardized IPv4/IPv6 translation prefixes
`64:ff9b::/96` and `64:ff9b:1::/48`. These forms can embed an IPv4 address and
reintroduce disagreement about whether the embedded address or outer IPv6
address controls policy. A public IPv4 destination can be expressed directly.

This is a literal-only rule. It does not attempt local DNS or infer how an exit's
network performs translation.

### Use a reviewed special-purpose range table

The current standard-library predicates do not express one durable product
policy for all IANA special-purpose ranges. Define reviewed typed CIDR tables
for IPv4 and IPv6. At minimum cover:

#### IPv4

- Unspecified/current-network space.
- Private-use ranges.
- Shared address space/CGNAT.
- Loopback.
- Link-local.
- Protocol-assignment and special-purpose ranges that are not globally
  reachable.
- Documentation ranges.
- Benchmarking ranges.
- Multicast.
- Reserved/future-use and limited broadcast.

#### IPv6

- Unspecified and loopback.
- IPv4-mapped and compatible forms.
- Translation prefixes listed above.
- Discard-only space.
- Unique-local.
- Link-local.
- Documentation and benchmarking ranges.
- Multicast.
- Other IANA entries marked not globally reachable for the reviewed snapshot.

Use a typed CIDR representation. If a small direct dependency is adopted for
prefix membership, pin it through `Cargo.lock` and review its behavior. If the
repository avoids a new dependency, implement one minimal byte-prefix matcher
with exhaustive boundary tests; do not scatter handwritten masks across policy
branches.

Record the IANA registry review date next to the table. Registry updates should
be applied through deliberate code review, never fetched at runtime.

### Reject ambiguous numeric hostnames

Some resolvers historically accept noncanonical numeric spellings such as a
single integer, shortened dotted forms, octal-looking components, or hexadecimal
forms. If Rust does not parse such a value as `IpAddr`, treating it as an
ordinary domain could move interpretation to Arti or the exit resolver.

Reject numeric-looking hosts that fail canonical `IpAddr` parsing, including a
reviewed corpus such as:

```text
127.1
2130706433
0177.0.0.1
0x7f000001
```

The detection must be conservative and tested. A normal domain with alphabetic
labels and a valid public suffix should not be rejected merely because one label
contains digits.

### Preserve domain privacy

Continue rejecting the existing local/special suffixes after lowercase and
terminal-dot normalization:

```text
localhost
.localhost
.local
.internal
.home
.lan
```

Do not log the rejected name and do not resolve it locally. Domain-suffix policy
is a coarse defense; it is not a claim that all other domains resolve publicly.

## Enforcement architecture

### Startup

In `main`:

1. Parse `DestinationPolicy::from_environment()` before Arti bootstrap.
2. Reject invalid configuration and exit before listeners start.
3. Wrap the validated policy in `Arc`.
4. Pass it into `TorCircuit::start_bridge` and the Pingora `Proxy` instance.
5. Log only a policy version/fingerprint, allowed-port count, additional-block
   count, and registry-table version. The exact configured ports may be recorded
   in the private deployment configuration, not repeated in per-request logs.

### Early ordinary-HTTP check

In Pingora `request_filter`, after trusted authentication context is established
but before cache access:

1. Derive the effective authority from the validated `Host` and request URI.
2. Supply the default port only according to ordinary-HTTP parsing rules.
3. Evaluate the shared policy.
4. On rejection, send `403 Forbidden`, mark a bounded policy reason, and return
   without enabling cache or selecting an upstream.
5. Store the canonical authority in `RequestCtx` for isolation and cache
   consistency.

The ordering must be:

```text
authentication and account admission
  -> destination policy
  -> isolation derivation
  -> cache decision
  -> upstream selection
```

This prevents a cache hit from serving a destination that the current policy no
longer allows.

### Mandatory bridge check

In `handle_connect_request`:

1. Evaluate the raw internal/public CONNECT authority exactly once.
2. Map malformed authority/port errors to `400 Bad Request`.
3. Map local policy denial to `403 Forbidden`.
4. Only after success, use `AllowedDestination` for the circuit-breaker key and
   Tor target.
5. Then evaluate circuit-breaker, account-tunnel, global-tunnel, circuit-build,
   and retry controls in the existing order.

The bridge must re-evaluate internal Pingora requests. Do not trust a
client-supplied “already validated” header. A future optimization may transport
a typed in-process value, but the Unix CONNECT boundary remains independently
validated.

### Connection API hardening

Change `connect_with_retry` to accept `AllowedDestination` or a narrower
`ApprovedTorTarget` wrapper rather than a freely constructed `TorAddr`. Make the
unchecked constructor private to the policy module/section.

This type boundary makes it difficult for future call sites to open an Arti
stream without policy evaluation. A source search for
`connect_with_prefs`, `TorAddr::from`, and destination socket constructors must
confirm there is no bypass.

## Client errors and observability

### Error mapping

| Condition | Client status | Internal class |
|---|---:|---|
| Malformed authority, missing/zero/out-of-range port | `400` | `invalid_destination` |
| Hard-blocked port | `403` | `hard_blocked_port` |
| Port absent from allowlist | `403` | `port_not_allowed` |
| Local/special hostname | `403` | `local_hostname` |
| Ambiguous numeric hostname | `403` | `ambiguous_numeric_host` |
| Mapped/compatible/translation IPv6 literal | `403` | `embedded_ipv4_literal` |
| Other special-purpose IPv4/IPv6 literal | `403` | `special_purpose_ip` |
| Internal policy/configuration failure after startup | `503` | `policy_unavailable` |

Ordinary HTTP and public CONNECT should expose the same `400` versus `403`
semantics. If Pingora receives a bridge `403` after the early check, preserve it
as a local policy response rather than converting it into a generic `502`.

Do not send the blocked port, address, hostname, or exact reason phrase in the
body. A generic response is sufficient.

### Metrics

Add an aggregate metric such as:

```text
proxy_destination_policy_rejections_total{reason="port_not_allowed"}
```

The `reason` label must come from the fixed enum above. Do not label by port,
host, IP family, tenant, workspace, URL, or raw authority. Keep the metrics
endpoint loopback-only.

Add tests proving that rejected requests do not increment:

- Circuit-build attempts.
- Tor-connect latency/count.
- Retry counts.
- Active or completed tunnel counts.
- Circuit-breaker entry count.

Structured logs should record only the event, public method class, response
status, and bounded rejection reason.

## Implementation phases

### Phase 0 — Reproduce and freeze the vulnerabilities

Add failing tests against current behavior:

1. `example.com:25`, `:465`, and `:587` are currently accepted by
   `connect_destination_allowed`.
2. `[::ffff:127.0.0.1]:443` is currently accepted.
3. The expanded hexadecimal mapped form is currently accepted.
4. `parse_connect_destination`, canonical breaker-key construction, and policy
   evaluation are independent calls.

**Gate:** The tests demonstrate both reported failures without contacting Tor or
an external service.

### Phase 1 — Add policy configuration and typed decisions

1. Implement the exact-port configuration parser.
2. Add the immutable SMTP deny floor.
3. Add `DestinationPolicy`, `AllowedDestination`, `CanonicalHost`, and
   `DestinationRejection`.
4. Parse policy before Arti bootstrap.
5. Pass one `Arc<DestinationPolicy>` into Bridge and Proxy.

**Gate:** Configuration and type-level unit tests pass, and no listener starts
when configuration is invalid.

### Phase 2 — Unify authority parsing and canonicalization

1. Replace the three separate destination helpers with one evaluator.
2. Build the canonical circuit-breaker key and `TorAddr` from the success value.
3. Reject mapped, compatible, and translation IPv6 forms structurally.
4. Reject ambiguous numeric hostnames.
5. Add the reviewed IPv4/IPv6 special-purpose range tables.

**Gate:** Equivalent textual forms produce identical allowed results or the same
bounded rejection class; no raw destination reaches `TorAddr::from` elsewhere.

### Phase 3 — Enforce at Pingora and bridge boundaries

1. Add the early ordinary-HTTP policy check before cache lookup.
2. Make the bridge evaluator mandatory for every public and internal CONNECT.
3. Change `connect_with_retry` to accept only an approved target wrapper.
4. Ensure policy rejection occurs before circuit-breaker and capacity state.
5. Preserve `400`/`403` semantics through Pingora.

**Gate:** Both ordinary HTTP and CONNECT deny disallowed ports and mapped
addresses without a Tor attempt, including when cache state exists.

### Phase 4 — Add metrics and privacy-safe operations

1. Add bounded rejection counters.
2. Add privacy-safe structured policy events.
3. Update Prometheus rendering and tests.
4. Document configuration ownership and change review.
5. Add an emergency account-suspension link to the operations runbook without
   logging destinations.

**Gate:** Metrics distinguish operational causes without destination or tenant
labels.

### Phase 5 — Full verification and controlled rollout

Run:

```bash
cargo fmt --check
cargo check --locked
cargo build --locked
cargo test --locked
git diff --check
```

Run opt-in network tests only against controlled HTTP/HTTPS services on approved
ports. Do not test SMTP by connecting to public mail servers. A local fake
connector or controlled fixture must prove that mail ports are rejected before
network activity.

**Gate:** The complete matrix below passes, configuration and documentation
agree, and packet/network observations show no connection attempt for rejected
fixtures.

## Required test matrix

### Port parser and policy

| Case | Expected result |
|---|---|
| Default configuration | Exactly `80` and `443` allowed |
| Allowed `80` or `443` | Approved if host policy also passes |
| Port `0` | Invalid `400` |
| Missing CONNECT port | Invalid `400` |
| Port `65536` | Invalid `400` |
| Port `25`, `465`, or `587` | Policy `403` |
| Hard-blocked port present in allowlist config | Startup failure |
| Unlisted port `22`, `53`, `8080`, or `8443` | Policy `403` by default |
| Explicit reviewed `8080` or `8443` | Allowed after restart if not additionally blocked |
| Empty allowed set | Startup failure |
| Duplicate allowed port | Canonically deduplicated or rejected consistently |
| More than 64 configured entries | Startup failure |
| Range, wildcard, service name, sign, or hexadecimal input | Startup failure |
| Port in both allowed and additional-blocked sets | Startup failure |

### IPv4 literals

Test the first, last, and adjacent address around every denied CIDR. Include:

- Unspecified/current network.
- `10.0.0.0/8`.
- `100.64.0.0/10`.
- `127.0.0.0/8`.
- `169.254.0.0/16`.
- `172.16.0.0/12`.
- `192.168.0.0/16`.
- IANA special-protocol ranges in the reviewed table.
- Documentation ranges.
- `198.18.0.0/15` benchmarking.
- Multicast and reserved/future-use ranges.
- Limited broadcast.
- At least two known public IPv4 fixtures accepted by the classifier, without
  opening a network connection.

### IPv6 literals

| Case | Expected result |
|---|---|
| `::` and `::1` | Rejected |
| `fc00::/7` unique-local | Rejected |
| `fe80::/10` link-local | Rejected |
| `ff00::/8` multicast | Rejected |
| Documentation/benchmark/discard-only fixtures | Rejected |
| `[::ffff:127.0.0.1]:443` | Rejected as embedded IPv4 |
| `[::ffff:7f00:1]:443` | Same rejection |
| Expanded mapped form | Same rejection |
| `[::ffff:8.8.8.8]:443` | Rejected; client must use canonical IPv4 |
| `[::127.0.0.1]:443` and `[::7f00:1]:443` | Rejected as compatible form |
| `64:ff9b::/96` fixture | Rejected as translation form |
| `64:ff9b:1::/48` fixture | Rejected as translation form |
| Known public global IPv6 fixture | Accepted by classifier without network activity |

### Domain names and authority canonicalization

| Case | Expected result |
|---|---|
| `Example.COM.:443` | Canonical `example.com:443` |
| `localhost` and local suffix variants with case/root dot changes | Rejected |
| Host with userinfo | Invalid |
| Empty host | Invalid |
| Bracketless IPv6 authority | Invalid |
| IPv6 zone identifier | Invalid/rejected |
| `127.1`, `2130706433`, `0177.0.0.1`, `0x7f000001` | Rejected as ambiguous numeric host |
| Normal domain containing digits | Accepted if otherwise valid |
| Canonical value passed to breaker and Tor target | Identical authority |

### Enforcement-path integration

Use an injectable fake Tor connector or counter:

1. Public CONNECT to `example.com:25` returns `403`; connector count remains
   zero.
2. Ordinary HTTP to an unlisted port returns `403`; cache and connector counts
   remain zero.
3. Public CONNECT and ordinary HTTP to mapped loopback return `403`; connector
   count remains zero.
4. A manually constructed internal bridge CONNECT cannot bypass the final
   policy.
5. Allowed ordinary HTTP on port 80 reaches the fake connector.
6. Allowed CONNECT on port 443 reaches the fake connector.
7. Rejected requests do not allocate circuit-breaker entries or permits.
8. Policy metrics increment once with the correct bounded reason.
9. No response or log contains the rejected authority.
10. A previously cached URL on a now-disallowed port cannot be served because
    the early policy check precedes cache lookup.

### Property and fuzz tests

Add table-driven/property coverage for:

- Equivalent compressed, expanded, uppercase, and mixed IPv6 text.
- Every IPv4 address embedded in mapped and compatible IPv6 prefixes.
- Port parser input around `0`, `1`, `65535`, and `65536`.
- Arbitrary authority punctuation, brackets, trailing dots, percent characters,
  whitespace, and control bytes.
- The invariant that policy success is required to construct an approved Tor
  target.

The evaluator must never panic on untrusted authority input.

## Deployment procedure

1. Inventory the product's intended destination protocols without enabling
   destination logging. Use product requirements and controlled test
   configuration, not customer browsing histories.
2. Start with the default `80,443` set.
3. Identify any controlled health checks currently using alternate ports and
   either move them to an approved port or document a reviewed exception.
4. Deploy configuration parsing and policy code together.
5. Restart so all listeners and Bridge/Proxy instances share the same immutable
   policy.
6. Verify allowed HTTP and HTTPS CONNECT against controlled origins.
7. Verify SMTP ports, an unlisted benign port, IPv4 loopback/private, mapped
   IPv6, compatible IPv6, and translation prefixes using local fake connectors.
8. Confirm policy rejections produce no Tor connection attempts.
9. Confirm rejection metrics remain low and contain no destination labels.
10. Add alternate ports only through explicit configuration review and restart.

Do not introduce a permissive runtime “audit-only” mode that continues opening
blocked connections. Compatibility must be assessed before production or with a
controlled staging appliance.

## Rollback procedure

Rollback must not restore “any nonzero port” or the mapped-IPv6 bypass.

If a legitimate workflow is blocked:

1. Confirm the required protocol and abuse implications.
2. Add one exact non-hard-blocked port to the reviewed allowlist.
3. Re-run port, address, privacy, and no-bypass tests.
4. Restart with the new immutable policy.

If the implementation itself fails:

1. Stop accepting public traffic.
2. Deploy a corrected build that preserves the exact allowlist, SMTP deny floor,
   and embedded-IPv4 rejection.
3. Do not roll back to the vulnerable boolean helper.
4. Re-run deterministic policy tests before reopening ingress.

## Documentation updates required during implementation

- Update the README destination-safety section from “should restrict ports” to
  the implemented exact policy and configuration.
- Add the port and IP-literal matrix to `TESTING_GUIDELINES.md`.
- Add controlled negative cases to `test-deployment.sh` without contacting
  public mail services.
- Update `src/ROADMAP.md` or the relevant completion ledger when gates pass.
- Cross-reference the cache-isolation plan because destination policy must run
  before cache lookup.
- Record the reviewed IANA special-purpose registry snapshot date.

## Definition of done

This work is complete only when:

- One `DestinationPolicy` instance is parsed before Arti bootstrap and shared by
  Proxy and Bridge.
- The bridge remains the mandatory final policy boundary for public and internal
  CONNECT.
- Ordinary HTTP performs the same policy check before cache access.
- Only exact configured ports are permitted, defaulting to `80,443`.
- Ports `25`, `465`, and `587` cannot be enabled through configuration.
- Mapped, compatible, and standardized translation IPv6 literals are rejected.
- Reviewed IPv4/IPv6 special-purpose CIDR tables replace scattered predicate
  logic.
- `AllowedDestination` is the only route to circuit-breaker and Arti connection
  code.
- Public CONNECT and ordinary HTTP return consistent `400`/`403` results.
- Rejected requests do not touch Tor, retries, breaker entries, cache, or
  capacity permits.
- Metrics and logs expose only bounded rejection classes.
- Full unit, integration, adversarial, and property/fuzz matrices pass.
- README, testing guidance, deployment configuration, and runtime behavior agree.
- `cargo fmt --check`, `cargo check --locked`, `cargo build --locked`,
  `cargo test --locked`, and `git diff --check` pass.

## Current source locations

The line numbers below describe the code when this plan was written and must be
refreshed if `src/main.rs` moves:

| Area | Current location |
|---|---|
| CONNECT parsing | `src/main.rs:1316-1413` |
| `TorAddr` construction and nonzero-port check | `src/main.rs:1415-1429` |
| Separate circuit-breaker key canonicalization | `src/main.rs:1431-1450` |
| Current hostname/IP boolean policy | `src/main.rs:1452-1493` |
| `Proxy` and `RequestCtx` | `src/main.rs:1538-1560` |
| Bridge structure and construction | `src/main.rs:2734-2804`, `3168-3193` |
| Ordinary HTTP upstream selection | `src/main.rs:2866-2911` |
| Pingora request filtering before cache | `src/main.rs:2929-3024` |
| Public CONNECT dispatch | `src/main.rs:3542-3555` |
| Internal Pingora-to-Bridge CONNECT | `src/main.rs:3610-3646` |
| Arti connection call | `src/main.rs:3648-3705` |
| Mandatory common CONNECT handler | `src/main.rs:3707-3750` |
| Startup and Proxy/Bridge wiring | `src/main.rs:4037-4105` |
| Existing destination unit tests | `src/main.rs:4738-4754`, `5369-5376` |
| Current README destination policy | `README.md:195-200` |

## Primary external references

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- [IANA IPv4 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [IANA IPv6 Special-Purpose Address Space](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
- [RFC 4291: IP Version 6 Addressing Architecture](https://www.rfc-editor.org/rfc/rfc4291.html)
- [RFC 5156: Special-Use IPv6 Addresses](https://www.rfc-editor.org/rfc/rfc5156.html)
- [RFC 6890: Special-Purpose Address Registries](https://www.rfc-editor.org/rfc/rfc6890.html)

## Evidence boundary

This document is an implementation plan. It does not claim that port controls,
mapped-address rejection, special-purpose CIDR tables, new metrics, or the
verification matrix are implemented. Tor exit-policy behavior and successful
unit tests alone are not evidence that this service's local abuse controls are
complete.
