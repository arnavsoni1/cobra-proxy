# Private Circuit-Isolation Proxy

> **Private and confidential**  
> This repository and its documentation are not open source. Access does not grant permission to copy, redistribute, sublicense, publish, reverse engineer, or commercialize the original software. A signed agreement should govern access by contractors, partners, and customers.

This project is a high-performance forward proxy that sends outbound traffic through the Tor network using Arti. Its defining feature is explicit circuit separation: traffic assigned to different isolation identities is prevented from sharing the same Tor circuit.

The service is designed for controlled, low-volume research and privacy-sensitive automation. It is not a consumer VPN, an open proxy, a Tor exit relay, a high-throughput scraping network, or a guarantee of anonymity.

## What the service does

The proxy accepts ordinary HTTP requests and HTTPS tunnels from a local client. It validates the destination, applies an isolation policy, waits for safe local capacity, and then opens the outbound connection through an embedded Arti client.

Two isolation modes are available:

- **Session isolation** keeps traffic in the same authenticated account/workspace, canonical destination, and optional caller sub-identity eligible to reuse the same isolation group. Different authenticated scopes or destinations cannot share a circuit or a pooled upstream connection.
- **Strict isolation** creates a fresh isolation group for each request or tunnel and disables connection reuse where necessary. This is considerably slower and places more load on the Tor network, so it should be reserved for small numbers of genuinely sensitive connections.

Authenticated production ingress derives isolation from the account, workspace,
and canonical destination automatically. `X-Proxy-Isolation` is an optional
subdivision inside that tenant boundary, never the boundary itself. The
loopback plaintext development mode retains the older behavior of generating a
fresh ephemeral identity when the header is absent.

Circuit isolation means that unrelated streams do not share the same circuit. It does not guarantee a unique exit IP, prevent the Tor network from independently selecting the same exit relay, defeat browser fingerprinting, or stop a sufficiently capable observer from performing timing correlation.

## Intended deployment

The current deployment model is a single private instance on a Linux VPS.
Development listeners are loopback-only or local-machine-only by default.
Production mode replaces the client ingress with an explicitly configured TLS
1.3 endpoint that requires both a trusted client certificate and an API key:

| Interface | Purpose | Default exposure |
|---|---|---|
| Client ingress | Accepts HTTP proxy traffic and HTTPS `CONNECT` tunnels | Plaintext loopback in development; explicit TLS address in production |
| Internal HTTP service | Runs the Pingora forwarding and cache pipeline | Loopback only |
| Tor bridge socket | Connects Pingora to the Arti bridge | Unix socket with owner-only permissions |
| Metrics service | Exposes Prometheus-format operational metrics | Loopback only |

The default development listener must never be exposed to the public Internet.
The production code path now supplies mTLS, API-key authorization, revocation,
and account admission controls, but that code is not by itself proof of a safe
public deployment. Firewall/process isolation, certificate operations,
provisioning, controlled-origin validation, monitoring, rollback, and an
emergency suspension procedure are still deployment gates.

Linux is the current production target because the internal bridge relies on Unix domain sockets and Unix file permissions. Other operating systems should be treated as development targets until their complete runtime paths have been tested.

## Architecture at a glance

The system runs as one Rust process with four cooperating layers:

| Layer | Responsibility |
|---|---|
| Public ingress | In production, bounds the TLS handshake and first request, verifies mTLS plus API authorization, and dispatches HTTP and `CONNECT` traffic |
| Pingora HTTP engine | Handles ordinary HTTP forwarding, conservative shared caching, connection pooling, and response instrumentation |
| Tor bridge | Applies destination policy, isolation, admission control, retries, circuit breaking, tunnel accounting, and idle timeouts |
| Arti client | Bootstraps into the Tor network, builds circuits, resolves remote destinations through Tor, and creates outbound streams |

The high-level paths are:

**HTTPS tunnel:** Client → public ingress → destination policy → tunnel admission → circuit-build admission → Arti → Tor network → destination

**Ordinary HTTP:** Client → public ingress → internal Pingora service → cache lookup or upstream selection → protected Unix bridge → circuit-build admission → Arti → Tor network → destination

**Observability:** Pingora and the Tor bridge → privacy-bounded counters and latency histograms → loopback metrics endpoint and structured operational logs

### Process startup

At startup, the service creates a dedicated asynchronous runtime and bootstraps a single Arti client. The public listeners are started only after the Arti client is available. The same client is shared across requests, while isolation preferences determine which streams may share circuits.

The Tor bridge and its metrics service run as asynchronous tasks. Pingora runs the internal HTTP service and uses the protected Unix socket whenever it needs an outbound Tor connection. A bootstrap failure stops startup rather than silently allowing direct network access.

### Bounded task draining

The bridge owns its public-ingress, internal-bridge, and metrics connection
tasks in one task registry. Because Tor connection establishment and tunnel
copying are awaited inside those connection tasks, their complete lifetime is
covered by the same ownership boundary.

On graceful termination, the listeners close first and the registry allows
owned tasks to finish naturally. The default drain period is 30 seconds. Tasks
remaining at the deadline are aborted, which drops their streams and
cancellation-safe admission guards, and the process waits up to another five
seconds for their termination. Shutdown logs and Prometheus metrics distinguish
normal completion, failure, deadline cancellation, and a force-stop timeout.

The two positive integer environment variables below configure this behavior.
Each accepts a value from 1 through 3600 seconds:

| Variable | Default | Meaning |
|---|---:|---|
| `PROXY_SHUTDOWN_DRAIN_SECONDS` | `30` | Natural completion window for owned bridge tasks |
| `PROXY_SHUTDOWN_FORCE_STOP_SECONDS` | `5` | Maximum wait for deadline-aborted tasks to terminate |

Pingora's grace period is derived from both values plus a safety margin, so a
service supervisor must allow more than the combined application budget before
sending `SIGKILL`. Local test runners use shorter, test-only values; they do not
change the production defaults.

### Public ingress and protocol dispatch

The ingress listener reads a bounded HTTP header without discarding bytes that may already belong to a tunneled protocol.

- A valid `CONNECT` request is handled as a raw end-to-end tunnel.
- An ordinary HTTP request, including its already-buffered body bytes, is forwarded to the internal Pingora listener.
- Malformed, incomplete, oversized, or unsafe requests are rejected before an outbound connection is attempted.

For HTTPS, the proxy returns a successful tunnel response only after the Tor stream has been established. TLS then remains end-to-end between the client and destination. The proxy does not decrypt or cache tunneled HTTPS traffic.

### Authenticated production ingress

`PROXY_INGRESS_MODE` selects the runtime boundary:

- Unset or `development` keeps the legacy plaintext listener restricted to a
  loopback address. Supplying production credential settings in this mode is
  rejected.
- `production` fails startup unless the TLS certificate, owner-only private
  key, client CA, account database, and owner-only 32-byte API-key hash secret
  are all explicit and valid. Only TLS 1.3 with ALPN `http/1.1` is accepted.

Required production settings:

| Variable | Meaning |
|---|---|
| `PROXY_INGRESS_LISTEN_ADDR` | Explicit TLS listen address, for example `0.0.0.0:8443` |
| `PROXY_INGRESS_SERVER_NAMES` | Explicit comma-separated service names recorded in the startup contract; clients still verify the presented certificate |
| `PROXY_INGRESS_SERVER_CERT` | PEM server certificate chain |
| `PROXY_INGRESS_SERVER_KEY` | PEM server private key; on Unix it must not be accessible by group or other users |
| `PROXY_INGRESS_CLIENT_CA` | PEM CA roots trusted to issue client certificates |
| `PROXY_ACCOUNT_DATABASE` | Owner-only SQLite account/credential/usage database |
| `PROXY_API_KEY_HASH_KEY_FILE` | Owner-only regular file containing exactly 32 random bytes |
| `PROXY_SINGLE_TIER_PERIOD_BYTE_LIMIT` | Combined upload and download bytes allowed to one account in each usage period |

Optional positive integer settings:

| Variable | Default | Meaning |
|---|---:|---|
| `PROXY_TLS_HANDSHAKE_TIMEOUT_SECONDS` | `10` | TLS handshake deadline |
| `PROXY_FIRST_REQUEST_TIMEOUT_SECONDS` | `10` | Post-handshake first-header deadline |
| `PROXY_MAX_CONCURRENT_TLS_HANDSHAKES` | `64` | Independent TLS work cap |
| `PROXY_MAX_CLIENT_CONNECTIONS` | `512` | Authenticated client connection cap |
| `PROXY_MAX_CACHED_ACCOUNTS` | `1024` | Bounded in-memory account admission states |
| `PROXY_USAGE_PERIOD_SECONDS` | `2592000` | Epoch-aligned usage/quota period |
| `PROXY_CERT_TRUST_OVERLAP_SECONDS` | `86400` | Planned client-CA rotation overlap |

Generate the API-key hash secret without placing it in an environment variable:

```bash
umask 077
openssl rand 32 > /run/proxy/api-key-hash-key
```

The account database must already contain an active account/workspace, a hashed
API key, and the SHA-256 fingerprint of the approved client leaf certificate.
The account module exposes provisioning and revocation operations, but a
customer dashboard or production admin CLI has not yet been added.

For the initial single-tier launch, every account must store the same non-zero
`period_byte_limit` as `PROXY_SINGLE_TIER_PERIOD_BYTE_LIMIT`. A mismatch fails
closed when that account authenticates; changing the allowance therefore
requires updating the stored account limits and restarting the service with the
matching setting. The configured value is a technical allowance, not a price or
billing-provider product identifier.

The allowance is enforced per account across all of its workspaces and active
tunnels, counting payload bytes in both directions. New requests receive `429`
when no allowance remains. A tunnel that consumes the final bytes is closed at
the exact boundary. Active usage is persisted after each MiB, every five
seconds, and when the tunnel closes, whichever happens first.

This launch implementation assumes one running proxy process. Its live budget
is process-local, so multiple replicas sharing the SQLite database could each
admit part of the same remaining allowance. Do not scale to multiple service
processes until quota reservation is coordinated transactionally across them.

An authorized client can verify an already provisioned endpoint with an HTTPS
proxy-capable curl:

```bash
curl --proxy https://proxy.example:8443 \
  --proxy-cacert server-ca.pem \
  --proxy-cert client.pem \
  --proxy-key client-key.pem \
  --proxy-basic \
  --proxy-user "$PROXY_API_KEY:" \
  https://check.torproject.org/api/ip
```

That command exposes the expanded API key to the local process list on some
systems; use an owner-only curl config or an application secret store for
routine operation.

### Destination safety policy

Before opening a Tor stream, the bridge parses and canonicalizes the requested authority. It rejects missing or zero ports, local hostnames, common private-network suffixes, loopback addresses, private IPv4 ranges, IPv6 unique-local addresses, link-local addresses, multicast addresses, and other non-routable literal addresses.

This is a baseline server-side request-forgery defense, not a complete commercial abuse policy. A paid deployment should also restrict ports, block email delivery ports, support customer or purpose-specific destination rules, and regularly test hostname-resolution edge cases.

### Isolation lifecycle

Isolation state is intentionally ephemeral:

- Isolation identities are length-limited and restricted to a small safe character set.
- Authenticated session identities incorporate account, workspace, canonical destination, and any optional caller sub-identity before mapping to in-memory Arti isolation tokens and connection-pool group keys.
- Entries expire after inactivity and the store has a fixed maximum size.
- Strict mode generates a fresh identity and isolation group for every operation.
- Isolation headers are removed before a request is sent to the destination.
- No isolation token or identity mapping is written to disk.

For ordinary HTTP, the Pingora peer is partitioned by the isolation group. This prevents a connection opened for one identity from being reused by another identity. In strict mode, downstream and upstream keep-alive are disabled where needed so that a newly generated token cannot be undermined by an already-open HTTP connection.

Opaque, short-lived in-process leases carry authenticated identity across the
loopback Pingora and owner-only Unix-socket hops. Raw API keys and account
identifiers are not forwarded in those internal headers, and all
credential/isolation headers are stripped before an origin request is emitted.

### Capacity and failure control

The runtime keeps separate limits because they protect different resources:

| Control | Current role | Current starting value |
|---|---|---:|
| TLS handshake limit | Bounds unauthenticated TLS CPU/work | 64 in production, configurable |
| Public client connection limit | Bounds accepted client tasks | 512 in production, configurable |
| Internal connection-task limit | Prevents the public cap from starving Pingora-to-bridge work | 512 |
| Active-tunnel limit | Caps established long-lived tunnels | 256 |
| Per-account tunnel/rate limits | Enforces the active account plan | Stored per account |
| Per-customer period data limit | Caps combined traffic across workspaces and tunnels | One required single-tier value in production |
| Circuit-build limit | Caps expensive concurrent Tor connect/build operations | 32 |

An active tunnel may wait briefly for capacity. A circuit build may wait longer because circuit construction is expensive and bursty. If the relevant wait expires, the client receives `503 Service Unavailable` with a retry hint.

The circuit-build permit is released as soon as the Tor connection attempt resolves. It is not held for the lifetime of the data tunnel. This keeps long-lived, low-bandwidth tunnels from consuming scarce circuit-construction slots.

Tor connection establishment has a total deadline. A retryable failure may be retried once, with a short backoff and isolation rotation where the selected isolation mode permits it. Repeated failures for a destination open a bounded circuit breaker, which temporarily rejects further attempts instead of repeatedly stressing the same failing route.

Once established, a tunnel remains open while traffic is active. A rolling idle timeout closes abandoned tunnels without imposing a maximum lifetime on active connections. Byte counters include traffic in both directions and preserve half-close behavior.

### Error semantics

The proxy intentionally distinguishes local policy failures from Tor and destination failures:

| Status | Meaning |
|---:|---|
| 400 | Malformed request, invalid authority, or invalid isolation metadata |
| 403 | Inactive/mismatched account or device, or destination rejected by local safety policy |
| 407 | Missing, invalid, or revoked proxy API key |
| 408 | Authenticated TLS client did not finish its first request in time |
| 429 | Per-account request, tunnel, or usage quota reached |
| 503 | Local capacity exhausted or destination circuit breaker open |
| 504 | Tor connection establishment exceeded its deadline |
| 502 | Other Tor, exit-policy, DNS, or destination connection failure |

An HTTP response produced by the destination is passed through as an origin response. In particular, a destination-generated `403` is not treated as a proxy failure; many sites intentionally reject Tor exit traffic.

## Cache model

Only ordinary HTTP is eligible for caching. HTTPS tunnels are opaque and never cached.

The cache is an in-memory, process-local shared cache with a bounded size, per-object size limit, sharded LRU eviction, and a cache lock to avoid duplicate cold fetches. The cache key includes scheme, normalized host, effective port, path, and query. A disagreement between an absolute request URI and the `Host` header is rejected.

The admission policy is deliberately conservative. A response is cacheable only when all of the following are true:

- The request is `GET` and contains no authorization or cookie header.
- The response is successful and explicitly declares public, positive freshness.
- The response contains no cookie-setting header.
- The response does not use `Vary`.
- The object fits within the configured size limit.

The shared cache can create cross-user timing signals even when it contains only explicitly public content. It should therefore be disabled by default for the strongest privacy offering, or partitioned by authenticated account and isolation policy. Disabling it also leaves the commercial service closer to a pure transmission service for legal classification purposes, although classification always remains jurisdiction- and fact-specific.

## Observability and data handling

The loopback metrics endpoint exposes bounded, low-cardinality operational data, including:

- Requests grouped by method and status
- Request, tunnel, cache-lock, and Tor-connect latency
- Active, queued, rejected, and completed tunnels
- Circuit admission and connection timeouts
- Retry and circuit-breaker activity
- Bytes transferred in both directions
- Cache activity and upstream connection reuse
- Isolation-store and circuit-breaker sizes
- Arti failures grouped into stable technical classes

Default structured logs contain method, status, latency, cache result, and a coarse error class. They intentionally omit full URLs, request paths, credentials, client IP addresses, destination names, and isolation identities.

This privacy-oriented logging policy is a product choice, not a promise that the process never handles identifying data. The ingress necessarily receives the client network connection and requested authority, and ordinary unencrypted HTTP is visible while being forwarded. A remote commercial service therefore requires encrypted client-to-proxy transport and a privacy notice that accurately describes both transient processing and retained data.

Any legally required account, billing, security, or abuse records must be kept separately from ephemeral isolation state. Retention must be defined by a written schedule and reviewed against the laws that actually apply to the operator and customers.

## Security boundaries

The design depends on the following boundaries:

- Production client ingress is trusted only after both mTLS and API-key authentication succeed; development ingress remains loopback-only and unauthenticated.
- The loopback Pingora listener is not a public interface.
- The Unix bridge socket is restricted to the operating-system owner.
- The metrics listener is loopback-only and must remain inaccessible from untrusted networks.
- The Arti client is the only supported route to the destination; there is no direct-connect fallback.
- Ephemeral isolation state is not a substitute for account authentication or tenant separation.

A production deployment should additionally provide least-privilege service
accounts, a read-only or tightly restricted filesystem, automatic security
updates, certificate and hash-secret rotation, monitored restarts, encrypted
backups for account data, and an emergency abuse-response procedure.

## Known limitations

- Authentication, revocation, rate limits, concurrent-tunnel limits, and aggregate SQLite usage accounting are active only in production ingress mode. There is no billing integration, dashboard, or production admin CLI yet.
- The account-wide data cap is exact within one running service process. A crash can lose at most the usage transferred since the last one-MiB/five-second checkpoint, and multi-process quota coordination is not implemented.
- Certificate reload/rotation, live production monitoring, and target-host rollback drills remain unimplemented or unverified.
- The default listener configuration is suitable for local development, not direct Internet exposure.
- Isolation does not guarantee different exit IP addresses or immunity from traffic correlation.
- Development mode defaults to fresh ephemeral isolation; authenticated production mode derives it from tenant and destination.
- Tor is slower and less predictable than commercial datacenter or residential proxy networks.
- Strict isolation has a meaningful performance and Tor-network cost.
- Some destinations block Tor exits regardless of circuit rotation.
- Shared HTTP caching is a privacy and legal-classification tradeoff.
- Unit tests do not replace a controlled end-to-end deployment test through the live Tor network.

## Development and verification

The runtime remains centered in `src/main.rs`, with private-ingress and account
management policy isolated in their own modules. The primary dependencies are
Pingora for HTTP proxying and caching, Tokio/Rustls for asynchronous encrypted
ingress, and Arti for Tor client functionality.

The required local verification order is:

1. Run the compiler check.
2. Run the automated test suite.
3. Build the executable.
4. Start the proxy and allow Arti to bootstrap.
5. Run the controlled HTTP and HTTPS functional matrix against infrastructure that is authorized for testing.

At the time this document was updated, the locked compiler check passed and 75
automated tests passed. Two tests remain intentionally ignored because they
require a running proxy and controlled external test origins. Published
reliability or performance claims must come from those controlled tests, not
from public websites or a local in-memory transport benchmark.

### End-to-end deployment test

On Linux, the complete self-check is:

```bash
./test-deployment.sh
```

The runner checks the locked build, automated tests, release build, process startup, Prometheus contract, metrics path scope, destination blocking, isolation-header validation, session and strict HTTPS forwarding, ordinary HTTP forwarding, Tor egress, runtime metrics activity, and process health. It stops the process it started and writes a timestamped evidence bundle to `artifacts/deployment-e2e/`, including per-check logs, proxy logs, metrics snapshots, response samples, and `summary.txt`.

To check a service already deployed on a VPS, run the framework on that host so its loopback-only listeners remain private:

```bash
./test-deployment.sh --mode running \
  --proxy-url http://127.0.0.1:8080 \
  --metrics-url http://127.0.0.1:9090/metrics
```

Caching requires an origin you control because a reliable assertion needs a known `Cache-Control: public, max-age=...` response. Enable that additional check with:

```bash
./test-deployment.sh \
  --cache-url http://your-authorized-test-origin.example/cacheable
```

Use `./test-deployment.sh --help` for endpoint, timeout, artifact-directory, build-reuse, and keep-running options. The default external matrix sends only three functional requests: one Tor Check request plus one HTTPS and one plain-HTTP request to Example Domain. It is a functional verification, not a load test.

## Ownership, licensing, and commercial terms

### Recommended structure

For the current plan—private source code and a hosted or managed service—the recommended combination is:

1. **Original code: proprietary, all rights reserved.** Do not attach an open-source or source-available license to the original project.
2. **Repository access: confidentiality agreement.** Copyright alone restricts copying but does not by itself create a complete confidentiality regime.
3. **Hosted access: Terms of Service plus Acceptable Use Policy.** Customers receive a limited, revocable right to use the service, not a copy or license to the software.
4. **Customer data: Privacy Notice and, where appropriate, a Data Processing Agreement.** These documents must match actual logging, subprocessors, locations, retention, and disclosure obligations.
5. **Commercial promises: order form and limited SLA.** Support, uptime, refunds, warranty disclaimers, and liability caps belong here rather than in the software copyright notice.
6. **Third-party code: a maintained `THIRD_PARTY_NOTICES` package.** This becomes essential before any executable or container is delivered outside the operator's organization.
7. **Branding: a neutral product name and Tor trademark disclaimer.** “Tor” may truthfully describe network compatibility, but should not be part of the product, company, domain, or account name without written permission.

This structure protects the private code while keeping service rules and privacy obligations explicit. A software license does not legalize an anonymity service, prevent abuse complaints, create intermediary immunity, or override mandatory laws.

### License models compared

| Model | Keeps source private? | Fit for this business | Main consequence |
|---|---:|---|---|
| Proprietary copyright plus hosted-service terms | Yes | **Best current fit** | Customers use the service without receiving source rights |
| Proprietary binary EULA | Yes | Useful only if binaries or appliances are delivered | Requires careful third-party notice and redistribution compliance |
| MIT or Apache-2.0 for the original code | No, once published | Poor fit | Competitors may legally copy, modify, host, and resell the code subject to notices |
| AGPL-3.0 plus a commercial alternative | No | Poor fit for the stated goal | Network users of covered modified versions must be offered corresponding source; dual licensing also requires clean ownership of all contributions |
| Business Source License or similar source-available license | No | Poor fit | Source must be disclosed even though production or competing use may be restricted |
| No notice and no license file | Source remains copyrighted, but ambiguous operationally | Inferior to an explicit proprietary posture | Creates uncertainty for employees, contractors, customers, and release tooling |

### Third-party dependency position

The original code can remain proprietary because its direct core dependencies use permissive licenses:

| Component | Resolved license family |
|---|---|
| Arti client and Tor runtime compatibility crates | MIT or Apache-2.0 |
| Pingora and Pingora memory cache | Apache-2.0 |
| Tokio | MIT |
| Anyhow, async-trait, HTTP, and httparse | MIT or Apache-2.0 |

The current Linux dependency graph also contains `option-ext` under MPL-2.0 and `priority-queue` under `LGPL-3.0-or-later OR MPL-2.0`. A commercial release should deliberately rely on the latter's MPL-2.0 option. MPL-2.0 permits an MPL-covered component to be statically linked into a larger proprietary work, but distributing the executable requires recipients to be told how to obtain the MPL-covered source. Changes to MPL-covered files must remain available under MPL terms. This does not require publication of separate original proprietary files.

For a server-only service where no executable, container, virtual-machine image, or client bundle is delivered, MPL network use is not distribution. Delivering a binary onto a customer's VPS should be treated conservatively as distribution.

Before every external release, generate a software bill of materials and have automated tooling verify the exact target-specific dependency graph. Preserve required MIT, BSD, Apache, Unicode, MPL, and other notices; carry forward applicable Apache `NOTICE` content; and provide an exact source location for MPL-covered components. The local audit performed for this document is not a substitute for a release-time legal review.

### Contributor ownership

If anyone else contributes—including classmates, contractors, interns, or an employer—obtain a written copyright assignment or an agreement granting the company sufficient rights to relicense and commercialize the contribution. A future dual-license strategy is unreliable if ownership is fragmented.

As a student project, also check the intellectual-property policy of any university, scholarship, incubator, laboratory, employer, or sponsor whose equipment, funding, coursework, or supervision contributed to the work.

## Jurisdiction and anonymity-service considerations

The governing-law clause in a customer contract is only one part of jurisdiction. Mandatory rules may be triggered by the operator's residence and entity, server and log locations, payment provider, customer's location, people deliberately targeted by the service, and where an investigation or alleged harm occurs. A Tor exit relay's country does not replace those connections.

This service is a Tor **client-side proxy**, not a Tor exit relay. The destination normally sees a Tor exit address rather than the service VPS address, but customers still connect to the service and the operator still controls an intermediary system. Legal material written for volunteer relay operators must not be assumed to cover a commercial authenticated proxy.

### Practical comparison

| Region | Issues requiring review before launch | Product implication |
|---|---|---|
| India | CERT-In directions cover service providers, intermediaries, bodies corporate, VPS/cloud providers, and VPN providers; the associated FAQ describes covered VPN services as providing “Internet proxy like services.” The directions include ICT logging, incident reporting, and customer-record requirements for specified provider categories. | A categorical “no logs” promise may be incompatible with applicable duties. Obtain Indian counsel before serving the public or Indian users, and determine whether the service is classified as a VPN-like provider, another service provider, an intermediary, or a customer-managed enterprise tool. |
| European Union | GDPR can apply to a non-EU business that targets people in the EU. The Digital Services Act lists VPNs as examples of possible “mere conduit” services and reverse proxies as possible caching services, but classification depends on actual functionality. | Document lawful data processing and retention; assess DSA points of contact and other duties; consider disabling shared caching and content modification for a transmission-only offering. |
| United States | EFF describes possible intermediary and copyright safe-harbor arguments for Tor relays, while emphasizing that the FAQ is U.S.-specific, fact-dependent, and not legal advice. It also notes that no court had resolved some Tor-specific questions. | Do not assume relay precedent or safe harbors automatically cover a paid proxy. Maintain an abuse contact and obtain advice on federal and relevant state privacy, communications, sanctions, and intermediary rules. |
| Other countries | VPN, proxy, telecommunications, encryption, data-retention, consumer, sanctions, and cybercrime rules differ widely and can change quickly. | Launch only in an explicit allowlist of reviewed markets. Do not infer legality from the fact that Tor software is reachable there. |

India deserves particular attention if the operator, entity, infrastructure, or customers are connected to India. CERT-In's April 2022 direction states that covered organizations must retain ICT-system logs for a rolling 180 days and that specified VPN, VPS, cloud, and data-center providers must retain validated customer information for five years after service ends. The related FAQ includes proxy-server logs among the possible ICT logs and says serious reportable incidents may need to be reported within six hours. Classification of this particular architecture is a legal question, not a software setting.

For EU customers, IP addresses, named business email addresses, and account activity can be personal data. Keeping isolation tokens only in memory reduces retained sensitive data, but it does not remove obligations for account, security, support, billing, or network records.

The safest early commercial posture is a small number of verified business customers, one private instance per customer, narrowly permitted use cases, restricted ports, customer-specific access, clear suspension rights, and no public free tier. This reduces shared-service abuse and tenant-correlation risk, but it does not eliminate the need for counsel.

## Required customer-facing policies before charging

At minimum, prepare and have locally qualified counsel review:

- Terms of Service and an order form
- Acceptable Use Policy
- Privacy Notice and retention schedule
- Data Processing Agreement where required
- Abuse-reporting and law-enforcement-request procedure
- Security incident response plan
- Subprocessor and infrastructure-location list
- Limited Service Level Agreement
- Tor trademark attribution and non-affiliation notice

The Acceptable Use Policy should expressly prohibit unauthorized access, credential attacks, malware delivery, denial-of-service activity, spam, unsolicited bulk messaging, unlawful surveillance, infringement, sexual abuse material, evasion of sanctions, and activity that violates a destination's authorization boundaries or applicable law.

## Trademark and non-affiliation notice

This project uses Arti to connect to the Tor network. It is an independent project and is not sponsored, endorsed, or operated by The Tor Project.

Tor is a trademark of The Tor Project; all rights reserved. The product should use its own distinctive name and visual identity, should not use the Tor onion logo without written permission, and should use the Tor word mark only to describe compatibility truthfully.

## Authoritative references

- [Arti stream-isolation behavior](https://docs.rs/arti-client/latest/arti_client/struct.StreamPrefs.html)
- [Tor's remaining traffic-correlation limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/)
- [Tor Project trademark and brand policy](https://www.torproject.org/about/trademark/)
- [EFF legal FAQ for Tor relay operators](https://www.eff.org/pages/legal-faq-tor-relay-operators)
- [CERT-In cybersecurity directions](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf)
- [CERT-In directions FAQ](https://www.cert-in.org.in/PDF/FAQs_on_CyberSecurityDirections_May2022.pdf)
- [EU Digital Services Act](https://eur-lex.europa.eu/eli/reg/2022/2065/oj/eng)
- [European Commission guidance on GDPR applicability](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/application-gdpr_en)
- [Mozilla Public License 2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
- [Apache License 2.0 application and notice guidance](https://www.apache.org/legal/apply-license)

## Document status

This README describes the implementation and legal-source review performed on **20 July 2026**. Architecture, dependencies, provider policies, and law change over time. Revalidate this document before every commercial launch or material product change.

Nothing in this README is legal advice. It is an engineering and issue-spotting document intended to support review by a lawyer licensed in the jurisdictions where the service will actually operate.
