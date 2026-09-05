# Egress containment and Apple TCP client: implementation guide

- **Prepared:** 2026-09-05.
- **Source audit:** [Egress hardening and Apple TUN overview audit](../audits/egress-apple-tun-overview-audit-2026-08-15T18-12-39Z.md).
- **Code reviewed:** checkout `10a054c`; source inspection, not deployment verification.
- **Status:** proposed implementation instructions. No milestone below is complete merely because this document exists.
- **Audience:** an implementation agent and the operator reviewing its evidence.

## 1. Objective and execution rules

Implement one consistent path from protected macOS application TCP flows to
native authenticated proxy ingress, a separate Arti service, and Tor. Prevent
the Linux proxy from opening direct destination or resolver connections. Keep
Apple protection explicitly scoped to applications, protocols, and lifecycle
states that have passed the tests below.

This guide resolves the source audit's contradictory recommendations for the
proposed implementation. It takes precedence over the older firewall diagram
and Apple prerequisite list for this work. Those documents remain historical
plans until reconciled in Step 1; they are not evidence of deployed controls.

The implementing agent must:

1. Read the source audit, [firewall plan](firewall/egress-hardening.md),
   [roadmap](../../src/ROADMAP.md), [README](../../README.md), and applicable
   `AGENTS.md` files. Inspect current symbols again; line numbers and this
   snapshot can become stale. `src/ARCHITECTURE.md` is empty in this checkout.
2. Preserve unrelated worktree changes. Follow `src/AGENTS.md`: keep new server
   Rust logic and its tests in `src/main.rs`, check before building, preserve
   existing comments/imports, and do not commit automatically. Read the existing
   ingress/account modules to preserve their contracts; do not refactor them
   incidentally. This documentation task does not authorize runtime changes.
3. Work milestone by milestone. For each, record files changed, commands,
   observed outcomes, remaining failures, and evidence paths. A failed gate
   blocks dependent milestones; independent preparation can continue.
4. Use offline fixtures first and operator-controlled endpoints for network
   tests. Never use customer browsing, arbitrary public services, or production
   traffic as load or failure-injection fixtures.
5. Generate and validate deployment artifacts before activation. Host firewall,
   routing, service, MDM, and extension installation changes require the
   applicable deployment authorization. Honor authorization already given;
   otherwise present the exact diff, recovery procedure, and validation results
   before requesting activation. Do not request permission for ordinary reads
   or authorized reversible repository edits.
6. Never fix a failed gate by enabling direct fallback, disabling certificate
   validation, widening a route exception, ignoring isolation, or restoring a
   permissive firewall. Keep ingress closed when containment is uncertain.
7. Do not mark skipped, unavailable, or simulated checks as live passes. Linux
   tests cannot establish macOS entitlement, routing, or lifecycle correctness.

## 2. What exists and what must change

| Area | Verified source baseline | Required work |
|---|---|---|
| Public ingress | `configured_public_ingress`, TLS acceptance, and `handle_public_connection` in `src/main.rs`; TLS 1.3 configuration in `src/private_ingress.rs` | Preserve native Rustls, mTLS, and account-bound API-key authentication |
| Tor transport | `TorCircuit::bootstrap` creates embedded `TorClient`; `Bridge::connect_with_retry` uses `connect_with_prefs` | Introduce a tested connector boundary and migrate production to external Arti |
| Isolation | `TenantIsolationHasher`, `IsolationStore`, session/strict modes | Preserve account/workspace/destination scope using opaque external-protocol isolation values |
| Ordinary HTTP | Pingora forwards through the internal bridge; scoped cache policy exists | Retain trusted identity leases, pool separation, and cache gates during migration |
| Destination policy | `parse_connect_destination`, `canonical_connect_destination_key`, and `connect_destination_allowed` are separate helpers | Complete the linked destination-policy plan before external pilot; the current boolean filter is insufficient |
| Lifecycle | Bridge task ownership, shutdown relay, admission permits, and bounded draining exist | Preserve these when removing embedded Arti and add client lifecycle tests |
| Host containment | No rendered, verified deployment boundary supplied by the audit | Add namespaces, firewall ownership, service ordering, recovery, and independent evidence |
| Apple client | Experimental E1 in the roadmap | Establish feasibility, then implement a signed flow-provider client |

Use the [destination-policy plan](destination/destination-port-and-address-policy-fix-plan.md)
for exact port/address rules and the [cache plan](cache/cache-isolation-and-exit-poisoning-fix-plan.md)
for migration regressions. Recheck which parts have already landed; do not
reimplement completed cache work. The host kill switch does not replace
destination, account, abuse, or cache controls.

## 3. Selected design and threat boundary

### Canonical data path

```text
protected macOS app
  -> managed Network Extension flow provider
  -> one TLS 1.3 + mTLS + HTTP/1.1 CONNECT per accepted TCP flow
  -> host ingress forwarding (TCP packets only; no TLS termination)
  -> proxy namespace: native Rustls -> authentication/policy -> bridge
  -> dedicated proxy-to-Arti link and private listener
  -> Arti namespace: separately owned, sandboxed Arti service
  -> host forwarding for Arti -> Tor -> destination
```

Decisions for the first implementation:

- **Ingress:** keep native Rustls. Do not introduce Caddy/nginx TLS termination
  or forwarded identity headers. Linux packet forwarding does not change the
  mTLS trust boundary.
- **Server egress:** external Arti is a production prerequisite. A proxy network
  namespace without an IPv4 or IPv6 default route is the baseline. UID-only
  filtering is an intermediate laboratory checkpoint, not completion.
- **Apple scope:** begin with managed, selected applications using
  `NEAppProxyProvider`, packaged as a system extension with Developer ID
  distribution. This is a proposed narrow pilot target, conditional on Step 2
  proving entitlement, MDM, DNS, and disconnected-state behavior. An unmanaged
  or whole-device product requires a new provider decision; do not silently
  substitute `NETransparentProxyProvider`.
- **Apple transport:** implement the first adapter in Swift using supported
  Apple APIs and a narrow flow state machine. Keep the Rust server protocol
  stable. A separate Rust client crate/workspace is not required by this plan;
  agree its ownership and repository rules first if later justified. Tower and
  Hyper are optional implementation tools, not security prerequisites.
- **DNS:** the initial client accepts verified hostname-bearing TCP flows and
  denies protected conventional DNS and IP-only flows. No DNS synthesis or
  local forward/reverse lookup. Step 7 defines the exact limitations.
- **Packet TUN:** conditional research only, after Step 11. Arti is a TCP stream
  transport; raw IP packets cannot be passed to it.

The claim is containment of application-originated destination/DNS egress by
the proxy, plus tested routing of the documented Apple scope. Host root, kernel
compromise, a compromised privileged provisioning layer, and compromised Arti
are outside this guarantee. Arti necessarily receives network permissions that
a compromised Arti process could misuse. The boundary also cannot stop a
compromised proxy from misusing already-authorized ingress sockets or its
authorized Arti API. Namespace separation is not a complete exfiltration proof.

The Mac intentionally opens an authenticated connection to the appliance; that
transport is visible to its local network. Unmanaged applications and documented
OS exclusions are outside the selected scope. Do not claim a whole-device VPN,
traffic-analysis resistance, or that Tor encryption supplies destination TLS
for plaintext HTTP.

## 4. Milestones and dependencies

```text
Step 1: baseline, architecture record, deployment facts
  +-> Step 2: Apple E0 feasibility
  +-> Step 3: connector contract and deterministic tests
        -> Step 4: pinned Arti compatibility and migration
        -> Step 5: namespace/firewall/service artifacts
        -> Step 6: controlled server activation and evidence
Step 2 -> Step 7: Apple DNS, scope, and exclusion contract
Steps 4 + 7 -> Step 8: credentials and client implementation
Steps 6 + 8 + destination/account gates -> Step 9: Mac acceptance testing
Step 9 -> Step 10: bounded experimental pilot and recovery
Step 11: optional TUN feasibility; never an implicit pilot dependency
```

### Step 1 — Freeze the baseline and remove architecture contradictions

1. Record `git status --short`, the revision, toolchain versions, and the source
   symbols in Section 2. Run the server verification sequence in Section 6 and
   record existing failures separately from changes.
2. Reconcile the firewall plan's TLS frontend and optional namespace with
   Section 3. Move external Arti out of the roadmap's deferred list into this
   dependency graph. Add Step 6 as an Apple external-pilot prerequisite.
   Preserve the dated audit; append a resolution link rather than rewriting
   its findings as if they had never existed.
3. Create a deployment-specific manifest under a proposed
   `deployment/egress/` directory. These paths are future deliverables, not
   files that currently exist. Include the following required fields:

   | Manifest group | Required values |
   |---|---|
   | Host | OS/kernel, systemd/nft versions, firewall owner, cloud rules, interfaces, address families |
   | Recovery | Management ranges/ports, console method, rules backup location, known-good release, rollback owner |
   | Network | Namespace names, each link's exact addresses, ingress port mapping, private Arti endpoint, telemetry path |
   | Identity/state | Numeric service UID/GID, read/write paths, socket ownership, certificate and database locations |
   | Arti | Exact release, build features, source/artifact digest, selected protocol, complete configuration, bootstrap DNS needs |
   | Apple | Supported OS/build/hardware, provider, packaging, signing identity, entitlement/profile, MDM app rules |
   | Credentials | Enrollment expiry, certificate/key lifetimes, finite trust overlap, active-tunnel revocation delay, recovery ownership |
   | Limits | Numeric setup, queue, flow, byte, drain, and resource budgets; expected workload |

4. Reject missing fields before rendering deployable files. Keep credentials
   outside the repository and evidence bundle. Detect the existing firewall
   owner read-only; do not layer raw nft changes over firewalld/ufw rules.

**Gate G1:** one architecture and dependency order; complete staging manifest;
baseline results retained. Unknown production host facts block production
rendering/activation, not local connector development.

### Step 2 — Prove Apple E0 before building the client

1. Build a minimal signed host application and provider for the selected scope.
   Record exact entitlements, provisioning, Team ID/bundle identifiers, supported
   OS versions, and notarization/installation results. Test the intended
   distribution package, not only Xcode's development launch.
2. Deploy selected apps and VPN rules through the intended MDM system. Include
   helper processes and resolver attribution in the scope record. Establish
   whether protection survives logout, boot before login, locked Keychain,
   provider failure, and network changes.
3. Keep protected flows denied during this spike; forwarding is unnecessary.
   Test that starting/stopping/killing the provider does not send these flows
   directly. Keep management recovery outside the protected app set.
4. Document the enforcement mechanism while provider code is absent. MDM rule
   presence, an on-demand flag, a UI state, or a reconnect loop alone is not a
   kill-switch proof. Prohibit disconnect-on-demand and domain-exclusion rules
   that bypass selected applications. If persistent denial cannot be shown,
   stop the pilot path and record the unsupported lifecycle states.
5. Demonstrate install, enable, logout/login, upgrade, disable, and uninstall on
   each supported OS. An explicit user/admin removal of protection must be
   distinguishable from an outage; do not label the resulting direct state
   protected. A managed deployment should restrict unauthorized removal.

Apple documents different deployment requirements and app/system-extension
lifetimes in [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).
Its [routing guidance](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)
describes managed app rules and bypass-capable disconnect rules. These establish
the feasibility questions; they do not replace device tests.

**Gate G2:** signed deployment and persistent scope enforcement demonstrated on
the supported OS matrix. If MDM or required capabilities are unavailable, report
an E0 blocker; continue independent server work without expanding Apple scope.

### Step 3 — Define the connector and preserve server invariants

1. Introduce a single injectable Tor connector in `src/main.rs`. Its input is a
   policy-approved canonical host/port, resolved isolation context, one absolute
   deadline, and cancellation. Its output is an asynchronous bidirectional
   stream or a bounded error enum. Do not expose a destination-socket fallback.
2. Make connector tests use an in-process fake or private local fixture. Keep
   the production path unchanged until the contract tests pass. Coordinate the
   approved-target type with the destination-policy plan; do not create two
   authority evaluators.
3. Derive session isolation from authenticated account, workspace, canonical
   destination, optional validated sub-identity, and current isolation generation.
   Encode keyed/random opaque material, not raw identities or unkeyed hashes.
   Generate at least 128 bits of unpredictable material; a 32-byte value encoded
   as 64 hex characters is a suitable explicit format.
4. Reuse the external token only within that session scope and generation.
   Rotation/TTL expiry produces a new value. Strict mode produces fresh material
   for each connection attempt, including retries. Bound the token store and
   redact tokens from `Debug`, errors, metrics, and logs.
5. Preserve request authentication, policy-before-cache ordering, trusted bridge
   leases, pool/cache scope separation, and strict-mode cache bypass. Never send
   client `Proxy-Authorization`, internal identity leases, or caller-supplied
   `Tor-*` headers to Arti. Construct the local protocol request from typed inputs.
6. Preserve at most one retry inside the current 45-second Tor-connect budget;
   endpoint connection, protocol handshake, and backoff consume that budget.
   Retry only classified transient failures before downstream success. Keep
   the circuit-build permit around establishment, then release it; retain the
   active-tunnel/account permits through transfer and final accounting.
7. Preserve buffered bytes at both CONNECT boundaries, short writes,
   half-closes, idle timeout, cancellation, and task joining. After success,
   stream failure closes the tunnel: no retry, injected HTTP error, stream
   splicing, or replay of opaque application bytes.

**Gate G3:** deterministic tests prove hostname preservation, isolation scope,
rotation, strict freshness, error classification, cancellation, permit release,
and byte/half-close correctness. Public CONNECT and ordinary HTTP exercise the
same final policy/connector boundary.

### Step 4 — Pin, prove, and migrate to external Arti

1. Pin the actual daemon artifact and configuration in the manifest. The
   repository's `arti-client = 0.42.0` dependency does not prove which CLI daemon,
   listener, features, or protocol are installed. Retain build provenance and
   the exact configuration used by the compatibility tests.
2. Prefer HTTP CONNECT only when that artifact passes its required behavior and
   isolation tests. Otherwise select SOCKS5 at configuration time and test it.
   Production must not negotiate a weaker protocol or drop isolation after an
   error. Do not assume a Unix listener or socket activation is supported.
3. For HTTP CONNECT, construct one bounded request with canonical authority,
   matching `Host`, and one locally generated `Tor-Stream-Isolation` value.
   Bound headers to 16 KiB/64 headers, matching the current server limits.
   Incrementally parse the response; reject malformed, oversized, unexpected
   interim, and non-success responses. Preserve bytes after the successful
   header. Send no destination data until success. Freeze accepted status and
   error mapping behavior in the compatibility fixture.
4. For SOCKS5, use a bounded implementation of CONNECT with domain-name address
   encoding for names and literal encoding for validated IPs. Require the pinned
   isolation-bearing username/password negotiation; reject method downgrades.
   Enforce protocol length fields, partial-read handling, reply address lengths,
   deadlines, and trailing-byte preservation. No UDP ASSOCIATE.
5. Establish isolation using test-only circuit identities or instrumentation of
   the pinned daemon in an isolated Tor test environment. Different isolation
   values must not share circuits. Equal values permit reuse; they do not force
   one circuit or exit address. Token inequality and different exit IPs alone
   are not circuit-separation proof. Do not expose circuit identities in normal
   production telemetry.
6. Authorize the private listener through the Step 5 namespace/link boundary.
   Isolation headers and SOCKS credentials are not caller authentication.
   Protocol/version banners cannot authenticate the daemon. Reject startup on
   an unexpected endpoint configuration or incompatible artifact.
7. Change `Bridge`, `Proxy`, `TorCircuit` startup, retry errors, and health wiring
   to use the external connector. Audit active `TorClient`, `DataStream`,
   `StreamPrefs`, and `connect_with_prefs` dependencies. Retain an owned runtime
   for bridge tasks after embedded bootstrap is removed. Any development-only
   embedded backend must be explicitly selected and rejected in production;
   it must never be an automatic fallback.
8. Readiness requires validated production configuration, private endpoint
   availability, and proven protocol/isolation compatibility. Test Tor bootstrap
   behavior separately from merely opening the local port. A controlled probe
   may establish functional readiness; pin its operator-owned destination and
   cadence. Mark new upstream work unavailable after Arti failure and recover
   only through the same external connector.

Freeze the public error mapping independently of Arti's changing status codes:

| Condition | Public result before tunnel success |
|---|---|
| Invalid authority / local destination-policy denial | Existing `400` / `403` policy contract |
| Missing or revoked API key / rejected device or account scope | Existing `407` / `403` authentication contract |
| Rate or quota rejection / unavailable admission capacity | Existing `429` / `503` admission contract |
| Readiness unavailable before establishment | Generic `503` |
| Exhausted establishment deadline | Generic `504` |
| Refused Arti stream, protocol incompatibility, other upstream failure | Generic `502`; incompatibility also withdraws readiness |
| Failure after tunnel success | Close the stream; no HTTP response injected |

Never forward an Arti `407` as if it requested the customer's credentials, or
expose its raw status reason, endpoint, destination, or isolation material.

The [Tor CONNECT specification](https://spec.torproject.org/http-connect.html)
defines isolation inputs and warns that capability reporting is incomplete;
neither a header nor a version string replaces the above evidence. The
[Arti startup guide](https://arti.torproject.org/guides/starting-arti/) documents
a SOCKS startup path. Check the pinned release against the
[SOCKS extensions](https://spec.torproject.org/socks-extensions.html) when choosing
that transport.

**Gate G4:** controlled ordinary HTTP and HTTPS work through the actual external
daemon; isolation semantics are established; refusal, restart, timeout, and
malformed replies fail closed; no active code path opens destination sockets.

### Step 5 — Produce the containment and service artifacts

1. Render separate namespaces for `proxy-app` and `proxy-arti`. Use dedicated,
   statically addressed point-to-point links for host-to-proxy ingress,
   proxy-to-Arti, and Arti-to-host egress. Give the proxy only connected routes
   for its two private peers, with no default route in either IP family. Disable
   forwarding in both service namespaces. Only host forwarding for explicitly
   approved paths is allowed. Do not attach either namespace to a shared bridge.
2. Preserve native TLS using narrowly scoped host DNAT to the namespace TLS
   listener, for example public TCP 443 to configured namespace TCP 8443. Use
   SNAT to the ingress-link peer for that exact ingress path so replies use a
   connected route; do not solve return routing by adding a proxy default route.
   Render/test IPv4 and IPv6 rules for the actual host. This loses the original
   peer IP at the application: review affected admission controls, retain
   certificate/account-based limits, and apply source limits at the host boundary
   if needed. Do not invent trusted identity from forwarded headers.
3. Render default-deny service-namespace input/output/forward policies, plus
   compatible host input/forward/NAT policy. The proxy may initiate TCP only to
   the exact private Arti address/port and exact required internal endpoints.
   Permit ingress replies only for the allowed ingress tuple and connection
   direction. Do not use blanket loopback or blanket established/related accepts
   that preserve preexisting unauthorized outbound sessions.
4. Keep internal Pingora and metrics on namespace loopback. Move the bridge
   socket from its current shared `/tmp` location to a private, owned runtime
   directory, with tests for ownership, stale sockets, and shutdown cleanup.
   SQLite remains a file dependency. Scrape metrics through a bounded collector
   in the proxy namespace or an explicitly authorized Unix-socket mechanism;
   do not expose port 9090 on the ingress link. Inventory permitted Unix sockets
   too: deny host resolver, container-engine, and privileged management sockets.
5. Bind Arti only on its proxy-facing address. The host has no route or general
   forwarding permission to that private link. Namespace handles, provisioning
   units, configuration, and executables are root-owned and not writable by
   either service. Do not schedule unrelated processes inside these namespaces.
   Verify that another ordinary host UID cannot connect to the listener, enter
   its namespace, or replace it while Arti is stopped. A supported Unix endpoint
   can replace the private TCP link only with equivalent ownership/peer checks.
6. Inventory the pinned daemon's bootstrap, rebootstrap, bridge, and pluggable
   transport DNS needs. Start with no resolver permission; prove startup from
   empty state and retained state. If a selected mode needs bootstrap DNS,
   document its exact resolver/transport path and allow only that path for Arti
   or its explicitly sandboxed transport. User destination names must still be
   resolved through Tor. A failed bootstrap is not grounds for broad DNS access.
7. Limit Arti Internet access to its explicit service path. Block access to host
   management/private services except reviewed bootstrap dependencies. A static
   public relay allowlist is not a reliable replacement for service isolation.
   Document required link control traffic separately: ARP/IPv6 neighbor handling
   and validated path-MTU errors must not become broad application ICMP/UDP
   exceptions. Do not let IPv6 autoconfiguration install a proxy default route.
8. Create systemd units with separate non-root users, empty ambient/bounding
   capabilities, `NoNewPrivileges=yes`, `PrivateDevices=yes`, read-only system
   paths, explicit state/runtime access, restricted address families/namespaces,
   disabled core dumps, and bounded file descriptors/tasks/memory/CPU/restarts.
   Use `NetworkNamespacePath=` for precreated namespaces; ensure no socket unit
   supplies an unintended host-network socket. Neither service gets
   `CAP_NET_ADMIN`, `CAP_NET_RAW`, or a privileged helper API.
   Pin daemon updates, assign an update owner, monitor upstream security notices,
   and rerun G4/G6 before promoting each changed daemon/configuration bundle.
   Keep state backups encrypted and separately controlled; never clone live
   secret state into test fixtures or publish it in the evidence ledger.
9. Make a privileged, narrowly scoped provisioning unit establish and verify the
   namespaces/firewall before service startup. Use requirement and ordering
   dependencies together; `After=` alone is insufficient. Bind service lifetime
   to required boundary units where applicable. Arti must start before proxy
   readiness, but process start alone is not bootstrap completion. Treat failed
   boundary verification as a startup failure, not a skipped successful check.
10. On shutdown, close public admission, stop/drain proxy work, stop Arti, and
    retain deny policy until processes and network state are gone. Keep a valid
    policy during reload using an atomic, owner-managed transaction. Never
    flush the host ruleset or remove the boundary while a service is running.
    Unit status cannot detect arbitrary out-of-band rule removal; protect rule
    ownership and document this privileged threat boundary.

Validate syntax and dependencies with the installed tools before activation:
`nft --check --file` on each rendered rules file and `systemd-analyze verify` on
the rendered units, in an authorized staging environment. Supply the actual
artifact paths; syntax checks do not prove routing or containment. See the
[nftables manual](https://netfilter.org/projects/nftables/manpage.html),
[systemd execution contract](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml),
and [unit dependencies](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml).
Check support against the deployed versions rather than copying latest options.

**Gate G5:** reviewed rendered artifacts, successful static checks, explicit
paths/identities, management access plan, and a tested staging recovery package.
No placeholder may remain in activation inputs.

### Step 6 — Activate in staging and prove the server boundary

1. Confirm authorization, management ranges, an independent console or second
   management session, and a restorable ruleset owned by the existing firewall
   manager. Close ingress and stop the old embedded-Arti proxy. Record existing
   service sockets/connection state; remove only stale state belonging to this
   deployment when needed. Do not flush unrelated host connections.
2. Activate the verified namespace/policy package with services stopped. Check
   routes, rule priorities, service identities, capabilities, and exact listeners.
   Start Arti, verify bootstrap, start the proxy, and open controlled ingress
   only after readiness. Confirm production mode rejects plaintext/development
   configuration and an embedded backend.
3. Run probes from the actual production namespace, UID, cgroup, and sandbox.
   A shell using only `sudo -u proxy-app` is not equivalent. Provide a staging
   test entry point with the same unit restrictions and only a bounded probe
   executable. Do not install an arbitrary command runner into production.
4. Use unique controlled target addresses/ports and DNS names. Start observations
   before probes and correlate namespace-link captures, public-interface
   captures, numeric nft counters, route tables, service/cgroup identity, and
   destination-side receipts. A public-interface capture cannot identify a UID
   on its own. A no-route failure may occur before a firewall counter increments;
   record that separately and exercise forbidden reachable peer ports to test
   firewall enforcement as well.
5. Execute the entire server matrix in Section 7, including boot, reload,
   upgrade, restart loops, and rollback. Use continuous bounded probes around
   transitions so a brief leak window cannot hide between samples. Repeat
   bootstrap tests for every supported bridge/transport mode.
6. Stop deployment on any unauthorized packet or listener access. Keep the
   containment boundary active, preserve controlled evidence, and repair before
   retrying. Restore management independently if needed; keep proxy ingress
   closed while restoring a host policy that has not passed containment tests.

**Gate G6:** all server matrix rows pass under the real service boundary, with
independent network evidence and exercised reboot/rollback. This gate is required
before any external Apple pilot. A smoke test, Tor exit-IP result, or unit-test
pass alone cannot satisfy it.

### Step 7 — Freeze Apple traffic, DNS, and exclusion policy

Implement this initial policy exactly for the selected protected apps. Expand it
only through a versioned policy decision with additional tests.

| Traffic or event | Initial outcome | Required implementation behavior |
|---|---|---|
| Hostname-bearing TCP to approved public destination/port | Tunnel | Preserve the canonical name through CONNECT; remote resolution through Arti |
| IP-only TCP, including addresses returned by app-managed DNS | Reject | No reverse lookup, SNI sniffing, hostname inference, or synthetic mapping |
| Public IPv4/IPv6 destination reached by hostname | Tunnel | Both destination families are test cases; no direct Happy Eyeballs fallback |
| Protected UDP/TCP port 53, including local resolver stub | Reject | No conventional client DNS forwarding or local resolver fallback |
| DNS-over-TLS TCP 853 | Reject | Outside the initial default destination-port allowlist |
| DNS-over-HTTPS on allowed TCP 443 | Tunnel as opaque HTTPS | The resolver connection also traverses Tor; subsequent IP-only flows remain rejected |
| QUIC/HTTP/3 and other application UDP | Reject | Handle DNS separately; application TCP fallback is optional compatibility behavior |
| Loopback, private, link-local, multicast, local discovery names | Reject | Enforce before control connection creation and again at server destination policy |
| Protected AirDrop/AirPlay/printer/local discovery attempts | Reject | No convenience LAN bypass; verify applicable flows actually belong to protected scope |
| ICMP or raw IP from a protected application | Deny by independently verified OS policy, or fail scope gate | A TCP/UDP flow callback cannot claim to enforce protocols it never receives |
| Captive portal and OS network control traffic | Explicit documented OS scope/exclusion | No temporary protected-app bypass; remain unavailable if needed for connectivity |
| Provider-owned connection to the appliance | Narrow transport exception | Exact configured endpoint, verified TLS identity and mTLS, provider ownership |
| Unmanaged apps | Outside this pilot's scope | Describe honestly; their direct traffic is not evidence about protected flows |
| Provider starting, failed, restarting, credentials unavailable | Reject protected traffic | Preserve managed policy; no direct release of flows |
| Explicit authorized disable/uninstall | Protection ends visibly | Warn in product state before removal; never report an outage as authorized disable |

1. Build a centralized admission decision before opening upstream connections.
   Standard app-proxy rejection can close the flow. If a future transparent
   implementation is approved, included protected TCP and UDP flows must always
   be claimed and then either forwarded or explicitly closed; returning `false`
   releases them to the direct path. Review both flow callbacks and every error,
   overload, cancellation, and unsupported-protocol branch. Apple documents the
   distinction in [the transparent provider contract](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
   and [the base flow handler](https://developer.apple.com/documentation/networkextension/neappproxyprovider/handlenewflow(_:)).
2. Prove that permitted hostname flows do not first resolve locally. Clear
   fixture caches, generate unique controlled names, and observe the system
   resolver path as well as app traffic. Include delegated resolver/helper
   traffic in the proof. Merely retaining the hostname is insufficient:
   transparent providers explicitly retain normal DNS behavior for connect-by-name
   APIs and ignore DNS settings in their transparent network settings, according
   to [Apple's contract](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider).
3. Do not promise compatibility with apps needing traditional DNS or IP-only
   sockets in this first version. If a required application cannot pass the
   no-local-DNS gate, mark it unsupported. A DNS proxy, remote DNS service, or
   synthetic-address system needs a separate specified design and entitlement
   review; it is not an implementation shortcut inside this step. DoH policy is
   about its transport path, not detecting encrypted query content.
4. Configure the appliance endpoint using authenticated, versioned provisioning
   with a small exact set of literal IP addresses and a separate expected TLS
   server name. This avoids needing unprotected bootstrap DNS on the Mac.
   Authenticate endpoint-set changes, cap the set, and test overlap/expiry.
   Exhausted or stale endpoint sets fail closed; never fall back to resolving an
   arbitrary hostname locally. Disable extra TLS revocation/AIA fetch paths that
   could bypass the reviewed network policy; choose and document a trust and
   revocation policy that does not need such uncontrolled fetches.
5. Prove that the provider's own outbound connection is not recursively captured
   using the selected API's documented behavior. Bind any required exception
   to that provider-owned connection as narrowly as possible. No general TCP 443,
   destination subnet, or shared-server exception. Another protected app
   connecting to the same appliance IP/port must not gain direct access.
6. Inventory mandatory and chosen OS exclusions by supported release. Each needs
   an expected outcome, owner, and capture case. Do not copy iOS always-on VPN
   promises into a macOS app-proxy claim. If the chosen provider cannot enforce
   the required policy while absent or cannot protect delegated DNS, fail G7.

**Gate G7:** a versioned app/protocol/lifecycle scope and exclusion matrix; no
unresolved DNS or recursive-connection behavior; negative tests demonstrate the
exception is unavailable to other protected apps. G7 failure blocks forwarding
for the affected app or deployment scope.

### Step 8 — Implement credentials and the bounded Apple adapter

#### Credentials and trust

1. Define authenticated device enrollment before accepting a configuration.
   Issue a device certificate and an account/workspace-scoped API key bound to
   the same account by the existing server checks. Do not invent a public,
   unauthenticated enrollment endpoint. Generate the device key in the selected
   Keychain-backed facility; keep it nonexportable where supported by the chosen
   TLS/signing path and prove the actual storage behavior.
2. Limit Keychain sharing to the signed host app and provider identities that
   need access. Test accessibility during logout, before first unlock, upgrade,
   and restore. A locked/unavailable credential store keeps traffic denied.
   Do not export secrets into preferences, environment variables, argv, logs,
   crash attachments, or a world-readable configuration file. Limit transient
   plaintext API-key copies and redact error/debug formatting.
3. Match the existing wire contract: `Proxy-Authorization: Basic` encodes the
   API key as the username with an empty password (`base64(api_key + ":")`).
   This header is sent only inside verified TLS. Require TLS 1.3, server-name
   validation, the configured trust roots, mTLS, and HTTP/1.1 compatibility.
   Do not enable TLS early data or share sessions across credential identities.
4. Specify certificate/API-key lifetimes, enrollment expiry, and a finite trust
   overlap in the manifest. Publish the new server-side credential binding,
   install the new client generation, verify a controlled authenticated flow,
   atomically switch the active generation, then retire the old one after the
   agreed overlap. Do not mix an old certificate and new key accidentally.
5. Test expired/revoked keys, revoked devices, suspended accounts/workspaces,
   certificate renewal, changed server roots, partial rotation, lost devices,
   restored backups, and uninstall cleanup. Establish an explicit policy for
   already-open tunnels: admission-time revocation is not immediate termination.
   For the pilot, require bounded active-tunnel revalidation/cancellation with
   a proposed maximum delay of 5 seconds from committed revocation, or implement
   that server prerequisite before pilot. Include revalidation, cache invalidation,
   and cancellation in this total; an unavailable authority must not extend the
   lease indefinitely. Record any reviewed alternative bound before testing.
   Idle tunnels must not evade revocation simply by producing no accounting
   updates. Recovery must not reactivate revoked credentials.

#### Flow ownership and transport

Implement the state machine below with a single owner per flow:

```text
received -> policy/admission -> transport connecting -> TLS verified
  -> CONNECT pending -> established -> half-closed/draining -> closed
any pre-establishment state -> failed -> closed
any state -> cancellation -> closed
```

1. Own the provider flow immediately and acquire bounded capacity before
   allocating transport buffers. Unsupported/rejected flows close promptly.
   Open the Apple flow only when the adapter is ready under the API contract.
2. Open one provider-owned connection to the configured appliance, verify TLS,
   send one CONNECT with canonical authority and existing isolation headers,
   and await success before copying application payload. Do not use a system
   HTTP proxy setting or automatic redirect handler for this transport.
3. Bound CONNECT response parsing to 16 KiB and 64 headers. Test incremental
   headers, rejected status codes, invalid syntax, and immediate post-header
   tunnel data. The server currently emits `200`; fail closed on other statuses
   for this client contract. Do not reflect remote error text into logs.
4. Keep application destination TLS end-to-end. Do not terminate it, install a
   destination-signing CA, parse tunneled application protocols, or pool separate
   CONNECT tunnels on a connection that has already become an opaque byte stream.
5. Honor backpressure in both directions. Retain each buffer until its write
   completes; bound outstanding reads/writes and partial writes. Propagate a
   one-sided EOF without prematurely losing data in the other direction. On
   fatal errors or revocation, close both sides and release all ownership once.
6. On stop, reject new flows, drain within the configured budget, cancel the
   remainder, and join all tasks. Repeated stop/cancel and late framework
   callbacks must be harmless. Leave managed fail-closed policy active during
   failures/restarts. Do not remove rules as generic error cleanup.
7. Record only bounded flow/setup/timeout/cancellation outcomes, queue depth,
   active counts, and buffer pressure. No destinations, DNS names, app identity,
   account identifiers, tokens, TLS material, payloads, or per-flow labels.

Use these **proposed pilot defaults**, then record measured changes in the
manifest. They are design limits, not existing constants or capacity claims:

| Resource | Initial bound | Enforcement |
|---|---:|---|
| Pending client flow setups | 32 per device | Reject excess; bounded wait at most 1 s |
| Concurrent client TLS handshakes | 8 per device | Separate semaphore; queue consumes setup deadline |
| Established client flows | 64 per device | Also subject to lower server/account admission ceilings |
| Relay buffering | 64 KiB per direction per flow; 8 MiB device-wide | Account for pending and established flows together |
| Client setup wall time | 90 s from admission | Never reset on stage changes or alternate appliance address |
| Appliance TCP connect / TLS handshake | 10 s each, within total | Bound each attempted endpoint; maximum two configured endpoint attempts |
| CONNECT response after TLS | 65 s, within total | Accommodates current server admission and 45 s Tor setup budget |
| Established idle timeout | 300 s | Activity in either direction resets it; revocation timer remains independent |
| Graceful drain / forced cleanup | 30 s / 5 s | Supervisor timeout must exceed their sum plus shutdown margin |

Framework/TLS buffers and task overhead are additional to relay buffers. Set a
measured extension memory budget and check aggregate server admission across all
pilot devices; 64 flows per device does not imply every device can receive that
many simultaneous server slots. Current server ceilings include 32 circuit builds
and 256 active tunnels. Preserve them until benchmark evidence justifies changes.

**Gate G8:** deterministic adapter and credential tests pass; controlled flows
preserve byte streams, isolation, deadlines, redaction, revocation behavior,
bounded memory, and cleanup. Benchmarks show the selected one-connection-per-flow
design meets the declared pilot budget. If it does not, reduce supported load or
write a separate multiplexing design preserving per-stream authorization and
isolation; do not silently pool authenticated tunnels.

### Step 9 — Run the real macOS acceptance matrix

1. Require G2, G6, G7, G8, completed destination-policy enforcement, and verified
   account/credential behavior. Install the intended signed release package on
   every supported OS/hardware combination.
2. Run the client matrix in Section 7 against controlled dual-stack origins and
   resolver fixtures. Capture relevant physical interfaces, loopback/resolver
   paths where applicable, and the appliance observation points. Verify the
   positive tunneled result and the absence of prohibited direct packets.
3. Start captures before enable/reconnect events. Use fresh controlled names to
   avoid cache-based false passes; test helper-process DNS attribution and both
   address-family fallback directions. Separate legitimate appliance transport,
   OS exclusions, and uncontrolled background-app traffic in analysis.
4. Benchmark TLS connection rate, concurrent/long-lived flows, CPU, memory,
   latency distributions, queue pressure, and Mac energy use. Run a declared
   bounded soak, for example one hour at the agreed pilot load, plus a capped
   burst above admission limits. Report hardware, duration, limits, and failures.
   Maintain an application compatibility table; QUIC denial does not guarantee
   that a particular application retries over TCP.

**Gate G9:** all required lifecycle and network cases have retained evidence on
the supported Mac matrix; no unresolved direct traffic, resource growth,
credential, or orphaned-task failures. Passing grants readiness for a controlled
experimental pilot, not unrestricted deployment or a general VPN claim.

### Step 10 — Publish the exercised runbook and pilot safely

1. Create the deployment-specific runbook only after activation and recovery are
   exercised. Include exact rendered artifact digests, prerequisites, activation
   commands, expected observations, shutdown, rollback, and console recovery.
   Link it from the documentation map and record evidence for each G1–G9 gate.
2. Pilot with an explicit device/account cap, declared supported applications,
   and an operator-owned incident channel. Alerts should use bounded rejection,
   readiness, DNS-attempt, restart, and resource metrics, without browsing data.
3. On containment, isolation, authentication, DNS, or credential failure, close
   admission and keep protected traffic denied. Existing streams may drain only
   when the security boundary remains valid; credential/security incidents can
   require immediate cancellation. Preserve minimal controlled evidence.
4. Roll back binaries, daemon configuration, namespace/rules, and credential
   compatibility as a reviewed bundle. Use a last-known-good **contained**
   deployment. If no such release exists, remain unavailable; do not restore the
   embedded production process or give the proxy Internet access to recover.
5. If host recovery requires restoring an older permissive firewall, first stop
   and prevent auto-restart of proxy/Arti and withdraw their ingress. Reopen only
   after G6 passes again. A management-access rollback and a service rollback
   have different acceptance criteria.
6. On the Mac, stop admission and close/revoke affected flows while preserving
   managed protection. A failed upgrade restores the prior signed compatible
   bundle without disabling policy. Uninstall is a separate explicit end of
   protection with credential revocation and documented residual Keychain/state
   cleanup; never use it automatically as incident recovery.

**Gate G10:** reproducible runbook, reviewed evidence ledger, tested contained
rollback, and a pilot whose published scope matches the evidence.

### Step 11 — Optional raw TUN research, only after a new feasibility gate

1. Document the routing requirement that the selected flow provider cannot meet.
   First assess whether the proposed use is supported by Apple.
   [TN3120](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)
   cautions against using packet tunnels as local filters or proxy servers.
   A tun2socks-style sketch is not proof of a supported or distributable design.
   If the intended translation conflicts with the platform contract, stop this
   track rather than depending on undocumented `utun` kernel controls.
2. If a supported design is established, specify packet ingestion and validation,
   IPv4/IPv6 handling, userspace TCP termination, per-flow CONNECT creation,
   bidirectional stream transfer, generated return packets, and packet injection.
   Sending captured IP packets directly to Arti is invalid.
3. Select a maintained userspace stack only after reviewing its provenance,
   license, update history, security process, unsafe/FFI boundaries, fuzzing, and
   supported targets. Specify sequence/window behavior, retransmission timers,
   half-close/reset, flow mapping, checksums, fragmentation policy, IPv6 extension
   handling, path MTU, permitted ICMP, DNS, routes, and teardown ownership.
4. Define numeric per-flow and global byte/flow/fragment/timer/retransmission
   limits before parsing packets. Use bounded queues and pressure rejection;
   reject unsupported packets deterministically without direct fallback.
5. Test with offline malformed-packet/property/fuzz fixtures and controlled
   network tests, including checksum failures, overlapping fragments, unknown
   extensions, out-of-order traffic, loss, tiny MTUs, resource exhaustion, and
   shutdown during reassembly. Repeat the DNS, containment, credentials,
   routing-exception, and lifecycle gates for the packet design.

**Gate G11:** a separately reviewed, supported, maintainable packet-to-stream
architecture and evidence. This guide does not select a TCP/IP stack or approve
Track B deployment. A WireGuard/BoringTun transport would add a separate remote
IP service and translator; it does not supply this missing Tor boundary.

## 5. Audit finding coverage

All 20 findings from the source audit have an implementation owner-step and a
checkable completion condition:

| Finding | Implementation steps | Evidence required |
|---|---|---|
| X1 — ingress topology | 1, 5 | Native TLS path; no forwarded identity trust; authenticated ingress tests |
| X2 — external Arti required/deferred | 1, 3, 4 | Roadmap dependency fixed; external connector is the production path |
| X3 — pilot before host kill switch | 6, 9 | G6 linked as mandatory; retained containment evidence |
| E1 — CONNECT capability | 4 | Exact daemon/protocol fixture; behavior and circuit-isolation evidence |
| E2 — private listener authorization | 4, 5, 6 | Endpoint use/replacement denied to unrelated local processes |
| E3 — Arti compromise boundary | Section 3; Steps 5, 10 | Threat limits stated; sandbox, update, monitoring, recovery package |
| E4 — UID-only filtering | 5, 6 | No-default-route namespace plus firewall verified under real unit identity |
| E5 — Arti DNS/bootstrap | 5, 6 | Per-mode DNS inventory and cold/warm/rebootstrap observations |
| E6 — policy/race verification | 6, 9 | Dual-stack protocol matrix and continuous transition probes |
| E7 — plan versus runbook | 10 | Host-specific exercised commands and recovery evidence |
| A1 — provider/deployment choice | 2 | Selected signed managed app-proxy package and lifecycle proof |
| A2 — transparent fail-open | 7, 8 | Both callback branches reviewed; claimed failures close instead of release |
| A3 — capture scope | 2, 7, 9 | Versioned protected apps, protocols, states, and OS exclusions |
| A4 — DNS architecture | 7, 9 | Explicit deny/hostname policy; delegated DNS and fresh-name captures |
| A5 — connection exception | 7, 9 | Provider-only exception; another app cannot use it directly |
| A6 — unsupported UDP | 7, 9 | DNS separated from other UDP; rejection and compatibility tests |
| A7 — per-flow TLS cost | 8, 9 | Numeric limits, bounded overload, CPU/memory/latency/energy measurements |
| A8 — packet-to-stream design | 11 | Separate Apple feasibility, stack review, bounded state machine/tests |
| A9 — credential lifecycle | 8, 9, 10 | Enrollment, Keychain, rotation, revocation, restore, and cleanup evidence |
| A10 — local-network policy | 7, 9 | Matrix outcome for each local traffic class and exclusion |

## 6. Verification commands and evidence format

For each server implementation milestone, run this sequence from the repository
root. It is a future implementation checkpoint, not a claim these commands were
run to produce this documentation:

```bash
git status --short
cargo fmt --check
cargo check --locked
cargo build --locked
cargo test --locked
git diff --check
```

If a baseline formatting check fails, record it and format the touched code
without sweeping unrelated files. Do not hide compiler/test failures or add
unrelated formatting changes to make a gate look clean. Add release build and
packaging checks for the actual deployment candidate. Review scripts before
running them: historical public-IP/geolocation checks in repository guidance
are not this task's controlled-origin containment evidence.

The implementing agent must supply exact Mac build/test/package commands using
the created project, scheme, signing method, and tested OS. Do not invent an
existing Xcode project or claim simulator/Linux tests verify Network Extension
behavior. Retain signed-entitlement inspection and release installation results.

Store a redacted gate ledger in `docs/tests/` and keep sensitive raw artifacts
outside the repository in a restricted evidence store. Each test record must
contain:

```text
test_id / audit_findings / gate
revision / binary and configuration digests / UTC start and end
OS and hardware / service UID and cgroup / namespace or Apple policy scope
controlled fixture / exact command or automated test name
expected result / actual result / pass, fail, blocked, or not applicable
capture and counter references / positive-control result / cleanup result
reviewer or operator / remaining limitation / next action
```

For captures, use controlled traffic, minimal necessary snap length and duration,
restricted permissions, and a declared retention/deletion period. Disable name
resolution in capture/counter tools. Keep any needed DNS proof in restricted
synthetic-fixture evidence, not application telemetry. Confirm the capture saw
the positive control and relevant interfaces; empty captures are not proof.

## 7. Required acceptance matrix

### Server

| Test group | Required cases | Pass condition |
|---|---|---|
| Connector framing | Partial reads/writes, oversize/truncated/invalid replies, non-success, success plus payload | Bounded parsing; no dropped or premature payload; classified failures |
| Isolation | Same scope, different accounts/workspaces/destinations/sub-identities, strict, expiry, retries | Expected reuse eligibility/separation with pinned-daemon circuit evidence |
| Policy and ingress | HTTP/CONNECT, invalid mTLS/API key, spoofed internal/Tor headers, denied ports/special addresses, cache hits after policy change | Denied before connector/cache use as applicable; no identity leakage |
| Accounting/lifecycle | Quota/revocation during transfer and idle, half-close, cancel at every stage, drain/force-stop | Timely enforcement; exact ownership and bounded shutdown |
| Direct TCP | Controlled public IPv4/IPv6, local/private/link-local targets, forbidden peer ports | No unauthorized packet or fixture receipt; attributable route/firewall denial |
| DNS | UDP/TCP 53 to public/private resolver and local stub, delegated host resolver IPC | No proxy-originated resolver access; no protected query leakage |
| UDP/other protocols | UDP 443, arbitrary UDP, IPv4/IPv6 fallback, unsupported raw protocols | Denied or unavailable under service capabilities; no direct escape |
| Endpoint boundary | Unrelated host UID, namespace entry attempt, listener replacement during Arti stop | No private endpoint access or replacement without privileged control |
| Positive controls | Authenticated HTTP and HTTPS; remote hostname resolution; IPv4/IPv6 destinations | Controlled origin sees Tor egress; client gets expected response |
| Arti lifecycle | Cold/warm bootstrap, configured bridges/transports, restart, refusal, timeout | Only declared bootstrap path; no user-name local DNS; no fallback |
| Host lifecycle | Cold boot, policy reload failure, proxy/Arti crash loops, upgrade, rollback | Continuous denial during transitions; firewall-before-service verified |
| Exposure and resources | Public internal-port checks, metrics, state/socket permissions, capped load | Only intended TLS ingress exposed; limits/recovery match manifest |

### Apple

| Test group | Required cases | Pass condition |
|---|---|---|
| Deployment | Signed install/enable/disable/uninstall, OS versions, entitlement denial, MDM rules | Real device behavior and documented protection state match G2 |
| Supported flows | HTTP/HTTPS, hostname-based IPv4/IPv6, concurrent/long-lived, half-close | Correct bytes through authenticated appliance/Tor path |
| DNS and scope | Fresh names, cleared caches, IP-only calls, conventional DNS, delegated helpers, DoH/DoT | Policy matrix honored; no protected local DNS, including before callback |
| Unsupported traffic | QUIC, arbitrary UDP, raw/ICMP, local discovery, LAN/loopback | Rejected within enforced scope; unsupported APIs cannot silently bypass |
| Exclusion abuse | Another protected app targets the appliance IP/port; endpoint set rotates/expires | Exception stays provider-owned; no recursion or broad direct path |
| Failure states | TLS/name/auth failure, proxy refusal, Arti outage, exhausted capacity, failed configuration | Included flows close; persistent policy prevents direct traffic |
| Credential lifecycle | Expiry/revocation, rotation overlap, locked Keychain, restore, changed trust | No unauthorized admission; active termination meets stated delay |
| Device lifecycle | Boot/login/logout, sleep/wake, interface changes, captive portal, provider crash/restart, upgrade | Continuous scoped protection or explicit unsupported result that blocks pilot |
| Cancellation/ownership | Stop during each setup stage, repeated stop, delayed callbacks, force-stop | No orphaned flow, task, buffer, transport socket, or stale owned state |
| Performance | Declared pilot concurrency, new-flow rate, capped burst, soak, energy | Limits hold; no growing queues/memory; compatibility limitations recorded |

## 8. Handoff and definition of done

The implementation handoff must include the server connector/tests, pinned daemon
contract, rendered deployment configuration, signed Apple project and policy,
credential lifecycle, bounded resource measurements, and the tested runbook.
Every audit row must link to a passing gate or an explicit blocker. G11 may remain
deferred without blocking the flow-provider pilot; G1–G10 may not be silently
waived. No test can be marked not applicable to evade the declared protected
scope.

Completion means the implementation and actual deployment evidence meet the
stated boundaries. Until then, describe results precisely as designed,
implemented, locally tested, staging verified, or pilot verified. Do not promote
this guide, its defaults, or passing unit tests into a claim of production
security or whole-device anonymity.
