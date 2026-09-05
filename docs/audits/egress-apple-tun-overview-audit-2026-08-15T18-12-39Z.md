# Egress Hardening and Apple TUN Overview Audit

- **Audit timestamp:** 2026-08-15T18:12:39Z
- **Audit type:** Documentation and architecture review
- **Implementation status:** Findings and repair procedures only; this audit does not claim that the proposed changes are implemented or deployed
- **Documents reviewed:**
  - [`docs/plans/firewall/egress-hardening.md`](../plans/firewall/egress-hardening.md)
  - Experimental Phase E1 in [`src/ROADMAP.md`](../../src/ROADMAP.md#experimental-phase-e1--macos-tcp-over-tor-client)
  - [`docs/audits/markdown-implementation-audit-2026-08-09.md`](markdown-implementation-audit-2026-08-09.md) for current-state conflicts

## Executive summary

The two plans contain strong component-level safeguards, but they do not yet
describe one consistent, implementable end-to-end security architecture. Three
cross-document blockers must be resolved before implementation:

1. The egress plan assumes Caddy/nginx ingress, while the current implementation
   uses native Rustls with mTLS and API-key authorization.
2. The egress plan requires external Arti, while the roadmap explicitly defers
   replacing embedded Arti.
3. The Apple experiment requires authenticated ingress and account controls but
   does not require completion of the host egress kill switch before an external
   pilot.

The Apple/TUN material is not a standalone document. It is Experimental Phase
E1 in `src/ROADMAP.md`. Its preferred flow-provider path remains a better match
for Arti TCP streams than raw packet tunneling, but provider selection,
deployment scope, DNS behavior, and fail-closed semantics need to be decided
before implementation begins.

## Cross-document blockers

### X1 — Conflicting ingress topology

**Priority:** Blocker

The egress target diagram places Caddy/nginx at the public TLS boundary. The
implemented architecture and Apple data path instead depend on native Rustls,
mTLS, and `Proxy-Authorization`. Introducing a separate frontend changes client
certificate verification, identity propagation, header-spoofing risk, service
identities, and firewall paths.

**Brief repair procedure:**

1. Select one canonical ingress architecture.
2. Retain native Rustls unless a separate trust-boundary review justifies a
   frontend.
3. Update the target diagram, service identities, certificate ownership,
   authentication flow, listener bindings, and firewall rules together.
4. If a frontend is adopted, prove that client identity cannot be injected or
   spoofed through forwarded headers.

### X2 — External Arti is both required and deferred

**Priority:** Blocker

Egress Phase 2 requires a separate Arti service so firewall policy can distinguish
the proxy from Tor relay traffic. The roadmap simultaneously lists replacement
of embedded Arti as deferred work. This leaves no authoritative dependency order
or implementation owner.

**Brief repair procedure:**

1. Decide whether external Arti is part of the active production architecture.
2. If yes, move it out of deferred work and give it a dedicated milestone,
   owner, compatibility contract, rollback path, and acceptance gate.
3. If no, revise the egress design because UID-based separation cannot be
   achieved while Pingora and Arti share one process identity.

### X3 — Apple pilot can precede the host kill switch

**Priority:** Blocker

Apple E1 lists authenticated ingress and account controls as prerequisites, but
not the host-level egress containment and packet-capture evidence required by the
egress plan. The current repository audit records only application-level
fail-closed behavior; the host kill switch is not implemented.

**Brief repair procedure:**

Add the following prerequisites to E1 before any external pilot:

- Completed egress Phase 4, or preferably the Phase 5 namespace boundary.
- Firewall-before-service ordering verified across reboot.
- Direct IPv4, IPv6, UDP, and DNS denial under the production proxy identity.
- Independent packet-capture and firewall-counter evidence.
- Tested Arti failure and rollback behavior.

## Egress-hardening findings

### E1 — HTTP CONNECT capability is assumed, not deployment-proven

**Priority:** High

The plan prefers Arti HTTP CONNECT but does not identify the exact pinned Arti
version, configuration option, listener, or startup capability check. The Tor
HTTP CONNECT specification describes Arti support, while the public Arti startup
guide currently documents `arti proxy` as a SOCKS proxy on port 9150. The Tor
specification also notes that advertised capability headers are not fully
implemented, so configuration presence alone is not a sufficient gate.

**Brief repair procedure:**

1. Pin the exact Arti release and configuration.
2. Start the actual production binary in a controlled environment.
3. Behaviorally test CONNECT, hostname preservation, bounded response parsing,
   error mapping, post-header bytes, and isolation separation.
4. Refuse proxy readiness when required isolation behavior is unavailable.
5. Use SOCKS5 isolation with a bounded client if the pinned deployment cannot
   expose the required HTTP CONNECT behavior.

### E2 — The private Arti listener lacks a complete authorization boundary

**Priority:** High

`Tor-Stream-Isolation` is an isolation input, not authentication of the local
caller. A loopback TCP listener protected only by separate Unix users can still
be reached by unrelated local processes unless host policy expressly prevents
it. A replacement process may also occupy the endpoint when Arti is unavailable.

**Brief repair procedure:**

1. Prefer a private namespace path or a Unix socket if supported by the pinned
   Arti deployment.
2. Otherwise restrict loopback traffic by service identity/cgroup and exact
   address and port.
3. Start the listener with deterministic ownership and ordering.
4. Verify expected peer behavior before declaring the proxy ready.
5. Add a negative test proving an unrelated local process cannot use or replace
   the endpoint.

### E3 — The Arti compromise boundary is unstated

**Priority:** High

The firewall can ensure that only Arti has general Internet access, but it cannot
prove that a compromised Arti process connects only to Tor relays. Relay and
directory addresses change, which makes a static destination allowlist
impractical. Therefore the kill switch protects against proxy-process clearnet
leaks, not arbitrary behavior after Arti compromise.

**Brief repair procedure:**

1. State this residual risk in the threat model and definition of done.
2. Run Arti with its own minimal systemd sandbox, read/write paths, resource
   limits, update policy, and private listener.
3. Monitor privacy-safe connection and DNS anomalies without logging user
   destinations.
4. Treat Arti compromise as a separate incident and recovery scenario.

### E4 — UID-scoped filtering is too weak for an unqualified production claim

**Priority:** High

The plan describes UID-scoped nftables as a reasonable first production
boundary and makes a network namespace optional. UID rules remain sensitive to
same-identity processes, host rule ownership, connection state, and ordering
races during boot, reload, restart, and upgrade.

**Brief repair procedure:**

1. Use UID-scoped filtering only as an intermediate deployment stage.
2. Make a proxy network namespace with no default route the production baseline.
3. Provide only explicit ingress, Arti, and monitoring paths.
4. Load and verify the namespace/firewall boundary before starting either public
   ingress or the proxy process.
5. Document host-root and same-UID compromise as threat-model limits.

### E5 — Arti DNS and bootstrap policy is undefined

**Priority:** High

The proxy is denied all local and external DNS, but the plan does not say whether
Arti, bridges, or pluggable transports require DNS for bootstrap or recovery. A
broad DNS permission for Arti could conceal regressions; denying it without a
bootstrap test could break deployment.

**Brief repair procedure:**

1. Inventory DNS requirements for the pinned Arti configuration, bridges, and
   transports.
2. If DNS is unnecessary, block it and test bootstrap/rebootstrap.
3. If required, allow only the chosen resolver path and document that user
   destination names must never reach it.
4. Add DNS counters and bridge/rebootstrap tests to the verification bundle.

### E6 — Verification does not cover the complete policy or race windows

**Priority:** High

The matrix checks TCP and DNS but does not explicitly test arbitrary UDP/QUIC,
firewall reload gaps, binary upgrades, crash/restart loops, or unauthorized
same-host services. A normal capture on the public interface also cannot, by
itself, attribute packets to a Unix UID.

**Brief repair procedure:**

Test under the real production identity and namespace:

- Direct TCP and arbitrary UDP over IPv4 and IPv6.
- UDP/443, UDP/TCP DNS, the local resolver stub, link-local and private ranges.
- Unauthorized loopback ports and replacement of the private Arti endpoint.
- Cold boot, firewall reload, service crash, Arti restart, proxy upgrade, and
  rollback.
- Packet captures correlated with nftables counters, cgroup/namespace evidence,
  route tables, and controlled unique test destinations.

### E7 — The artifact is a plan, not yet a runbook

**Priority:** Low

The title calls the document a runbook, while its purpose identifies it as an
implementation plan. It does not contain exercised host-specific commands,
rendered units, rule ownership, recovery commands, or evidence.

**Brief repair procedure:**

Rename it as a plan until one deployment-specific artifact contains exact,
reviewed commands and has passed activation, reboot, rollback, and recovery
testing. Preserve the tested version as the operational runbook.

## Apple flow-provider and TUN findings

### A1 — Provider and deployment model are undecided

**Priority:** Blocker

The roadmap proposes `NEAppProxyProvider` or `NETransparentProxyProvider` as if
they were interchangeable. They have different traffic scopes, deployment
requirements, lifecycle behavior, and failure semantics. App-proxy flows apply
to apps matching configured rules; macOS per-app VPN rules target MDM-managed
apps. App extensions are terminated at logout, while system extensions operate
independently of the logged-in user. Distribution through the App Store versus
Developer ID also changes the permitted packaging.

**Brief repair procedure:**

Create an E0 Apple feasibility gate before Rust implementation:

1. Choose managed per-app, system-wide transparent, or packet-tunnel scope.
2. Select app extension versus system extension.
3. Select App Store versus direct Developer ID distribution.
4. Obtain entitlement and provisioning proof.
5. Demonstrate install, enable, logout/login, disable, upgrade, and uninstall on
   every supported macOS release.

### A2 — Transparent-proxy rejection can fail open

**Priority:** Blocker

For `NETransparentProxyProvider`, returning `false` from `handleNewFlow` lets the
operating system connect directly to the destination. For ordinary
`NEAppProxyProvider`, returning `false` discards the flow. The roadmap's phrase
“demonstrably fail closed” does not encode this critical semantic difference.

**Brief repair procedure:**

1. Establish an invariant that included protected traffic is never returned as
   `false` by a transparent provider.
2. Claim unsupported or failed protected flows and explicitly close them.
3. Centralize this decision in one reviewed flow-admission function.
4. Add negative tests for authentication failure, TLS failure, proxy refusal,
   Arti outage, resource exhaustion, cancellation, and provider restart.

### A3 — The no-leak claim exceeds the defined capture scope

**Priority:** High

App-proxy coverage is rule-scoped. Packet tunnels have unavoidable Apple-defined
exclusions for traffic such as network control-plane operations and some captive
portal or device services. Broad route exclusions and application scoping can
also bypass a packet tunnel. Consequently, “no DNS or IPv4/IPv6 leak” cannot be
an unqualified whole-device statement across all proposed provider choices.

**Brief repair procedure:**

1. Define the exact protected applications, protocols, routes, and lifecycle
   states.
2. Enumerate Apple-mandated and product-selected exclusions.
3. Scope security claims and packet captures to protected traffic.
4. For managed deployments, document the required MDM and on-demand policy and
   prohibit disconnect rules that create unreviewed bypasses.

### A4 — DNS architecture is not selected

**Priority:** High

“Intercept, synthesize, or block” leaves three incompatible DNS designs open.
Higher-level networking APIs may provide the original hostname directly, while
low-level DNS can arrive as UDP flows. A transparent proxy ignores DNS settings
placed in its network settings, and IP-only flows cannot safely recover a
hostname through reverse DNS.

**Brief repair procedure:**

Define one DNS design for the selected provider, including:

- Hostname-bearing TCP flows sent unchanged to the proxy/Arti path.
- IP-only TCP behavior without reverse lookup.
- UDP and TCP DNS handling.
- DNS-over-HTTPS and DNS-over-TLS policy.
- Resolver failure and provider-restart behavior.
- Tests proving no protected hostname reaches a local resolver.

### A5 — The control-connection exclusion can become a bypass

**Priority:** High

The provider must avoid recursively capturing its own mTLS connection, but a
broad destination-IP or port exclusion can also permit other applications to use
the same direct path. Endpoint changes, multi-address DNS, or a shared frontend
can widen the exception unexpectedly.

**Brief repair procedure:**

1. Bind the exclusion as narrowly as the selected API permits to the
   provider-owned connection and authenticated proxy endpoint.
2. Avoid subnet, hostname-family, or general port exclusions.
3. Require mTLS and server verification on the excluded connection.
4. Add a negative test showing that another application cannot exploit the same
   exception.

### A6 — Unsupported UDP behavior is incomplete

**Priority:** High

The roadmap focuses on blocking UDP/443 so QUIC-capable applications may retry
TCP. A TCP retry is not guaranteed, and all unsupported protected UDP—not only
QUIC—needs deterministic behavior. DNS is a special UDP case and cannot simply
be conflated with application datagrams.

**Brief repair procedure:**

1. Define deny behavior for every protected UDP flow.
2. Separate DNS handling from general UDP rejection.
3. Never return `false` for included transparent-proxy UDP merely because it is
   unsupported.
4. Treat TCP fallback as an application compatibility result, not part of the
   security guarantee.
5. Maintain an application compatibility matrix.

### A7 — One authenticated HTTP/1.1 TLS connection per flow may not scale

**Priority:** High

The proposed mapping creates an independently authenticated mTLS/HTTP CONNECT
connection for every application TCP flow. This multiplies TLS handshakes,
certificate verification, server admission work, latency, and battery use.
Meanwhile, multiplexing is explicitly deferred.

**Brief repair procedure:**

1. Benchmark connection rate, concurrency, memory, CPU, latency, and energy on
   supported Macs and the appliance.
2. Set explicit pending-handshake and established-flow ceilings.
3. Decide whether the experiment accepts this limitation or requires a
   long-lived authenticated multiplexed transport.
4. Preserve per-stream authorization and Tor isolation if multiplexing is
   introduced.

### A8 — Raw `utun` research lacks a complete packet-to-stream design

**Priority:** High

The roadmap correctly acknowledges the need for a userspace TCP/IP stack, but it
does not select or gate that dependency or describe the full bidirectional
packet-to-CONNECT state machine. NAT/state mapping, reverse packet injection,
TCP timers, fragmentation, checksums, DNS synthesis, ICMP, path MTU, IPv6, and
memory exhaustion remain unresolved.

**Brief repair procedure:**

Require a separate tun2socks-style architecture spike before Track B:

1. Select and security-review a maintained userspace stack.
2. Specify packet ingestion, TCP termination, CONNECT creation, return-data
   injection, DNS, routing, MTU, IPv6, and shutdown.
3. Define numeric memory, flow, retransmission, and timer bounds.
4. Test malformed and adversarial packets.
5. Reject Track B if the dependency or maintenance burden cannot meet those
   gates.

### A9 — Credential lifecycle stops at Keychain storage

**Priority:** Medium

The roadmap says to store certificates and API credentials in Keychain but does
not define extension access groups, enrollment, expiry, rotation, revocation,
trust overlap, device replacement, or recovery after partial updates.

**Brief repair procedure:**

1. Define host-app/extension Keychain sharing and least-privilege access groups.
2. Use an authenticated enrollment process and bounded credential lifetime.
3. Support atomic certificate and API-key rotation with a reviewed overlap
   window.
4. Test revocation, expired credentials, partial upgrades, restore, and
   uninstall cleanup.

### A10 — Local-network behavior has tests but no expected policy

**Priority:** Medium

The verification section says to attempt local-network access without deciding
whether loopback, RFC1918, link-local, multicast, AirDrop, AirPlay, printers, and
captive portals should be blocked, tunneled, or deliberately excluded. These
choices materially affect both the leak claim and product usability.

**Brief repair procedure:**

Create a policy matrix for each traffic class with one of three explicit
outcomes: protected/tunneled, rejected, or intentionally excluded. Document the
security and usability consequence of every exclusion and turn each row into an
acceptance test.

## Recommended repair order

1. Resolve the ingress and external-Arti architecture contradictions.
2. Add external Arti and host egress containment to one authoritative dependency
   graph.
3. Complete the Apple E0 provider, entitlement, packaging, and distribution
   feasibility gate.
4. Prove the pinned proxy-to-Arti protocol and isolation behavior.
5. Implement and independently verify the server namespace/firewall kill switch.
6. Select and specify the Apple DNS and control-connection exclusion designs.
7. Implement the flow-provider proof of concept and run its failure-state and
   packet-capture matrix.
8. Consider raw `utun` research only if a documented requirement cannot be met
   by the flow-provider design.

## Primary external references

- [Tor HTTP CONNECT specification](https://spec.torproject.org/http-connect.html)
- [Tor stream-isolation specification](https://spec.torproject.org/path-spec/stream-isolation.html)
- [Starting Arti as a proxy](https://arti.torproject.org/guides/starting-arti/)
- [Apple: App proxy provider](https://developer.apple.com/documentation/networkextension/app-proxy-provider)
- [Apple: `NEAppProxyProvider`](https://developer.apple.com/documentation/networkextension/neappproxyprovider)
- [Apple: `NETransparentProxyProvider`](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)
- [Apple: Handling Flow Copying](https://developer.apple.com/documentation/networkextension/handling-flow-copying)
- [Apple: Routing your VPN network traffic](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)
- [Apple TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

## Evidence boundary

This audit is a documentation review. It does not demonstrate that external
Arti, systemd hardening, nftables, network namespaces, Apple entitlements,
Network Extension packaging, macOS routing, or live packet-capture verification
currently exist or pass. Those claims require their respective implementation
and deployment evidence gates.
