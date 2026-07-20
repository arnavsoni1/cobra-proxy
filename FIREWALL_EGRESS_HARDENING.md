# Firewall and Tor Process-Isolation Runbook

## Purpose

This document is an implementation plan for adding production-grade network containment to the proxy. It is written for an implementation agent and must be followed in order.

The primary security objective is **fail-closed Tor egress**:

- User traffic must leave through Tor or fail.
- The proxy process must not be able to open a direct Internet or DNS connection.
- Internal listeners and metrics must not become publicly reachable.
- Per-session and strict circuit-isolation behavior must survive the architecture change.

This work is separate from request rate limiting, authentication, abuse controls, and account authorization.

## Key decision

Do **not** use `tor-hsrproxy` as a firewall. `tor-hsrproxy` is an onion-service reverse proxy: it accepts incoming onion-service streams and forwards them to local services. It does not filter host traffic or prevent clearnet leaks.

Do **not** implement the host firewall inside the Rust proxy. A proxy that modifies its own firewall would require privileges such as `CAP_NET_ADMIN`, increasing the impact of a proxy compromise. Install firewall policy through the host's provisioning and service-management layer.

For production, separate the proxy and Arti into different processes. The current embedded design puts Pingora and Arti under one process identity, so a UID- or cgroup-based firewall cannot tell an intended Arti relay connection from an accidental direct connection elsewhere in the proxy.

## Target architecture

```text
                       public network
                             |
                    TLS/auth ingress only
                       (Caddy/nginx)
                             |
                    loopback/private network
                             |
                  +----------v-----------+
                  | Proxy service        |
                  | dedicated Unix user  |
                  | no Internet egress   |
                  +----------+-----------+
                             |
              local HTTP CONNECT or SOCKS5
                  with an isolation token
                             |
                  +----------v-----------+
                  | Arti service         |
                  | separate Unix user   |
                  | Internet egress      |
                  +----------+-----------+
                             |
                         Tor network
```

The minimum viable deployment may use loopback TCP between the proxy and Arti, protected by separate Unix users plus `nftables`. A stronger deployment puts the services in separate network namespaces or containers connected through a private veth/container network with no proxy-side default route.

## Agent execution contract

The implementation agent must obey these rules:

1. Read `src/AGENTS.md`, `src/ARCHITECTURE.md`, `src/ROADMAP.md`, this file, and the current `README.md` before changing anything.
2. Preserve unrelated worktree changes. Never run `git reset --hard`, discard user changes, or commit automatically.
3. Treat firewall activation as a destructive production operation. Creating and validating configuration files is allowed; applying them to a host requires explicit user approval.
4. Never apply an input default-drop policy until the management interface, SSH port, deployment ingress port, and out-of-band recovery method are known.
5. Do not assume the host uses raw `nftables`. Detect whether `firewalld`, `ufw`, a cloud firewall, or another tool owns the ruleset. Use one owner rather than creating conflicting policies.
6. Do not run the proxy or Arti as root. Do not grant either service `CAP_NET_ADMIN`.
7. Do not add a clearnet fallback. If Arti is unavailable or rejects a connection, return the appropriate proxy error.
8. Do not resolve destination hostnames locally. Send the original validated hostname to Arti.
9. Keep the current circuit admission guard around Tor/Arti connection establishment.
10. Complete and report every verification gate before proceeding to the next phase.

## Phase 0: Collect deployment facts

Before designing rules, record the following in the implementation summary or a deployment-specific configuration file:

- Linux distribution and kernel version.
- Whether the host uses systemd.
- Current firewall manager and complete active ruleset.
- Public network interface names.
- IPv4 and IPv6 availability.
- SSH/management source ranges and port.
- Public ingress ports, normally `443` and possibly `80` for an HTTP-to-HTTPS redirect.
- Which user runs Caddy/nginx, the proxy, and Arti.
- Whether the proxy and Arti will share a network namespace, use separate namespaces, or use containers.
- Exact Arti binary version and supported proxy protocols.
- Required local dependencies such as SQLite, metrics collection, and the Pingora internal listener.
- Available console, snapshot, or provider recovery access if firewall activation disconnects SSH.

Read-only discovery must happen before any package installation or firewall mutation. Redact public IP addresses, credentials, onion-service keys, and other secrets from logs and reports.

### Phase 0 gate

Do not continue to firewall activation unless:

- The existing ruleset has been backed up.
- A reviewed rollback procedure exists.
- A second management session or out-of-band console is available.
- All required ports and service identities are known.

## Phase 1: Add tests that define fail-closed behavior

Add tests before changing the Tor integration.

### Connector boundary

Create a narrow connection boundary in `src/main.rs`, consistent with the repository's single-source-file constraint. Production code should have one path responsible for opening anonymized streams. Test code must be able to substitute a fake local Arti endpoint.

The boundary must accept:

- The validated destination hostname and port.
- The resolved isolation policy.
- A connection-establishment deadline.

It must return an async byte stream or a classified connection error. No code outside this boundary may open destination sockets.

### Required automated tests

Add tests for all of the following:

1. A hostname is forwarded to Arti without local DNS resolution.
2. Session isolation reuses the same opaque isolation value for related streams.
3. Different isolation identities produce different isolation values.
4. Strict isolation produces a fresh value for every stream.
5. The isolation value contains no raw account identifier, API key, hostname, or URL.
6. The Arti request is rejected if it exceeds the existing header and destination limits.
7. A non-success Arti response never causes a direct connection fallback.
8. Arti connection timeout maps to the existing `502`/`504` policy as appropriate.
9. The circuit admission permit is released after Arti resolves connection establishment, not after the tunnel closes.
10. Bytes received immediately after a downstream CONNECT header are preserved.

### Phase 1 gate

- `cargo check` passes.
- `cargo build` passes.
- All existing and new tests pass.
- No production network path has changed yet.

## Phase 2: Run Arti as a separate service

### 2.1 Pin and configure Arti

Install a pinned Arti release through the deployment system. Do not implicitly track `latest` in production.

Configure Arti to:

- Run as a dedicated unprivileged user, for example `proxy-arti`.
- Persist its cache, state, and keys only in directories owned by that user.
- Listen only on a private endpoint.
- Enable the proxy protocol selected below.
- Keep sensitive-information logging disabled.
- Keep metrics private if enabled.
- Restart on failure with bounded backoff.

Do not expose the Arti listener on a public interface.

### 2.2 Preferred local protocol: HTTP CONNECT

The first implementation should use Arti's HTTP CONNECT support because the proxy already constructs and parses CONNECT traffic. It also avoids adding a general SOCKS client dependency.

For each destination, connect to the private Arti listener and send a request equivalent to:

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
Tor-Stream-Isolation: opaque-local-token
Connection: close

```

Requirements:

- Construct the authority from the already validated hostname and port.
- Preserve domain names; never perform a local lookup first.
- Generate the `Tor-Stream-Isolation` value from local opaque isolation material.
- Never place raw API keys, account IDs, URLs, or destination names in that header.
- Apply the existing maximum-header-size and timeout protections.
- Parse the Arti response with bounded buffering.
- Do not send `200 Connection Established` downstream until Arti returns success.
- Treat an unsupported isolation header as a startup/compatibility failure, not as permission to run without isolation.
- Do not log the isolation value.

The official Tor HTTP CONNECT specification defines `Tor-Stream-Isolation` as an application-provided strong isolation input. Two streams with different isolation values must not share a circuit.

### 2.3 Alternative: SOCKS5 or Arti RPC

Use SOCKS5 only if HTTP CONNECT support cannot meet a verified requirement. SOCKS5 username/password fields can convey a Tor isolation string, but they are not authentication to the local Arti daemon.

Arti RPC may be considered if its pinned API is stable enough for this deployment. Its stream-opening API accepts an isolation string directly. Do not adopt experimental APIs without documenting upgrade and compatibility risk.

Do not add `tor-hsrproxy` for outbound connectivity.

### 2.4 Preserve existing proxy behavior

During the migration:

- Preserve destination validation and local-network blocking.
- Preserve session and strict isolation semantics.
- Preserve global circuit admission control and active-tunnel limits.
- Preserve retries, but keep them inside the overall connection deadline.
- Preserve buffered tunnel bytes and half-close behavior.
- Preserve byte accounting and privacy-safe metrics.
- Replace detailed embedded-Arti errors with stable local classifications; never expose internal details to clients.
- Remove the embedded Arti client only after the external path passes all tests.

### Phase 2 gate

- A normal HTTP request succeeds through external Arti.
- An HTTPS CONNECT request succeeds through external Arti.
- Isolation tests demonstrate reuse and separation as intended.
- Stopping Arti makes new requests fail closed.
- A code search confirms no destination connection path bypasses the connector boundary.

## Phase 3: Create service identities and systemd hardening

Create separate service identities such as:

- `proxy-app`: runs Pingora and the local bridge.
- `proxy-arti`: runs only Arti.
- Existing Caddy/nginx user: owns public TLS ingress.

Files containing Arti state or onion-service keys must not be readable by `proxy-app` or the ingress user.

### Proxy service hardening

At minimum, evaluate and enable compatible systemd controls:

- `User=proxy-app`
- `Group=proxy-app`
- `NoNewPrivileges=yes`
- Empty `CapabilityBoundingSet=` unless a documented capability is required
- `PrivateDevices=yes`
- `ProtectSystem=strict`
- `ProtectHome=yes`
- Explicit `ReadWritePaths=` for only required state/socket paths
- `RestrictSUIDSGID=yes`
- `LockPersonality=yes`
- `RestrictNamespaces=yes` when the deployment does not require the process to create namespaces
- An explicit `RestrictAddressFamilies=` list
- Resource limits appropriate for the configured connection caps

Apply similar controls to Arti, while allowing its required state directories and Internet sockets.

Systemd sandboxing is defense in depth. It does not replace the egress firewall.

### Service ordering

- Load validated firewall policy before starting the proxy.
- Start Arti before declaring the proxy ready.
- Ensure proxy restart loops cannot bypass firewall initialization.
- Use bounded restart delay for both services.
- Keep readiness separate from mere process existence: Arti may need time to bootstrap.

### Phase 3 gate

- Both services run under distinct non-root UIDs.
- Neither service has `CAP_NET_ADMIN`.
- The proxy can reach only the expected local dependencies.
- Arti can bootstrap and serve a local CONNECT request.

## Phase 4: Install the egress kill switch

Use host-managed `nftables` unless the existing firewall owner requires another mechanism. Do not add a Rust firewall crate.

### 4.1 Proxy-specific output policy

Do not default-drop the entire host output chain as the first step. Create a policy scoped to the `proxy-app` UID or its dedicated cgroup/network namespace.

The proxy-specific policy should conceptually allow:

- Packets belonging to established connections, so the proxy can reply to ingress clients.
- New connections to the private Arti endpoint only.
- New connections to the internal Pingora listener if it remains TCP-based.
- Explicitly documented local database or telemetry endpoints, preferably over Unix sockets.

It should reject:

- New IPv4 Internet connections.
- New IPv6 Internet connections.
- UDP and TCP DNS, including access to a local resolving stub such as `127.0.0.53:53`.
- QUIC/UDP and every protocol not explicitly required.
- Link-local and private-network destinations other than the exact local endpoints required by the design.

Using `oifname "lo" accept` by itself is too broad because it permits access to local DNS resolvers and unrelated local services. Allow exact destination addresses, ports, and connection states.

### 4.2 Arti output policy

Arti must reach changing Tor relays and directory services, so a static relay-IP allowlist is not maintainable. Scope its outbound permission by its separate service identity or network namespace instead.

Arti should not be allowed to listen publicly. Its inbound policy should allow only the private proxy path and established traffic.

### 4.3 Host input policy

After the proxy-specific egress policy is proven, add or review host input filtering:

- Default-deny unsolicited inbound traffic.
- Allow established and related traffic.
- Allow management only from approved source ranges.
- Allow the public TLS ingress ports only.
- Do not expose `8080`, `8081`, `9090`, the Arti proxy port, or internal Unix sockets.
- Apply equivalent IPv4 and IPv6 policy.
- Keep the cloud security group/firewall aligned as a second layer.

### 4.4 Safe activation procedure

Before applying rules:

1. Render the complete candidate ruleset.
2. Validate it using the firewall manager's check-only mode, such as `nft --check`.
3. Review the diff against the active ruleset.
4. Prepare a time-bounded, independently executed rollback mechanism.
5. Confirm out-of-band console access.
6. Keep an existing management session open.
7. Apply only after explicit user approval.
8. Open a second new management session before cancelling rollback.
9. Run the verification matrix below.
10. Persist the rules only after every test passes.

Never use an unresolved environment variable, wildcard interface, or guessed SSH port in a firewall command.

### Phase 4 gate

- Direct egress as `proxy-app` fails for both IPv4 and IPv6.
- Direct DNS as `proxy-app` fails.
- Tor-proxied HTTP and HTTPS succeed.
- Arti bootstrap/rebootstrap succeeds.
- Management access and public TLS ingress still work.
- Internal ports remain unreachable from an external host.

## Phase 5: Stronger network-namespace isolation

UID-scoped `nftables` is a reasonable first production boundary. Network namespaces or containers provide a stronger boundary by giving the proxy a separate routing table and network stack.

For the stronger design:

1. Place the public TLS frontend in an ingress namespace/container with the public interface.
2. Place the proxy in an internal-only namespace/container with no default Internet route.
3. Place Arti in a namespace/container that can reach the Internet and a private proxy-to-Arti network.
4. Give the proxy routes only to the ingress and Arti private addresses.
5. Filter forwarding between these networks with default-deny policy.
6. Keep metrics on a separate private monitoring path.
7. Verify that deleting the Arti route or stopping Arti cannot create a path to the host default route.

Do not use systemd `PrivateNetwork=yes` blindly: it creates a loopback-only namespace, which will also make an external Arti TCP listener unreachable unless sockets or a private network are explicitly provided.

### Phase 5 gate

- The proxy namespace has no default Internet route.
- It cannot reach a public IPv4 or IPv6 address.
- It can reach only ingress, Arti, and explicitly approved local dependencies.
- Removing Arti causes fail-closed proxy errors.

## Optional Phase 6: Onion-service ingress

Implement this phase only if an onion address is a product requirement.

Use the Arti binary's onion-service reverse-proxy configuration or the high-level `TorClient::launch_onion_service` API. Use `tor-hsrproxy` directly only when custom handling unavailable in the higher-level interfaces is genuinely required.

Requirements:

- Run the onion service separately from the outbound proxy process.
- Forward only to the intended local ingress port.
- Protect the onion-service identity key with strict filesystem permissions and backups appropriate to the product.
- Retain proxy authentication and authorization. An onion address is not an account-authentication mechanism.
- Apply connection and request limits to onion ingress.
- Do not expose metrics or administration through the onion service.
- Pin all Arti ecosystem components and avoid mixing incompatible release lines.

This phase provides responder-location privacy and an alternative inbound transport. It does not replace the egress kill switch.

## Verification matrix

Run these checks in a controlled environment. Record commands, timestamps, versions, and redacted results in an evidence bundle.

| Test | Expected result |
|---|---|
| Direct TCP from `proxy-app` to a controlled public IP | Rejected by policy |
| Direct IPv6 TCP from `proxy-app` | Rejected by policy |
| UDP DNS from `proxy-app` | Rejected by policy |
| TCP DNS from `proxy-app` | Rejected by policy |
| Lookup through the host's local DNS stub as `proxy-app` | Rejected by policy |
| HTTP through the proxy | Succeeds through Tor |
| HTTPS CONNECT through the proxy | Succeeds through Tor |
| Session-isolated repeated requests | Preserve the intended isolation identity |
| Different isolation identities | Do not share an isolation profile |
| Strict-isolation requests | Receive fresh isolation values |
| Stop Arti, then request a destination | Fails closed; no direct traffic |
| Restart Arti | Proxy recovers after readiness |
| External access to internal and metrics ports | Refused or filtered |
| Reboot host | Firewall loads before proxy; all tests still pass |

Where possible, observe both application logs and packet capture on the public interface. The absence of a successful application response is not sufficient proof of no leak; the packet capture must show that the proxy UID/namespace emitted no unauthorized DNS or destination traffic.

## Metrics and alerts

Add or retain privacy-safe operational signals for:

- Arti connection availability and bootstrap readiness.
- Local Arti CONNECT failures by bounded error class.
- Circuit-admission queue depth and timeouts.
- Direct-egress firewall reject counters for the proxy identity.
- Unexpected attempts to access local DNS.
- Service restarts.

Do not label metrics with destination, account, isolation token, URL, or onion address. Alert when any proxy-specific firewall reject counter increases; it may identify a code regression or compromise attempt.

## Rollback requirements

Rollback must restore service without weakening the anonymity guarantee silently.

If the external Arti migration fails:

- Stop accepting new public traffic.
- Roll back the proxy binary and service configuration together.
- Restore the prior firewall rules only as an explicit, reviewed operation.
- Never leave a new proxy binary running with an old permissive egress policy.

If firewall activation fails:

- Use the prearranged rollback path or out-of-band console.
- Restore the backed-up ruleset through its existing firewall manager.
- Confirm management access and service state.
- Keep the proxy stopped until fail-closed behavior is revalidated.

## Deliverables

An implementation agent is finished only when it provides:

- The proxy-to-Arti connector and automated tests.
- A pinned Arti configuration with private listening only.
- Separate non-root service definitions for proxy and Arti.
- A validated firewall ruleset owned by the host's chosen firewall manager.
- A documented, tested rollback procedure.
- A deployment verification script or exact reproducible commands.
- A redacted evidence bundle showing every verification-matrix result.
- Updated architecture and operations documentation.
- A summary of remaining risks and any deployment-specific exceptions.

## Definition of done

This work is complete only when all statements below are true:

- The proxy cannot make direct Internet connections under its production identity.
- The proxy cannot use local or external DNS directly.
- Arti is the only component authorized for Tor-network egress.
- HTTP and HTTPS proxy flows work through external Arti.
- Session and strict isolation behavior is demonstrably preserved.
- Arti failure causes fail-closed client errors.
- IPv4 and IPv6 are covered.
- Internal listeners and metrics are not publicly reachable.
- Firewall policy survives reboot and starts before the proxy.
- Neither service runs as root or holds firewall-administration capability.
- Production activation and rollback have been tested safely.

## Primary references

- [tor-hsrproxy crate documentation](https://docs.rs/tor-hsrproxy/latest/tor_hsrproxy/)
- [Arti proxy startup guide](https://tpo.pages.torproject.net/core/arti/guides/starting-arti)
- [Tor HTTP CONNECT extensions](https://spec.torproject.org/http-connect.html)
- [Tor stream-isolation specification](https://spec.torproject.org/path-spec/stream-isolation.html)
- [Tor SOCKS extensions](https://spec.torproject.org/socks-extensions.html)
- [Arti client documentation](https://docs.rs/arti-client/latest/arti_client/)
- [Official nftables manual](https://netfilter.org/projects/nftables/manpage.html)
- [Linux network namespace manual](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
