# libp2p adoption boundary

**Date:** 2026-08-09

**Status:** Current decision

**Scope:** Customer-local Tor proxy and any future multi-appliance topology

## Decision

Do not add libp2p to the current proxy runtime for Tor circuit selection,
mid-session failover, or alert delivery.

The supported data path remains fail closed:

```text
client -> local proxy -> Arti -> Tor -> destination
```

If an established Tor-backed TCP stream is interrupted, the required behavior
is to close the affected tunnel, record a privacy-safe termination class, send
any user or operator alert through a separate private control channel, and
require the client to reconnect. A later connection may use another Tor
circuit, but the existing TCP/CONNECT session cannot be transferred to it.

The current runtime closes an interrupted stream and emits coarse observations.
A dedicated active-tunnel termination taxonomy and out-of-band alert delivery
are not implemented yet; they are follow-up operational work, not a reason to
introduce libp2p.

This decision assumes one locally run proxy appliance per customer. libp2p
should be reconsidered only when a verified requirement introduces multiple
independent peers that need discovery, authenticated communication, or
decentralized coordination.

## Why libp2p is not Tor failover

libp2p manages connections, substreams, protocols, and routing within a libp2p
peer network. It does not extend Arti's Tor relay selection or circuit manager.

When a Tor stream or its circuit fails, the corresponding TCP stream closes.
Neither libp2p nor another routing layer can transparently reconstruct the
application state, byte acknowledgements, or TLS state of that established
connection on a new path.

Two possible integrations both fail to provide the desired behavior:

- A direct libp2p fallback creates a non-Tor egress path, weakening the proxy's
  fail-closed anonymity boundary and potentially exposing the customer or
  destination.
- A libp2p connection carried over Tor remains subject to the same Tor stream
  interruption. It can redial, but recovery still requires an
  application-level resumable protocol.

The current implementation already applies the appropriate mechanism during
connection establishment: `Bridge::connect_with_retry` performs a bounded
retry under one total deadline and rotates session isolation where policy
permits. Once the proxy sends `200 Connection Established`, it forwards opaque
tunnel bytes and cannot inject an HTTP alert without corrupting the tunneled
protocol.

## Genuine future use cases

### Customer-owned high availability

If a customer operates two or more appliances, libp2p could support:

- LAN or configured peer discovery;
- authenticated health and readiness exchange;
- coordination that directs new sessions to a healthy appliance; and
- propagation of non-sensitive operational events.

Failover would apply only to new or explicitly resumable operations. It would
not preserve arbitrary active TCP tunnels.

### Decentralized appliance control plane

A fleet with no dependable central coordinator could use custom libp2p
request/response protocols for signed configuration notifications, health
queries, and administrative acknowledgements.

Peer identity is not authorization. Such a control plane would still require
an explicit allowlist or trust policy, message authorization, replay
protection, schema versioning, rate limits, and auditable key rotation.

### Administrative connectivity through NAT

Circuit Relay and hole punching could make a local appliance reachable for
administration when inbound connectivity is unavailable. This is suitable
only for an explicitly authorized control plane. libp2p Circuit Relay is not
an anonymity system: peers and relays are identified by Peer IDs.

A conventional outbound mTLS management connection or reverse tunnel remains
preferable when a central service is acceptable, because it is simpler to
operate and secure.

### Separate peer-to-peer application mode

libp2p could be appropriate for a distinct product that provides authenticated
peer messaging, file synchronization, cooperative jobs, or another resumable
application protocol. Tor could optionally be one transport for that protocol,
but this would be a separate threat model and product mode rather than a hidden
fallback for the proxy.

## Explicit non-use cases

Do not use libp2p to:

- choose, replace, or expose Tor relays;
- migrate or replay arbitrary TCP/CONNECT traffic;
- route protected traffic directly when Arti is unavailable;
- turn random public peers into exit gateways;
- publish account, destination, URL, isolation, circuit, or session metadata
  to a DHT or gossip topic; or
- deliver alerts from one local appliance to its local user when loopback IPC,
  a private webhook, or the existing metrics path is sufficient.

## Adoption gates

Adding libp2p requires all of the following:

1. A documented, tested multi-peer requirement that cannot be met more simply
   with local IPC or a conventional mTLS control service.
2. A strict separation between the Tor data plane and the libp2p control plane,
   including an explicit decision about whether direct transports are allowed.
3. Permissioned peer authorization in addition to cryptographic Peer IDs.
4. Bounded discovery, connection, message-size, rate, and resource policies.
5. Privacy review proving that discovery records and messages contain no
   sensitive routing or customer metadata.
6. Application-level idempotency, acknowledgement, and resumption semantics
   for anything expected to survive reconnection.
7. Tests proving that loss of Arti or the libp2p control plane never enables
   direct destination or local DNS egress.
8. Operational ownership for peer keys, revocation, upgrades, incident
   response, and compatibility between protocol versions.

Until those gates are met, the target failure behavior is:

```text
Tor-backed tunnel interrupted
  -> close the tunnel
  -> record a bounded termination class
  -> notify through a private out-of-band channel
  -> let the client establish a new CONNECT tunnel through Arti
```

## References

- [libp2p Swarm and NetworkBehaviour](https://docs.rs/libp2p/latest/libp2p/swarm/)
- [libp2p request/response protocols](https://docs.rs/libp2p/latest/libp2p/request_response/)
- [libp2p mDNS peer discovery](https://docs.rs/libp2p/latest/libp2p/mdns/)
- [libp2p Circuit Relay](https://docs.libp2p.io/concepts/circuit-relay/)
- [Tor stream-closing specification](https://spec.torproject.org/tor-spec/closing-streams.html)
- [Repository security boundaries](../../README.md#security-boundaries)
- [Firewall and fail-closed egress plan](../plans/firewall/egress-hardening.md)
