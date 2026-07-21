# Documentation map

`src/main.rs` remains the core runtime implementation. This directory contains
the design, operational, and security material that explains how that runtime is
to be changed or deployed.

## Structure

```text
docs/
  README.md                 this navigation and structure guide
  plans/                    reviewed future-state work, not yet deployed
    ingress/                client ingress and transport security plans
    firewall/               egress containment and network-boundary plans
  architecture/             current-state diagrams and component contracts
  runbooks/                 tested, repeatable operational procedures
```

Only directories with current content are created now. Add `architecture/` or
`runbooks/` when there is a real document to place in them; do not create empty
placeholder trees.

## Current plans

- [Rustls private ingress plan](plans/ingress/rustls-private-ingress.md) — TLS,
  mTLS, proxy authentication, bounded ingress handling, and the inventory of
  handwritten subsystems versus available crates.
- [Firewall egress-hardening plan](plans/firewall/egress-hardening.md) —
  separate identities/processes, fail-closed Tor egress, network containment,
  and safe deployment verification.

## Document lifecycle

- A **plan** describes proposed work, its constraints, verification gates, and
  rollback conditions. It is not authorization to alter a production host.
- A **runbook** describes an already-reviewed and reproducible operational
  procedure. It must name the owner, exact prerequisites, verification, and
  rollback path.
- **Architecture** documents describe the implementation that exists now; they
  must be updated only after the corresponding change is verified.

When a plan changes runtime behavior, keep the high-level phase and its source
of truth linked from `src/ROADMAP.md`.
