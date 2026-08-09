# Documentation map

`src/main.rs` remains the core runtime implementation. This directory contains
the design, operational, and security material that explains how that runtime is
to be changed or deployed.

## Structure

```text
docs/
  README.md                 this navigation and structure guide
  audits/                   dated code-to-document reconciliation snapshots
  decisions/                reviewed architectural choices and adoption gates
  plans/                    reviewed future-state work, not yet deployed
    ingress/                client ingress and transport security plans
    firewall/               egress containment and network-boundary plans
  architecture/             current-state diagrams and component contracts
  runbooks/                 tested, repeatable operational procedures
```

Only directories with current content are created now. Add `architecture/` or
`runbooks/` when there is a real document to place in them; do not create empty
placeholder trees.

## Current audits

- [Markdown implementation and conflict audit, 2026-08-09](audits/markdown-implementation-audit-2026-08-09.md)
  — implemented behavior, remaining work, and contradictions across every
  project-authored Markdown file.

## Current decisions

- [libp2p adoption boundary](decisions/libp2p-adoption-boundary.md) — why
  libp2p is not a Tor mid-session fallback, the future multi-peer cases where
  it could be justified, and the gates required before adoption.

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
- A **decision** records a reviewed architectural boundary and the conditions
  that must be met before that boundary changes.
- An **audit** is dated evidence about a repository snapshot. It does not turn
  an unverified plan into deployed behavior.
- A **runbook** describes an already-reviewed and reproducible operational
  procedure. It must name the owner, exact prerequisites, verification, and
  rollback path.
- **Architecture** documents describe the implementation that exists now; they
  must be updated only after the corresponding change is verified.

When a plan changes runtime behavior, keep the high-level phase and its source
of truth linked from `src/ROADMAP.md`.
