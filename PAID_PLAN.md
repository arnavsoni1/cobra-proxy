# Tor Circuit-Isolation Proxy — Business Requirements
---

## 1. Core Differentiator (do not compromise this)

Per-domain **circuit isolation** — each destination host gets its own Tor identity via `IsolationToken`, so requests to different sites can't be correlated by a shared exit identity. This is the entire value prop vs. free Tor / standard VPNs.

**Rule:** Circuit/isolation state (`token_store`, `IsolationToken` mappings) stays **ephemeral, in-memory, never written to disk**. This is a selling point (no log of which token talked to which site), not a gap to fix.

Only **account/billing metadata** needs persistence — a completely separate, low-sensitivity data store.

---

## 2. Code Changes Required

### 2.1 Local persistent storage (account/billing only)
- [x] Add **SQLite** via `rusqlite` — single owner-only file, no external service needed at this scale.
- [x] Add the account schema (expanded to include workspaces, limits, and device credentials):
  ```sql
  accounts(id, email, stripe_customer_id, plan, active, created_at)
  api_keys(id, account_id, key_hash, active, created_at, revoked_at)
  usage(account_id, period_start, bytes_used, requests_used)
  ```
- [x] Never store raw API keys — keyed BLAKE3 digests are stored and compared in constant time.
- [ ] Encrypt the SQLite file at rest via **SQLCipher**, or rely on full-disk encryption (LUKS) on the VPS.
- [ ] Add a nightly cron job to copy the encrypted DB file off-box (e.g. to Backblaze B2 or a second small VPS) — this is the actual failure point local storage introduces, not the "local vs cloud" choice itself.

### 2.2 Auth layer
- [x] Support **HTTP Basic Auth on the CONNECT request** (`Proxy-Authorization: Basic base64(key:)`) — zero-config for customers using standard proxy clients.
- [x] Add a bounded `extract_proxy_auth_api_key()` helper to parse the header.
- [x] Add `account_id: Option<AccountId>` and the redacted ingress identity to `RequestCtx`.
- [x] Enforce auth at the mTLS ingress before assigning work to `RequestCtx`:
  - Reject with `407 Proxy Authentication Required` if key missing/invalid.
  - Reject with `403` if account inactive/suspended.
- [x] Key session isolation and Pingora pooling by **(account, workspace, canonical destination, optional sub-identity)**.

### 2.3 Rate limiting
- [x] In-process GCRA limiting via the `governor` crate (sufficient under ~10–20 customers — skip Redis entirely at this scale).
- [x] Limit both requests/sec and concurrent tunnels per account.
- [x] Return `429` when exceeded.

### 2.4 Usage metering (required for billing)
- [x] Use the flush-aware bidirectional bridge copy to count bytes in both directions.
- [x] Aggregate request and directional byte usage by account/workspace/period after each Tor transport closes.
- [ ] Add a scheduled job (hourly/nightly) to push usage totals to Stripe's metered billing `UsageRecord` API.

### 2.5 Billing (Stripe)
- [ ] Stripe Checkout for signup → subscription.
- [ ] Stripe **Metered Billing** for usage-based charges.
- [ ] Webhook handler: on successful subscription → create `accounts` row + generate first API key.
- [ ] Stripe Customer Portal for self-serve plan management (minimal code needed).

### 2.6 Minimal dashboard
- [ ] Small web app (separate from the Pingora service) for: signup, view/regenerate API key, view usage vs. plan limit.
- [ ] Can be a thin wrapper around Stripe Customer Portal + a few SQLite queries.

### 2.7 Ops / hardening
- [x] Add a native Rustls TLS 1.3 production listener with required mTLS and API-key authorization; retain plaintext only for loopback development mode.
- [ ] systemd unit (or Docker + supervisor) for auto-restart of both the Pingora service and the Tor bridge.
- [ ] Alerting on `TorClient::create_bootstrapped` failures — this takes down the whole service if it fails silently.
- [ ] Document logging policy explicitly: log account/timestamp/destination-host/bytes for billing & abuse investigation; do **not** log full request paths/URLs — this is core to the privacy pitch.

---

## 3. Legal / Policy (required before charging money)

- [ ] Publish a **Terms of Service + Acceptable Use Policy** — explicitly ban CSAM, credential stuffing, DDoS, spam. (Use an existing proxy provider's ToS, e.g. Bright Data, as a structural starting point.)
- [ ] Publish a clear **data retention policy** for usage logs (relevant if taking EU customers — see GDPR checklist).
- [ ] State clearly in marketing that this is a **Tor client proxy, not an exit relay** — different legal exposure profile, avoids abuse-liability confusion with prospects.

---

## 4. Pricing

- Free tier: hard-capped (e.g. 500MB–1GB/mo, 1 concurrent circuit) — this is the marketing funnel.
- Paid tiers: $15–40/mo per customer, priced by bandwidth/circuit-count tiers (not "unlimited" — Tor bandwidth is a scarce, shared resource).
- 3–5 paying customers covers the $100/mo target.
- Pricing must be transparent on the page — no "contact sales." Developers bounce off opaque pricing.

---

## 5. Go-to-Market Plan

### Positioning
- Lead with the **mechanism**, not adjectives: "each destination domain gets an isolated Tor circuit — no shared exit identity across targets," not "military-grade anonymous scraping."
- Be upfront about tradeoffs: Tor is slower than residential proxy pools, not suited to high-throughput scraping. State this yourself — builds trust and self-selects the right (low/medium-volume, correlation-sensitive) customers.
- Moat = **operation**, not architecture. The code can be reverse-engineered or rebuilt by an AI coding agent from a technical blog post — that's fine. What's hard to replicate is uptime, warmed circuits, tuned config, and not having to own the operational burden. Compete on that, not secrecy.

### Sequence

| Phase | Action |
|---|---|
| 1 | Finish auth/metering/billing (Section 2), deploy free tier |
| 2 | Write one in-depth technical blog post explaining per-domain circuit isolation (with diagram) — this is the entire credibility asset |
| 3 | Post to r/webscraping and r/proxies (read the sub for a week first; lead with the writeup, not a pitch) |
| 4 | Show HN once there are a few real free-tier users to speak to |
| 5 | Engage in comments/questions for several weeks before any direct selling — build credibility first |
| 6+ | Direct outreach to 10–15 small scraping/data agencies, referencing the live writeup and public traction |

### Channels
- r/webscraping, r/proxies (highest signal-to-effort)
- Hacker News "Show HN"
- ProductHunt (secondary)
- Indie Hackers (build-in-public narrative)
- Scraping-adjacent Discords / dev Twitter (ongoing visibility)

### Code/repo strategy
- Open-source the core proxy on GitHub with a clear README; sell the hosted version ("or just use our hosted version, $X/mo, no setup"). Standard, trusted model in this space (cf. Plausible, Sentry, Supabase — all self-hostable, most customers still pay to not deal with it).

---

## 6. Reference Links

- SQLite appropriate use cases: https://www.sqlite.org/whentouse.html
- SQLCipher (encrypted SQLite): https://www.zetetic.net/sqlcipher/
- OWASP password/key storage cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP REST/API security cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- MDN — Proxy-Authorization header: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Proxy-Authorization
- Pingora book — request filter phases: https://github.com/cloudflare/pingora/blob/main/docs/user_guide/phase.md
- `governor` rate-limiting crate: https://docs.rs/governor/latest/governor/
- Stripe metered billing: https://docs.stripe.com/billing/subscriptions/metered
- Stripe Checkout quickstart: https://docs.stripe.com/checkout/quickstart
- Stripe Customer Portal: https://docs.stripe.com/customer-management
- Backblaze B2 pricing (backup target): https://www.backblaze.com/cloud-storage/pricing
- Bright Data Terms (ToS structural reference): https://brightdata.com/terms
- GDPR compliance checklist: https://gdpr.eu/checklist/
- Tor Project legal FAQ (relay-focused, useful context): https://community.torproject.org/relay/community-resources/eff-tor-legal-faq/
