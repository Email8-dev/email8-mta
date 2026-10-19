# Email8:Mta - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Email8:Mta **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Email8:Mta is the **engine room of the mail vertical**: it delivers:

- **Mail that arrives and mail that leaves** - the industry-standard SMTP
  surface for inbound reception and user submission, backed by a durable
  queue that retries intelligently for days and never loses a message
  that reached the queue.
- **Reputation protection** - SPF, DKIM verification and signing, DMARC
  enforcement, DNSBL screening, greylisting, rate limits, URL and
  spoofing heuristics, and milter-style hooks stand between the hostile
  Internet and user mailboxes.
- **Self-learning spam defense** - a per-account FTRL model trains from
  the junk/user feedback each mailbox generates, so filtering sharpens
  with use instead of waiting on external threat feeds.
- **Standards-grade trust** - DMARC aggregate reports and TLS-RPT to
  other domains (so partners see the vertical plays by the rules) and
  MTA-STS/DANE handling for best-possible outbound TLS.
- **Operational control** - a rich admin surface (queue, DKIM rotation,
  reports, spam policy, hook chain, domains) rendered in the platform
  dashboard.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | SMTP submission (587/465) | Authenticated user send-off with per-sender rate limits and quotas |
| 2 | SMTP reception (25) | Inbound mail acceptance from foreign MX hosts with full authentication checks |
| 3 | SMTPS | Implicit-TLS submission variant |
| 4 | LMTP (24) | Local-recipient handoff dialogue (per-recipient status) |
| 5 | Delivery queue | Durable message + per-recipient state machine with scheduled retries (backoff schedule), expiry/DSN, quota release at terminal states |
| 6 | Local delivery | Filing into Store mailboxes with spam-score routing and thread grouping |
| 7 | Remote relay | Outbound delivery: MX resolution (RFC 7505/5321), MTA-STS, DANE TLS, BDAT when offered |
| 8 | DKIM | Key rotation lifecycle (pending→active→retiring→retired) and message signing at queue time (RSA-SHA256, ed25519) |
| 9 | SPF / DMARC | Inbound evaluation (HELO identity for null senders), DMARC policy enforcement with quarantine/reject actions |
| 10 | Spam pipeline | Tag-scoring engine (URL scans, zero-width/mixed-script/homograph heuristics, Message-ID checks, DNSBL hits), reject/discard thresholds, greylisting |
| 11 | Spam learning | Per-account FTRL training from mailbox feedback, model artifacts stored, hot-swap event on update |
| 12 | Reports | DMARC aggregate + TLS-RPT report windows (24h), inbound external report intake and classification (DMARC/TLS/ARF) |
| 13 | Hooks | Milter protocol (stage chain: connect/ehlo/mail/rcpt/data) + HTTP hook endpoints driven by `mta_hooks` config rows |
| 14 | Quotas | Sender/recipient/domain buckets (count + bytes) enforced pre-queue for both count and size |
| 15 | Abuse control | Valkey-backed fixed-window rate limits, greylist defers, fail2ban strikes/bans |
| 16 | Admin console | Six admin pages (queue, dkim, reports, spam, hooks, domains) rendered in the platform dashboard |
| 17 | Telemetry | Queue depth/age, spam rate, hourly volume frames on the platform stat property |
| 18 | Health | Service health endpoint for fleet supervision |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Mailbox storage, thread state, mailbox filing metadata | Email8:Store (MTA hands off at ingest) |
| Blob bytes itself | Sentin8:Storage (MTA writes content-addressed blobs only) |
| Mail-domain DNS records (MX/SPF/DKIM TXT) | Tenant DNS; MTA reads them via DoH |
| User identity and credential issuance | Sentin8:Auth (submission tokens verified, PLAIN bridged) |
| Authorization policy definitions | Shield (registration declares the scope-mirror set) |
| Port ownership for clients | Email8:Gate (MTA binds OS-ephemeral listeners) |
| Recurring job *timing* beyond the queue | Sentin8:Cron (drives DKIM rotation steps) |
| Event transport/durability | Sentin8:Bus (local outbox → produce API) |
| Web/UI mail surfaces | Email8:Webmail (submits via Store/MTA handoff) |

## 3. Business Capabilities

### 3.1 Accept and submit mail

| Capability | Business rule |
|---|---|
| Session hardening | PROXY v2 consumed (client IP fidelity behind the Gate); EHLO required; 15-minute session timeout; 250 MiB max message; 100 recipients cap per message |
| Submission authentication | XOAUTH2/OAUTHBEARER verified against Sentin8:Auth + Shield `email8:submission:send`; PLAIN available only where the platform SASL bridge is enabled |
| Sender rate limits | MAIL 100/60s per sender; RCPT 200/60s; unauthenticated RCPT greylisted for 300s |
| Quota buckets | Per-env count/byte buckets (default 10,000 items / 2 GiB) checked at submit; `452 4.3.1` when exceeded; released at terminal delivery |
| Relay discipline | Relaying denied unless the domain is platform-hosted or policy allows; denials audited |
| Message acceptance | DATA/BDAT chunking accepted; content-addressed (blake3) blob stored once in Sentin8:Storage, referenced by hash |
| Loop protection | Over-50 References chains rejected; Return-Path/Received stamped on ingest |

### 3.2 Screen mail

| Capability | Business rule |
|---|---|
| SPF | Evaluated on inbound (HELO identity for null senders); result stamped in Authentication-Results/Received-SPF |
| DKIM verify | Signatures verified before policy evaluation |
| DMARC | Policy evaluated; `p=reject` and quarantine outcomes enforced; failures audited |
| Spam scoring | Tag engine (URL literals, zero-width characters, mixed-script, homograph domains, Message-ID shape, DNSBL zone hits with per-env zones) builds a score; reject threshold (default 15) discards with a 5xx, discard threshold (default 10) drops, tag threshold (default 5) marks X-Spam headers |
| Greylisting | First-time triples (IP/sender/recipient) deferred 300s via Valkey; legitimate retries pass |
| Rate limits / bans | Fixed-window Valkey counters per kind (sender/rcpt/rcpt-domain/remote-host/ip/ehlo); 3 fail2ban strikes in 60s → 1h ban |
| Hook chain | Sieve/milter/HTTP hooks per stage (connect/ehlo/mail/rcpt/data) can continue, reject, discard, temp-fail, or add headers |
| Learning | Junk keyword moves insert training samples; a 5-minute FTRL worker trains per (env, account) and hot-swaps the model by event |

### 3.3 Deliver mail

| Capability | Business rule |
|---|---|
| Local delivery | Resolve recipient (sub-addressing, aliases, catch-all, groups) and file into the account mailbox; spam score rides through for re-filing |
| Remote delivery | MX/implicit-MX resolution; null-MX hard-fails; MTA-STS (none/testing/enforce) and DANE (opportunistic/enforced) govern the TLS dialogue; BDAT used when CHUNKING is offered |
| Retry schedule | Backoff ladder 2m → 5m → 10m → 15m → 30m → 1h → 2h → 1d → 3d for mail; distinct shorter ladders for DSNs and reports |
| Expiry | 3-day TTL; expiries mark permanent failure and generate per-recipient delay DSNs |
| DSNs | RFC 3464 bounce generation (failure and delay classes) with double-bounce guarding |
| Queue durability | Message metadata + recipient state machine in PostgreSQL; blobs in Storage; claiming is SKIP LOCKED so multiple workers never double-deliver |
| Priority & state | Per-recipient status transitions scheduled→completed/permanent-failure/temporary-failure; audit `email8_*` actions for auth failures, rate limiting, relay denials, DMARC rejects, spam discards |

### 3.4 Report and rotate

| Capability | Business rule |
|---|---|
| DMARC reports | 24h aggregate windows per (env, domain, policy) assembled and enqueued for delivery |
| TLS-RPT | `v=TLSRPTv1` rua lookups (STS/TLSA policy outcomes) fed into report windows |
| External reports | Inbound DMARC reports, TLS reports, and ARF feedback parsed, classified and stored |
| DKIM rotation | Cron-driven staged rotation (pending→active→retiring→retired) with per-domain selectors and secret references only |
| Admin pages | Queue contents, DKIM keys, report windows, spam policy/training, hook chain, and domains manageable from the dashboard |

## 4. Business Events (Outbound)

| Event (Bus family per envelope `stream_family`) | Fires when | Carries |
|---|---|---|
| `email8:smtp:message:received` | a message is accepted into the queue | queue_id, return_path, recipients, blob_hash, size, source_flags |
| `email8:smtp:dsn:generated` | a bounce/DSN enters the queue | queue_id, dsn_queue_id, recipient, reply |
| `email8:smtp:message:expired` | TTL expiry marks permanent failure | queue id, recipients |
| `email8:spam:model:updated` | the FTRL worker finishes a training pass | account/env, model artifact reference |

Additional lifecycle statuses (`recipient:delivered/failed/deferred`,
report outcomes, DKIM rotations) ride payload contracts declared in the
shared SDK; the four above are what the relay currently produces.

**Inbound (consumed):** none directly. The Shield hot-reload consumer
rides the dedicated `email8:mta-policy` workload; spam training is
driven by DB rows (`email8.spam_training`), not bus events.

| Channel | Content |
|---|---|
| Audit journal → Sentin8:Sys `POST /v1/audit` | `email8_auth_failed`, `email8_rate_limited`, `email8_relay_denied`, `email8_dmarc_rejected`, `email8_spam_discarded`, `email8_admin_mutation` and related actions |
| Telemetry → platform stat property `mta` | `email8.queue.{status}.depth`, `email8.queue.scheduled.age_seconds`, `email8.spam.hourly_rate`, `email8.email.hourly_count` (hourly MemBus frames) |

## 5. Business Rules & Invariants

1. **The queue is the retry contract**: once accepted (blob persisted +
   queue row committed), delivery retries per schedule for 3 days
   regardless of process crashes - acceptance is never lost.
2. **Bytes are content-addressed and single-stored**: identical
   content blobs are deduplicated in Storage; queue rows only carry
   hashes and metadata.
3. **No relay without authorization**: unauthenticated senders never
   relay; authenticated senders never exceed scope-gated submission.
4. **Spam policy is per-environment**: thresholds, greylist expiry,
   DNSBL zones, and trusted domains are config rows, not code.
5. **Recipient states never jump backwards**: scheduled → terminal
   transitions are one-way; quota counters are always released at
   terminal states.
6. **Every audit-worthy event is journalled**: auth failures, bans,
   DMARC rejects, spam discards - the audit trail is the compliance
   surface.
7. **DKIM keys live by reference**: secret references only; plaintext
   signing material never enters a table.
8. **Remote TLS is upgraded when possible**: MTA-STS enforce and DANE
   enforced modes reject downgrade paths; opportunistic TLS is the
   floor for normal traffic.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Email8:Mta |
|---|---|
| End users | Send mail from any client/webmail via submission; receive mail from any external sender |
| Email administrators | Tune per-env spam policy, quotas, rate limits, and relaying per domain; watch the queue |
| Postmasters of partner domains | Receive DMARC/TLS-RPT aggregates showing the vertical's outbound posture |
| Domain owners | Enroll their domains, rotate DKIM keys, declare report addresses |
| Security operations | Trace greylist/ban/rate-limit decisions and abuse attempts in the audit stream |
| Integration developers | Attach milter/HTTP hooks for compliance stamping or quarantine workflows |
| Platform operators | Monitor queue depth/age telemetry; replay or inspect stuck deliveries via admin pages |

## 7. KPIs / Success Criteria

| Category | Target |
|---|---|
| Deliverability | Messages queue within milliseconds of DATA completion; deliveries follow the retry ladder without loss across restarts |
| Spam defense | Reject/discard thresholds per-env tuneFP: DMARC rejects are enforced before filing; greylist+DNSBL+heuristics materially cut junk at the door |
| Reputation | DKIM signing coverage 100% for active domains; outbound TLS upgraded wherever MTA-STS/DANE allows |
| Abuse control | Rate limits and fail2ban hold under hostile senders; audits capture every enforcement |
| Queue health | Queue depth/age telemetry visible; 3-day expiry + DSN keep inbound honesty |
| Integration | Hook chain executes per stage deterministically; temp-fail semantics preserved for upstream politeness |
| Reporting | DMARC/TLS-RPT windows close hourly and queue for delivery on schedule |

## 8. Dependencies & Reliance on Other Services

| Relied on | For |
|---|---|
| Email8:Store | Recipient resolution and local filing (internal data API), domain registry, DNSBL zone config |
| Sentin8:Storage | Content-addressed message blobs, spam model artifacts, DKIM key material by reference |
| Sentin8:Auth | Submission token verification; PLAIN bridge to the platform password grant (opt-in) |
| Shield (Sentin8:Policy) | Per-request decisions; policy hot reload via the `-policy` workload |
| Email8:Gate | Well-known client ports (25/465/587; LMTP 24 is platform-internal) |
| Valkey | Rate limits, greylist, fail2ban counters (cert-identity ACL) |
| DoH resolver | TXT/MX/DNSBL/MTA-STS/TLS-RPT/DANE lookups (`EMAIL8_DOH_URL`) |
| Sentin8:Bus | Domain event production (local outbox → produce API) |
| Sentin8:Sys | Audit journal drain |
| Sentin8:Stat | Telemetry property + metric ingest |
| Sentin8:Cron | DKIM rotation step timing |

## 9. Acceptance Criteria

1. A submission with a valid token queues a message, emits
   `email8:smtp:message:received`, and releases quota counters only at
   terminal recipient states.
2. An over-quota submit receives `452 4.3.1` and no queue row.
3. Unauthenticated relaying to external domains is refused and audited.
4. A message failing DMARC reject policy is refused before filing;
   spam above threshold is rejected/dropped/tagged per environment
   config.
5. Local delivery resolves sub-addressing, aliases, catch-all and
   groups correctly and files into the right mailbox with spam-aware
   re-filing.
6. Remote delivery honors MX (null-MX hard-fail), implicit MX,
   MTA-STS, DANE, and BDAT; temporary upstream failures enter the
   backoff ladder; 3-day expiry generates the delay DSN.
7. Rotating a DKIM key stage transitions correctly with secret
   references; messages are signed with the active key (RSA-SHA256 or
   ed25519).
8. DMARC/TLS-RPT windows close and queue reports; inbound external
   reports are classified and stored.
9. Hook stages can reject/discard/temp-fail/add-headers per config
   without protocol framing errors.
10. `make build`, `make test` (policy suite incl. Shield semantics and
    enroll gate, OpenAPI drift floor), `make lint`, and the OpenAPI
    spec pass.

## 10. Open Business Questions

- External blocklist/threat-feed integration beyond DNSBL zones.
- Queue re-prioritization UX for admins (currently priority exists in
  the data model but not as a dashboard action).
- Native in-line TLSRPT/DMARC report push scheduling per-domain (today
  windows queue on the `report` lane and follow the retry ladder).

---

**Design attribution:** email8:mta and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.