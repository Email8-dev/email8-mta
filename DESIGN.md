# Email8:Mta - Detailed Design Document

## 1. Scope & Context

Email8:Mta owns: the SMTP/LMTP protocol listeners and session state
machines, the durable delivery queue (messages + per-recipient state
machine + due-event scan), quota buckets, DKIM rotation and signing,
the inbound screening pipeline (SPF/DKIM-verify/DMARC/spam tags/DNSBL/
greylist/rate-limits/hooks), outbound relay (MX/MTA-STS/DANE), report
generation (DMARC/TLS-RPT/external intake), the FTRL spam-training
worker, the mta leaf schema objects, and the `email8:smtp:*` /
`email8:spam:*` event production.

It does NOT own: mailbox persistence (Email8:Store), blob bytes
(Sentin8:Storage), credential issuance (Sentin8:Auth), client ports
(Email8:Gate), or scheduling of long-run jobs (Sentin8:Cron drives
DKIM rotation).

```mermaid
graph TD
    subgraph clients["Internet / mail clients"]
        FOREIGN["Foreign MX hosts"]
        MUA["Mail clients (outbound)"]
    end
    subgraph email8["email8 vertical"]
        GATE["Email8:Gate (25/465/587)"]
        MTA["Email8:Mta"]
        STORE["Email8:Store"]
    end
    subgraph platform["Sentin8 platform"]
        AUTH["Sentin8:Auth"]
        POLICY["Shield (embedded)"]
        ST[("Sentin8:Storage")]
        BUS["Sentin8:Bus"]
        SYS["Sentin8:Sys"]
        STAT["Sentin8:Stat"]
        CRON["Sentin8:Cron"]
        V[("Valkey")]
        DOH["DoH resolver"]
    end
    FOREIGN -->|":25 (via Gate)"| GATE --> MTA
    MUA -->|":587/:465 (via Gate)"| GATE
    MTA -->|"bearer verify / PLAIN bridge"| AUTH
    MTA -->|"step-5 decisions"| POLICY
    MTA -->|"resolve + ingest (mTLS cert)"| STORE
    MTA -->|"blob put/get (workload cert)"| ST
    MTA -->|"rate limits, greylist, f2b"| V
    MTA -->|"TXT/MX/DNSBL/STS/TLSA lookups"| DOH
    MTA -->|"outbox → produce"| BUS
    MTA -->|"audit drain"| SYS
    MTA -->|"hourly telemetry frames"| STAT
    CRON -->|"DKIM rotation steps"| MTA
```

Trust boundary: the SMTP-facing side is hostile; every session is
rate-limited, greylisted, screened and audited. Internal edges (Store,
Storage, Bus) cross on certificate identity only.

## 2. Runtime Architecture

Boot is shell-owned (`Sentin8Shell::new("email8:mta","EMAIL8_MTA")`):
pool + Shield engine + outbox relay (8b, channel `mta_outbox_changed`)
+ audit pusher (8c, `mta-audit` workload).

```mermaid
graph TD
    subgraph shell["sentin8-shell boot"]
        POOL["capped PgPool"]
        ENG["Shield engine boot_full"]
        RELAY["outbox relay (mta.outbox)"]
        JP["journal pusher (mta-audit)"]
    end
    subgraph state["build_state (server.rs)"]
        CFG["MtaConfig"]
        LSN["4 raw-TCP listeners<br/>submission / smtp / submissions / lmtp"]
        PUB["listener advertisement<br/>(email8::gate::contracts::listener_registry)"]
        QW["QueueWriter (submit.rs)"]
        ROUTER["HTTP router (submit + admin)"]
        TLSU["STARTTLS upgrader"]
    end
    subgraph loops["spawned background loops"]
        DELIV["queue delivery loop (2s)"]
        TRAIN["FTRL training worker (5m)"]
        WINDOWS["report window closer (hourly)"]
    end
    POOL --> ROUTER
    ENG --> ROUTER
    LSN --> PUB
    QW --> ROUTER
    TLSU --> LSN
    DELIV --> POOL
    TRAIN --> POOL
    WINDOWS --> POOL
```

**Listener set** (per `server.rs`; OS-ephemeral under the Gate unless a
positive port pins dev direct-bind):

| Listener | Well-known port | Role |
|---|---|---|
| `submission` | 587 | authenticated user send-off |
| `smtp` | 25 | inbound MX reception |
| `submissions` | 465 | implicit-TLS submission |
| `lmtp` | 24 | platform-internal local delivery dialogue |

**Inbound SMTP session lifecycle (submission; reception differs only
in auth gating):**

```mermaid
sequenceDiagram
    participant C as Client (via Gate)
    participant S as MTA session
    participant V as Valkey
    participant AU as Sentin8:Auth
    participant P as Shield (step 5)
    participant ST as Storage
    participant DB as PostgreSQL
    C->>S: connect
    S->>V: f2b strike check (e8:{env}:f2b:{ip})
    S-->>C: banner (EMAIL8_MTA_HOSTNAME)
    C->>S: EHLO
    S-->>C: capabilities (incl. STARTTLS, AUTH=*)
    C->>S: AUTH XOAUTH2/OAUTHBEARER (or PLAIN if bridged)
    S->>AU: verify token
    S->>P: EvalTarget email8:submission:send
    P-->>S: ALLOW
    C->>S: MAIL FROM (sender rate limit 100/60s)
    C->>S: RCPT TO (200/60s, greylist unauth 300s)
    C->>S: DATA/BDAT chunks (<=250MiB, <=100 rcpts)
    S->>ST: put_if_absent blake3 blob (email8/blobs/{hash})
    S->>DB: BEGIN
    S->>DB: queue_messages + queue_recipients + queue_events +
    S->>DB: blob_links + mta.outbox event
    S->>DB: COMMIT
    S-->>C: 250 queued (queue id)
```

**End-of-DATA pipeline (pipeline.rs; the screening order is policy):**

```mermaid
flowchart TD
    EHLO["EHLO + MAIL + RCPT accepted"] --> SPF["SPF check<br/>(HELO identity for null senders)"]
    SPF --> DK["DKIM verify"]
    DK --> DM["DMARC evaluate"]
    DM -->|"p=reject"| REJ["protocol-level reject<br/>(audit email8_dmarc_rejected)"]
    DM --> AR["Authentication-Results +<br/>Received-SPF headers"]
    AR --> TAGS["spam tags: URL scan,<br/>zero-width/mixed-script/homograph,<br/>Message-ID shape, DNSBL zones (60s TTL cache)"]
    TAGS --> |"score ≥ reject_threshold (15)"| REJ2["5xx reject (audit email8_spam_discarded)"]
    TAGS --> |"score ≥ discard_threshold (10)"| DROP["discard"]
    TAGS --> |"score ≥ spam_threshold (5)"| TAGHDR["X-Spam-* headers stamped"]
    TAGHDR --> RECV["Received + Return-Path prepend"]
    RECV --> SIGN["DKIM sign (active key)"]
    SIGN --> ENQ["QueueWriter enqueue"]
```

**Delivery loop (queue.rs):**

```mermaid
sequenceDiagram
    participant DL as delivery loop (2s tick)
    participant DB as PostgreSQL
    participant ST as Store
    participant MX as Foreign MX
    participant Q as queue state
    DL->>DB: claim ≤16 due queue_events FOR UPDATE SKIP LOCKED
    alt queue_name = local
        DL->>ST: POST /v1/internal/ingest (spam_pct rides)
        ST-->>DL: filed
    else queue_name = remote
        DL->>MX: resolve MX (null-MX hard fail, implicit MX RFC 5321)
        DL->>MX: MTA-STS + DANE TLS dialogue (BDAT if CHUNKING)
        MX-->>DL: reply
    end
    alt success
        DL->>Q: status=completed, release quota counters
    else temporary (classify_reply)
        DL->>Q: status=temporary_failure
        DL->>Q: next_attempt_at = retry_schedule()
        Note over Q: ladder local/remote: 120,300,600,900,<br/>1800,3600,7200,86400,259200
    else permanent
        DL->>Q: status=permanent_failure
        DL->>Q: DSN queued (3464, double-bounce guard)
    end
    Note over DL: expiry pass: TTL (3d) → permanent + delay DSN
```

## 3. Data Model

Tables live in the shared `email8` schema; producer tables
(`mta.outbox`, `mta.audit_journal`) live in the service leaf schema,
which leads the service role's `search_path`.

```mermaid
erDiagram
    queue_messages ||--o{ queue_recipients : "per-recipient state"
    queue_messages ||--o{ queue_events : "due scan"
    queue_messages }o--|| blob_links : "content ref"
    queue_messages ||--o| queue_quota_counters : "released at terminal"
    dkim_keys }o--|| domains : "signs for"
    reports_dmarc }o--|| domains : "window per policy"
    reports_tls }o--|| domains : "sts/tlsa windows"
    reports_external }o--|| domains : "intake"
    mta_policy ||--|| env : "per-env"
    mta_hooks }o--|| env : "stage chain"
    spam_training }o--|| emails : "labels train"
    mta_outbox ||..|| mta_audit_journal : "producer tables (leaf schema)"
    dnsbl_zones }o--|| env : "cached 60s"
```

| Table | Key columns | Purpose |
|---|---|---|
| `email8.queue_messages` | id, env_id, return_path, blob_hash, size, priority, source_flags, expires_at, metadata JSONB | Enqueued message pointer (bytes in Storage) |
| `email8.queue_recipients` | id, message_id CASCADE, address, orcpt, queue_name CHECK('local','remote','dsn','report'), status CHECK('scheduled','completed','permanent_failure','temporary_failure'), notify_flags, attempts, spam_pct, next_attempt_at, next_notify_at, last_reply, dsn_sent_at | Per-recipient state machine (the retry contract) |
| `email8.queue_events` | id, message_id, queue_name, kind CHECK('delivery','dsn','expiry'), due_at, claimed_at, claimed_by; partial idx `(env_id,due_at) WHERE claimed_at IS NULL` | Claiming surface (SKIP LOCKED) |
| `email8.queue_quota_counters` | PK (env_id,bucket_kind,bucket_key), used_bytes, used_count | Sender/rcpt/rcpt-domain quota buckets |
| `email8.dkim_keys` | id, env_id, domain, selector, algorithm CHECK('rsa-sha256','ed25519'), stage CHECK('pending','active','retiring','retired'), secret_ref, next_transition; UNIQUE(env,domain,selector) | DKIM rotation state (secret references only) |
| `email8.reports_dmarc` | env_id, domain, policy_hash, window_start/end, rows JSONB; UNIQUE(env,domain,policy_hash,window_end) | DMARC aggregate windows |
| `email8.reports_tls` | env_id, domain, policy_type CHECK('sts','tlsa'), policy_hash, windows, rows | TLS-RPT windows |
| `email8.reports_external` | env_id, report_kind CHECK('dmarc','tls','arf'), domain, payload JSONB, source_address | Inbound report intake |
| `email8.mta_policy` | env_id PK, hostname, max_message_size (25MB), max_recipients_per_message (100), max_messages_per_session (10), require_auth, allow_relaying, dsn_name/address | Env SMTP policy |
| `email8.mta_hooks` | env_id, stage CHECK('connect','ehlo','mail','rcpt','data'), hook_kind CHECK('sieve','milter','http'), target, config, is_enabled; UNIQUE(env,stage,hook_kind,target) | Hook chain config |
| `email8.spam_training` | env_id, account_id, email_id, label BOOLEAN, trained_at; partial pending idx | FTRL worker input |
| `email8.dnsbl_zones` (owned by Store) | PK (env_id,zone), scopes, max_checks | Zone config the MTA caches 60s |
| `mta.outbox` (leaf) | id, env_id, event_type, stream_family, payload, relayed, relay_attempts, next_retry_at | Local outbox (DBX) |
| `mta.audit_journal` (leaf) | 15-column AUDJOUR contract | Audit journal (drained by 8c) |

**Recipient state machine:**

```mermaid
stateDiagram-v2
    [*] --> scheduled : enqueue
    scheduled --> completed : delivery ok (local ingest / remote 2xx)
    scheduled --> temporary_failure : classify_reply → temp
    temporary_failure --> scheduled : next_attempt_at due
    temporary_failure --> permanent_failure : retry budget exhausted / expiry TTL (3d)
    scheduled --> permanent_failure : classify_reply → permanent / null-MX
    completed --> [*]
    permanent_failure --> [*] : DSN queued (double-bounce guard)
    Note right of completed : quota counters released
```

RLS: every tenant table ENABLE+FORCE with `env_id = sentin8_current_env_id()`;
grants to `email8_mta_service` (no bypass).

## 4. API Surface

### 4.1 HTTP (server.rs routes)

| Method | Path | Gate | Purpose |
|---|---|---|---|
| GET | `/v1/health` | none | liveness |
| POST | `/v1/internal/submit` | user bearer re-verified + Shield `email8:submission:send` (env match) | JMAP submission handoff from Store: fetch blob from Storage, enqueue |
| GET/POST | `/v1/admin/{*page}` | Shield `email8:admin:queue` etc. | RFW pages `queue`(0xe8d3), `dkim`(0xe068), `reports`(0xe873), `spam`(0xe868), `hooks`(0xe8e1), `domains`(0xe80b); `target_env_id` on data |
| * | `/v1/admin/policy-sets…`, `/v1/admin/relations…`, `/v1/admin/attributes…` | platform policy admin | shared Shield admin surface |

SMTP/LMTP listeners are raw TCP (§2); the Gate fronts 25/465/587 while
24 (LMTP) is platform-internal.

**Error codes** (registered): `email8_dmarc_policy_reject` 422,
`email8_spam_score_reject` 422, `email8_greylisted` 429,
`email8_queue_full` 402, `email8_relay_denied` 403,
`email8_sender_address_rejected` 403, `email8_dkim_key_not_found` 404,
`email8_domain_not_found` 404.

### 4.2 Event catalog (DBX producer path)

```mermaid
sequenceDiagram
    participant H as handler / queue worker
    participant O as mta.outbox
    participant R as shell relay (8b)
    participant B as Sentin8:Bus
    H->>O: INSERT same-tx (idempotency = row id)
    O-->>R: NOTIFY mta_outbox_changed
    R->>O: drain WHERE relayed = false
    R->>B: POST /v1/produce (M2M sentin8:bus:produce)
    alt 2xx
        R->>O: mark relayed
    else failure
        R->>O: relay_attempts + 1 (budget, stays for replay)
    end
```

| Event | Trigger | Payload |
|---|---|---|
| `email8:smtp:message:received` | enqueue | `{queue_id, return_path, recipients[], blob_hash, size, source_flags}` |
| `email8:smtp:dsn:generated` | DSN queued | `{queue_id, dsn_queue_id, recipient, reply}` |
| `email8:smtp:message:expired` | TTL expiry | `{queue_id, recipients[]}` |
| `email8:spam:model:updated` | FTRL pass done | `{env_id, account_id, artifact_ref}` |

**Audited actions**: `email8_auth_failed`, `email8_rate_limited`,
`email8_relay_denied`, `email8_dmarc_rejected`,
`email8_spam_discarded`, `email8_admin_mutation` (+ journal drain to
Sys).

## 5. Cross-Cutting Concerns

- **Auth**: XOAuth2/OAuthBearer decode → Sentin8:Auth bearer verify →
  Shield `EvalTarget("email8:submission:send")`; PLAIN is bridged
  to the platform OAuth password grant at `{issuer}/oauth/token` and
  exists only when `EMAIL8_SASL_BRIDGE=on`.
- **Rate limiting / greylist** (`valkey_limits.rs`): fixed windows
  `e8:{env}:{kind}:{key}:{window}` per `ThrottleKind`
  (Connection/Sender/Rcpt/RcptDomain/RemoteHost/RemoteIp/Ehlo/
  AuthenticatedAs); greylist `e8:{env}:grey:{ip}:{sender}:{rcpt}` SET
  NX TTL; f2b `e8:{env}:f2b:{ip}` 3 strikes/60s → 1h ban. The `e8:*`
  key namespace is provisioned to the service ACL via the enroll
  fragment's `valkey` section.
- **Tenant/RLS**: every stamped sequence runs in ONE transaction on
  ONE connection (`sentin8_current_env_id()` transaction-local);
  `dnsbl_config.rs` and `telemetry.rs` audit inserts follow the same
  rule.
- **Certificate identity (internal plane)**: `storage_auth.rs` builds
  the mTLS Storage/Store clients presenting the `m2m-email8:mta`
  workload certificate (CERTFREE-4V; no bearer token on internal
  paths). Registered workloads: `email8:mta` (produce, mail
  read/write/receive), `email8:mta-policy` (bus consume, stat
  measure), `mta-audit` (sys audit write).
- **Idempotency**: blob `put_if_absent` is content-hash idempotent;
  queue claiming is SKIP LOCKED so exactly one worker owns a due
  event; event production reuses the outbox row id as idempotency key.
- **TLS**: STARTTLS upgrades in place with RFC 3207 state reset
  (built from `sentin8::tls`, PQ); submissions (465) implicit TLS;
  outbound uses DANE verifier (DANE-TA/DANE-EE over webpki roots) and
  MTA-STS (STSv1 parse, mode cache by `_mta-sts` id).
- **Graceful drain**: listeners unpublish on shutdown; the relay and
  training/window loops are shell-managed tasks.

## 6. Failure Modes & Recovery

```mermaid
flowchart TD
    Q["queue event claimed"] -->|"claim crash"| SKIP["SKIP LOCKED + claimed_at reset on rollback"]
    L["local delivery"] -->|"Store unreachable"| T["temporary_failure → retry ladder"]
    R["remote delivery"] -->|"conn timeout (30s)"| T
    R -->|"5xx permanent"| PERM["permanent_failure + DSN"]
    T -->|"budget exhausted / 3d TTL"| EXP["expired → delay DSN → double-bounce guard"]
    OB["blob put fails"] -->|"queue full 402"| REJ["submission refused<br/>audit trail intact"]
    RELAY["bus produce fails"] -->|"row stays unrelayed"| RET["relay retries (8b budget)"]
    RET -->|"exhausted"| STUCK["manual replay from outbox"]
    TRW["training worker error"] --> NEXT["next 5m tick re-drains batch"]
```

- Crash mid-transaction: enqueue tx (messages+recipients+events+blob
  links+outbox) is atomic - either all rows or none.
- Store outage: deliveries degrade to temporary failures on the ladder
  (retry contract holds); submission is unaffected while Storage
  answers.
- DNS outage: resolver paths (SPF/DKIM-verify/DMARC/DNSBL/MX) fail
  conservative - screening errors do not silently pass mail.
- Audit/outbox drain outage: local tables persist rows; pushers retry
  with budget; nothing is dropped.

## 7. Concurrency & Performance Model

```mermaid
graph LR
    LSN["4 listener loops"] --> SES["session tasks"]
    SES --> QW["QueueWriter (single enqueue path)"]
    QW --> DB[("email8.* + mta.outbox")]
    DB --> DL["delivery loop<br/>batch ≤16 / 2s"]
    DB --> TRAIN["FTRL worker<br/>batch ≤500 / 5m"]
    DB --> WIN["window closer<br/>hourly"]
    DL --> STO[("Storage blobs")]
    QW --> V[("Valkey limits")]
    SES --> V
```

- One session task per SMTP connection; session caps: 15-min timeout,
  250 MiB transfer, 100 recipients, 10 messages per session
  (policy-controlled).
- Delivery loop claims bounded batches (≤16) with SKIP LOCKED; the
  claiming index `(env_id, due_at) WHERE claimed_at IS NULL` keeps the
  scan O(due).
- Blob writes are content-addressed (`put_if_absent`) - dedupe turns
  duplicate content into a no-op.
- Valkey counters are fixed-window atomics (no locks on the hot path).
- Spam-tag evaluation caches DNSBL zones per env for 60s; TXT
  resolution rides DoH with token-gated access.

## 8. Invariants, Insecure-Defaults Rejected, Unsafe Rationale

- Once committed, a queued message either delivers or expires with a
  DSN within the 3-day TTL - never vanishes.
- Recipient status transitions are one-way to terminal states; quota
  counters are always released at terminal states.
- Relaying requires policy allowance per domain (`allow_relaying` or
  hosted-domain match) - unauthenticated relay is refused by default.
- DKIM key material only by secret reference; plaintext secrets never
  enter storage.
- DMARC `p=reject` and the spam reject threshold are enforced before
  any filing.
- No `unsafe` code.
- Rejected defaults: accepting DATA before authentication on
  submission, disabling greylisting globally, bypassing the hook chain
  on protocol errors, silent `let _ =` on audit/outbox writes.

## 9. Testing Strategy

```mermaid
graph TD
    U["Unit - protocol crates<br/>(smtp-proto reply/command codecs,<br/>mail-auth SPF/DKIM/DMARC,<br/>mail-queue schedules/DSN,<br/>spam tag engine)<br/>milter wire cases"] --> I["Integration - DB-backed<br/>tests/policy.rs (Shield scope-mirror<br/>semantics, M2M parity, enroll gate)<br/>tests/openapi_drift.rs (spec floor ≥19 ops)"]
    I --> E["E2E - platform flows<br/>(submission via Gate, delivery via fleet)"]
```

- The mail-auth/mail-queue/spam crates are pure-function tested with
  injected `DnsTxt` resolvers, so protocol math is covered without
  network.
- Policy suite runs the real seeded Shield sets (no-set → deny,
  forbid-beats-permit, shadow never blocks, platform-admin parity).
- Deliberately not tested here: Store filing semantics, Gate
  passthrough, TLS handshakes (platform layers).

## 10. Open Questions

- hickory DNSSEC validation upstream gap (DoH path today).
- Queue reprioritization admin action (data model supports priority).
- Additional milter extensions beyond the SMFIC v2/v6 subset in use.

---

**Design attribution:** email8:mta and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.