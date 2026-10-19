-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
-- SPDX-License-Identifier: Apache-2.0

-- Email8:Mta - outbound queue, recipients, due events, DKIM keys, reports.
--
-- The queue replaces the legacy KV `e`/`q` subspaces: message rows +
-- normalized recipient rows + a due-event index scanned by the manager
-- loop. Claiming uses `FOR UPDATE SKIP LOCKED` - crash-safe,
-- multi-instance by construction (mta design §3.1).
--
-- Design: email8/design/sentin8-email8-mta-technical-design.md.

CREATE SCHEMA IF NOT EXISTS email8;

-- ── Queue: messages ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.queue_messages (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    return_path   TEXT NOT NULL,
    blob_hash     TEXT NOT NULL,                 -- Storage content-address key
    size          BIGINT NOT NULL,
    priority      INT NOT NULL DEFAULT 0,
    source_flags  INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    metadata      JSONB NOT NULL DEFAULT '{}'    -- per-rcpt DKIM2 headers, quota refs
);

-- ── Queue: recipients ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.queue_recipients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    message_id    UUID NOT NULL REFERENCES email8.queue_messages(id) ON DELETE CASCADE,
    address       TEXT NOT NULL,
    orcpt         TEXT,
    queue_name    TEXT NOT NULL DEFAULT 'remote',
    status        TEXT NOT NULL DEFAULT 'scheduled'
                    CHECK (status IN ('scheduled', 'completed', 'permanent_failure', 'temporary_failure')),
    notify_flags  SMALLINT NOT NULL DEFAULT 0,
    attempts      INT NOT NULL DEFAULT 0,
    spam_pct      REAL,
    next_attempt_at TIMESTAMPTZ,
    next_notify_at  TIMESTAMPTZ,
    last_reply    TEXT,
    dsn_sent_at   TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email8_queue_recipients_msg
    ON email8.queue_recipients (message_id);
CREATE INDEX IF NOT EXISTS email8_queue_recipients_pending
    ON email8.queue_recipients (env_id, status, next_attempt_at);

-- ── Queue: due-event index (the manager loop's scan surface) ─────────────
CREATE TABLE IF NOT EXISTS email8.queue_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    message_id    UUID NOT NULL REFERENCES email8.queue_messages(id) ON DELETE CASCADE,
    queue_name    TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('delivery', 'dsn', 'expiry')),
    due_at        TIMESTAMPTZ NOT NULL,
    claimed_at    TIMESTAMPTZ,
    claimed_by    TEXT
);
CREATE INDEX IF NOT EXISTS email8_queue_events_due
    ON email8.queue_events (env_id, due_at) WHERE claimed_at IS NULL;
CREATE INDEX IF NOT EXISTS email8_queue_events_msg
    ON email8.queue_events (message_id);

-- ── Queue quota counters (sender/rcpt/rcpt-domain; legacy 'u' subspace) ──
CREATE TABLE IF NOT EXISTS email8.queue_quota_counters (
    env_id        UUID NOT NULL,
    bucket_kind   TEXT NOT NULL,                  -- 'sender' | 'rcpt' | 'rcpt_domain'
    bucket_key    TEXT NOT NULL,                  -- lowercased address or domain
    used_bytes    BIGINT NOT NULL DEFAULT 0,
    used_count    BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (env_id, bucket_kind, bucket_key)
);

-- ── DKIM keys (rotation state machine; mta design §5) ───────────────────
CREATE TABLE IF NOT EXISTS email8.dkim_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    domain          TEXT NOT NULL,
    selector        TEXT NOT NULL,
    algorithm       TEXT NOT NULL DEFAULT 'rsa-sha256',
    stage          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (stage IN ('pending', 'active', 'retiring', 'retired')),
    secret_ref      TEXT NOT NULL,                -- sentin8-secrets:// reference - NEVER the key
    next_transition TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, domain, selector)
);

-- ── Reports: DMARC aggregates ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.reports_dmarc (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    domain          TEXT NOT NULL,
    policy_hash     TEXT NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    submitted_at    TIMESTAMPTZ,
    rows            JSONB NOT NULL DEFAULT '[]',  -- aggregate records
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, domain, policy_hash, window_end)
);

-- ── Reports: TLS-RPT aggregates ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email8.reports_tls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    domain          TEXT NOT NULL,
    policy_type     TEXT NOT NULL,                 -- 'sts' | 'tlsa'
    policy_hash     TEXT NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    submitted_at    TIMESTAMPTZ,
    rows            JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, domain, policy_type, policy_hash, window_end)
);

-- ── Reports: inbound external reports (DMARC/TLS/ARF received) ──────────
CREATE TABLE IF NOT EXISTS email8.reports_external (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    report_kind     TEXT NOT NULL,                 -- 'dmarc' | 'tls' | 'arf'
    domain          TEXT NOT NULL,
    payload         JSONB NOT NULL,
    source_address  TEXT,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── MTA policy rows (env-scoped config; admin via RFW) ───────────────────
CREATE TABLE IF NOT EXISTS email8.mta_policy (
    env_id          UUID PRIMARY KEY,
    hostname        TEXT NOT NULL DEFAULT 'mail.local',
    max_message_size  BIGINT NOT NULL DEFAULT 26214400,   -- 25 MB
    max_recipients_per_message INT NOT NULL DEFAULT 100,
    max_messages_per_session INT NOT NULL DEFAULT 10,
    require_auth    BOOLEAN NOT NULL DEFAULT FALSE,
    allow_relaying  BOOLEAN NOT NULL DEFAULT FALSE,
    dsn_name        TEXT NOT NULL DEFAULT 'MAILER-DAEMON',
    dsn_address     TEXT NOT NULL DEFAULT 'postmaster@localhost',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS email8.mta_hooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    stage           TEXT NOT NULL,                 -- connect|ehlo|mail|rcpt|data
    hook_kind       TEXT NOT NULL,                 -- 'sieve' | 'milter' | 'http'
    target          TEXT NOT NULL,                 -- script id | milter addr | hook URL
    config          JSONB NOT NULL DEFAULT '{}',
    is_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, stage, hook_kind, target)
);

-- ── Spam training samples (FTRL worker; story 5.4) ───────────────────────
CREATE TABLE IF NOT EXISTS email8.spam_training (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    account_id      UUID NOT NULL,
    email_id        UUID NOT NULL,
    label           BOOLEAN NOT NULL,              -- true = spam
    trained_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS email8_spam_training_pending
    ON email8.spam_training (env_id) WHERE trained_at IS NULL;

-- ── RLS (env-scoped: queue + reports + policy are tenant surfaces) ───────
DO $$
DECLARE
    tables CONSTANT text[] := ARRAY[
        'queue_messages', 'queue_recipients', 'queue_events',
        'queue_quota_counters', 'dkim_keys',
        'spam_training',
        'reports_dmarc', 'reports_tls', 'reports_external',
        'mta_policy', 'mta_hooks'
    ];
    t text;
BEGIN
    FOREACH t IN ARRAY tables LOOP
        BEGIN
            EXECUTE format('ALTER TABLE email8.%I ENABLE ROW LEVEL SECURITY', t);
            EXECUTE format('ALTER TABLE email8.%I FORCE ROW LEVEL SECURITY', t);
            EXECUTE format('DROP POLICY IF EXISTS %I ON email8.%I', t || '_tenant', t);
            EXECUTE format($f$
                CREATE POLICY %I ON email8.%I FOR ALL USING (
                    sentin8_context_initialized()
                    AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
                ) WITH CHECK (
                    sentin8_context_initialized()
                    AND (sentin8_bypass_rls() OR env_id = sentin8_current_env_id())
                )$f$,
                t || '_tenant', t);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'RLS skip %: %', t, SQLERRM;
        END;
    END LOOP;
END $$;

-- Per-service grants.
DO $$
BEGIN
    EXECUTE 'GRANT USAGE ON SCHEMA email8 TO email8_mta_service';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA email8 TO email8_mta_service';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA email8 TO email8_mta_service';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'mta grants skip: %', SQLERRM;
END $$;
-- ── Local outbox (OUTBOX-EMAIL8, architecture-principles §6.7) ──────────
-- NOTE: this block ALSO ships as migration v2 in registration.rs - the
-- live DB already has v1 applied; the version bump provisions the
-- outbox without recreation (greenfield versioning, no migration code).
CREATE TABLE IF NOT EXISTS email8.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email8_outbox_unrelayed
    ON email8.outbox (created_at) WHERE relayed = false;
ALTER TABLE email8.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE email8.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON email8.outbox;
CREATE POLICY outbox_select ON email8.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON email8.outbox;
CREATE POLICY outbox_insert ON email8.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON email8.outbox;
CREATE POLICY outbox_update ON email8.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION email8.notify_outbox_changed() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    -- Both shell relays (email8:mta → 'mta_outbox_changed',
    -- email8:store → 'store_outbox_changed') wake on every row.
    PERFORM pg_notify('mta_outbox_changed', '');
    PERFORM pg_notify('store_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON email8.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON email8.outbox
    FOR EACH ROW
    EXECUTE FUNCTION email8.notify_outbox_changed();

-- The relay's drain calls sentin8_outbox_unrelayed_envs() (outbox crate) -
-- a SECURITY DEFINER helper that must exist in the DB; email8's init
-- creates it over the shared table (IF NOT EXISTS from any service's
-- init keeps the pair idempotent).
CREATE OR REPLACE FUNCTION sentin8_outbox_unrelayed_envs()
RETURNS TABLE (env_id UUID)
LANGUAGE sql SECURITY DEFINER SET search_path = email8, public
AS $$
    SELECT DISTINCT env_id FROM email8.outbox
    WHERE relayed = false AND relay_attempts < 10
      AND (next_retry_at IS NULL OR next_retry_at <= now());
$$;
