-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
-- SPDX-License-Identifier: Apache-2.0

-- ── Local outbox (OUTBOX-EMAIL8, architecture-principles §6.7) ──────────
-- DBX migration v2: the local outbox in THIS service's schema.
--
-- Layout: each email8 service role's search_path leads with its own leaf
-- schema (`mta` for email8_mta_service), which the platform's canonical
-- `public.sentin8_outbox_unrelayed_envs()` helper probes (`{leaf}.outbox`)
-- and the shell's 8b relay drains (`FROM outbox` unqualified resolves
-- through the same search_path). The leaf schemas carry ONLY the outbox;
-- domain tables stay in the shared `email8` schema (unchanged).
--
-- The relay is spawned per shell boot with the service leaf's notify
-- channel (`mta_outbox_changed`) - the trigger below notifies it.
CREATE SCHEMA IF NOT EXISTS mta;
CREATE TABLE IF NOT EXISTS mta.outbox (
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
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mta_outbox_unrelayed
    ON mta.outbox (created_at) WHERE relayed = false;
ALTER TABLE mta.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE mta.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON mta.outbox;
CREATE POLICY outbox_select ON mta.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON mta.outbox;
CREATE POLICY outbox_insert ON mta.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON mta.outbox;
CREATE POLICY outbox_update ON mta.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION mta.notify_outbox_changed() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('mta_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON mta.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON mta.outbox
    FOR EACH ROW
    EXECUTE FUNCTION mta.notify_outbox_changed();

-- Per-service grants: the role owns its outbox schema; domain tables in
-- the shared email8 schema keep their existing grants.
GRANT USAGE ON SCHEMA mta TO email8_mta_service;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA mta TO email8_mta_service;