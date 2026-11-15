-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
-- SPDX-License-Identifier: Apache-2.0

-- ── Queue: due-event envs (the pump's env discovery - E2E-QUEUE-1) ───────
-- The queue pump (queue.rs `claim_due_batch`) runs on the service pool
-- with NO tenant context; the queue tables are FORCE-RLS'd, so a
-- context-less claim returns ZERO rows silently (no delivery ever
-- fired). The SDK outbox-relay precedent: a SECURITY DEFINER helper
-- surfaces the DISTINCT env_ids that have due (unclaimed) events - the
-- pump then claims per-env under that env's stamped context
-- transaction (identical to `sentin8_outbox_unrelayed_envs()`).
CREATE OR REPLACE FUNCTION email8.sentin8_queue_due_envs()
RETURNS TABLE (env_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = email8, public
AS $$
    SELECT DISTINCT e.env_id
      FROM email8.queue_events e
     WHERE e.due_at <= now() AND e.claimed_at IS NULL
$$;
GRANT EXECUTE ON FUNCTION email8.sentin8_queue_due_envs() TO email8_mta_service;
