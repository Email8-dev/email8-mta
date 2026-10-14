// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Mta observability — audit events (`sentin8.sys_audit_events`, the
//! platform's Sys-owned table; story 5.8) and metric frames on the shared
//! MemBus telemetry path (SDD §2.6, story 5.9).
//!
//! Audit rows follow the sys handlers' insert shape: action,
//! target_resource_type/id, actor, correlation, before/after state.
//! The Mta is machine-driven — the actor is the service identity.
//!
//! Metrics (queue depth, delivery latency, spam rates — design §P4.9)
//! publish through `sentin8::shield::stat_emit::emit_metric_event`:
//! MemBus `stat:telemetry` Pub/Sub, consumed by Stat's worker.
//! Fire-and-forget, log-only on failure — no stat client, no DCR
//! workload, no cross-service calls.

use uuid::Uuid;

/// Emit one audit row (non-blocking on the request path — failures are
/// logged, never surfaced). Actions: `email8_relay_denied`,
/// `email8_dmarc_rejected`, `email8_spam_discarded`, `email8_auth_failed`,
/// `email8_admin_mutation`.
pub async fn audit(
    pool: &sqlx::PgPool,
    env_id: &Uuid,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    details: serde_json::Value,
) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(pool)
        .await;
    let res = sqlx::query(
        r#"INSERT INTO sys_audit_events
           (env_id, actor_user_id, actor_subject_type, correlation_id,
            action, target_resource_type, target_resource_id, after_state)
           VALUES ($1, 'email8-mta', 'machine', $2, $3, $4, $5, $6)"#,
    )
    .bind(env_id)
    .bind(Uuid::new_v4().to_string())
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(details)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, action, "email8:mta: audit insert failed");
    }
}

/// The periodic telemetry sweep (queue depth, delivery latency,
/// spam-rate counters) — spawned at startup, hourly cadence. The shared
/// emitter is initialized by the shell boot; a disabled emitter makes
/// each pass a no-op.
pub fn spawn_telemetry(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = tick.tick().await;
        loop {
            if let Err(e) = telemetry_pass(&pool).await {
                tracing::warn!(error = %e, "email8:mta: telemetry pass failed");
            }
            let _ = tick.tick().await;
        }
    });
}

/// One telemetry pass over the queue tables (design §P4.9 metrics).
async fn telemetry_pass(pool: &sqlx::PgPool) -> Result<(), String> {
    use sqlx::Row;
    // Queue depth by recipient status (platform-wide; the stat service
    // is a global consumer — env tags ride the event payload).
    let rows = sqlx::query(
        "SELECT r.status, COUNT(*) AS n, AVG(EXTRACT(EPOCH FROM (now() - m.created_at))) AS age_s \
         FROM email8.queue_recipients r \
         JOIN email8.queue_messages m ON m.id = r.message_id \
         GROUP BY r.status",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    for r in rows {
        let status: String = r.get("status");
        let n: i64 = r.get::<i64, _>("n");
        let age_s: f64 = r.get::<Option<f64>, _>("age_s").unwrap_or(0.0);
        sentin8::shield::stat_emit::emit_metric_event(
            "email8:mta",
            "email8.queue.snapshot",
            serde_json::json!({
                format!("email8.queue.{status}.depth"): n,
                "email8.queue.scheduled.age_seconds": if status == "scheduled" { age_s } else { 0.0 },
            }),
            serde_json::json!({ "status": status }),
        );
    }
    // Spam outcomes over the last window (discards + rejects).
    let spam: Option<(i64, i64)> = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE is_spam_score >= 50) AS spam_n, COUNT(*) AS total \
         FROM email8.emails WHERE received_at > now() - interval '1 hour'",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;
    if let Some((spam_n, total)) = spam {
        let rate = if total > 0 {
            spam_n as f64 / total as f64
        } else {
            0.0
        };
        sentin8::shield::stat_emit::emit_metric_event(
            "email8:mta",
            "email8.spam.snapshot",
            serde_json::json!({
                "email8.spam.hourly_rate": rate,
                "email8.email.hourly_count": total,
            }),
            serde_json::json!({}),
        );
    }
    Ok(())
}
