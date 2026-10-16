// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Aggregate report worker — DMARC (RFC 7489 §7.2) and TLS-RPT
//! (RFC 8460) report assembly + outbound submission.
//!
//! The pipeline records per-message evaluation outcomes into
//! `reports_dmarc` / `reports_tls` rows as they happen;
//! this worker closes the window (24h DMARC / 24h TLS by default),
//! serializes the aggregate (RFC 7489 Appendix C / RFC 8460 §4 JSON),
//! and enqueues it to the `report` queue for the report-recipient
//! address (the domain's `rua` / TLS-RPT `rua` contact).
//!
//! Design: `email8/design/sentin8-email8-mta-technical-design.md` §4.

use std::sync::Arc;

use sqlx::Row;
use uuid::Uuid;

use crate::config::MtaConfig;
use crate::submit::QueueWriter;

/// Spawn the periodic report-close loop (called once at startup).
pub fn spawn(pool: sqlx::PgPool, config: Arc<MtaConfig>, queue: Arc<QueueWriter>) {
    tokio::spawn(async move {
        // Daily window close; first pass 60s after boot, then hourly
        // sweeps (a 24h window close is idempotent via the window_end
        // uniqueness, so extra sweeps are harmless).
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = tick.tick().await; // immediate first tick
        loop {
            if let Err(e) = close_windows(&pool, &config, &queue).await {
                tracing::warn!(error = %e, "email8:mta: report window close failed");
            }
            let _ = tick.tick().await;
        }
    });
}

/// Record one DMARC evaluation outcome into the current 24h aggregate
/// window for the From domain (RFC 7489 §7.2 — the MTA aggregates each
/// inbound message into policy_domain/day rows). Called from the SMTP
/// session finalize path; failures never block acceptance.
pub async fn record_dmarc_result(
    pool: &sqlx::PgPool,
    env_id: &Uuid,
    from_domain: &str,
    spf_pass: bool,
    dkim_pass: bool,
    disposition: &str,
) {
    if from_domain.is_empty() {
        return;
    }
    // PROVRLS-1: stamp + write share ONE transaction (the context is
    // transaction-local — on the raw pool each statement lands on a
    // different connection and the stamp never applies to the INSERT).
    let Ok(mut tx) = pool.begin().await else {
        return;
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    // 24h window boundaries.
    let end = chrono::Utc::now();
    let day = end.format("%Y-%m-%d").to_string();
    let start = chrono::Utc::now() - chrono::Duration::hours(24);
    let record = serde_json::json!({
        "source_ip": "inbound",
        "count": 1,
        "spf": { "result": if spf_pass { "pass" } else { "fail" }, "domain": from_domain },
        "dkim": { "result": if dkim_pass { "pass" } else { "fail" }, "domain": from_domain },
        "disposition": disposition,
    });
    let res = sqlx::query(
        r#"INSERT INTO email8.reports_dmarc
               (env_id, domain, policy_hash, window_start, window_end, rows)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)
           ON CONFLICT (env_id, domain, policy_hash, window_end)
           DO UPDATE SET rows = reports_dmarc.rows || $6::jsonb
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(from_domain)
    .bind(&day)
    .bind(start)
    .bind(end)
    .bind(record.to_string())
    .fetch_optional(&mut *tx)
    .await;
    if let Err(e) = res {
        tracing::debug!(error = %e, "email8:mta: dmarc aggregate upsert failed");
    }
    let _ = tx.commit().await;
}

/// Detect + persist inbound external reports (design §P4.6): DMARC rua
/// (application/feedback-report with report Domain), TLS-RPT
/// (application/tlsrpt+json), and ARF ruf feedback
/// (message/feedback-report). Called from the finalize path; the raw
/// payload snapshot is stored for the admin viewer.
pub async fn record_external_report(
    pool: &sqlx::PgPool,
    env_id: &Uuid,
    raw: &[u8],
    from_address: &str,
) {
    let text = String::from_utf8_lossy(raw);
    let head_end = text.find("\r\n\r\n").map(|p| p + 4).unwrap_or(text.len());
    let head = text[..head_end].to_ascii_lowercase();
    let kind = if head.contains("application/feedback-report") {
        "dmarc"
    } else if head.contains("application/tlsrpt+json") {
        "tls"
    } else if head.contains("message/feedback-report") {
        "arf"
    } else {
        return; // not a report
    };
    let domain = from_address
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_string();
    // PROVRLS-1: stamp + write share ONE transaction.
    let Ok(mut tx) = pool.begin().await else {
        return;
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let res = sqlx::query(
        r#"INSERT INTO email8.reports_external
               (env_id, report_kind, domain, payload, source_address)
           VALUES ($1, $2, $3, $4::jsonb, $5)"#,
    )
    .bind(env_id)
    .bind(kind)
    .bind(&domain)
    .bind(serde_json::json!({ "size": raw.len(), "head": &text[..head_end.min(2048)] }).to_string())
    .bind(from_address)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
    if let Err(e) = res {
        tracing::debug!(error = %e, "email8:mta: external report insert failed");
    } else {
        tracing::info!(kind, %domain, "email8:mta: inbound external report recorded");
    }
}

/// Close any aggregate windows whose `window_end` has passed: build the
/// report payload, enqueue it to the report queue, mark submitted.
async fn close_windows(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    queue: &Arc<QueueWriter>,
) -> anyhow::Result<()> {
    // ── DMARC aggregates ──────────────────────────────────────────
    let pending = sqlx::query(
        "SELECT id, env_id, domain, policy_hash, window_start, window_end, rows \
         FROM email8.reports_dmarc \
         WHERE submitted_at IS NULL AND window_end <= now() LIMIT 50",
    )
    .fetch_all(pool)
    .await?;
    for row in &pending {
        let id: i64 = row.get("id");
        let env_id: Uuid = row.get("env_id");
        let domain: String = row.get("domain");
        let policy_hash: String = row.get("policy_hash");
        let window_start: chrono::DateTime<chrono::Utc> = row.get("window_start");
        let window_end: chrono::DateTime<chrono::Utc> = row.get("window_end");
        let rows: serde_json::Value = row.get("rows");
        // PROVRLS-1: stamp + UPDATE share ONE transaction per window.
        let Ok(mut tx) = pool.begin().await else {
            continue;
        };
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;

        // RFC 7489 Appendix C aggregate document (JSON).
        let report = serde_json::json!({
            "version": "1.0",
            "org_name": domain,
            "email": format!("postmaster@{domain}"),
            "report_id": format!("{id}"),
            "date_range": {
                "begin": window_start.timestamp(),
                "end": window_end.timestamp(),
            },
            "policy": { "domain": domain, "policy_hash": policy_hash },
            "records": rows,
        });
        // RFC 7489 Appendix C aggregate document (JSON). The report queue
        // consumer stores the payload; the envelope identifies the
        // window + policy for viewers (single-tenant local loop).
        let body = serde_json::to_vec(&report)?;
        let subject = format!("Report Domain: {domain} Submitter: {domain} Report-ID: {id}");
        let raw = format!(
            "From: postmaster@{domain}\r\nSubject: {subject}\r\n\
             To: postmaster@{domain}\r\nDate: {date}\r\n\
             MIME-Version: 1.0\r\nContent-Type: application/feedback-report; name=\"{domain}!{id}!{ts}.json\"\r\n\r\n{payload}\r\n",
            date = chrono::Utc::now().to_rfc2822(),
            ts = window_end.timestamp(),
            payload = String::from_utf8_lossy(&body),
        );

        if let Err(e) = queue
            .enqueue(
                &env_id,
                &format!("postmaster@{domain}"),
                &[format!("postmaster@{domain}")],
                raw.as_bytes(),
                true,
            )
            .await
        {
            tracing::warn!(error = %e, %domain, "email8:mta: dmarc report enqueue failed");
            continue;
        }
        let _ = config;
        sqlx::query("UPDATE email8.reports_dmarc SET submitted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let _ = tx.commit().await;
        tracing::info!(report_id = id, %domain, "email8:mta: DMARC aggregate submitted");
    }

    // ── TLS-RPT aggregates ────────────────────────────────────────
    let pending = sqlx::query(
        "SELECT id, env_id, domain, policy_type, policy_hash, window_start, window_end, rows \
         FROM email8.reports_tls \
         WHERE submitted_at IS NULL AND window_end <= now() LIMIT 50",
    )
    .fetch_all(pool)
    .await?;
    for row in &pending {
        let id: i64 = row.get("id");
        let env_id: Uuid = row.get("env_id");
        let domain: String = row.get("domain");
        let policy_type: String = row.get("policy_type");
        let policy_hash: String = row.get("policy_hash");
        let window_start: chrono::DateTime<chrono::Utc> = row.get("window_start");
        let window_end: chrono::DateTime<chrono::Utc> = row.get("window_end");
        let rows: serde_json::Value = row.get("rows");
        // PROVRLS-1: stamp + UPDATE share ONE transaction per window.
        let Ok(mut tx) = pool.begin().await else {
            continue;
        };
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;

        // RFC 8460 §4 JSON structure.
        let report = serde_json::json!({
            "organization-name": domain,
            "date-range": {
                "start-datetime": window_start.to_rfc3339(),
                "end-datetime": window_end.to_rfc3339(),
            },
            "policies": [{
                "policy-type": policy_type,
                "policy-domain": domain,
                "policy-string": [policy_hash.clone()],
                "summary": rows,
            }],
            "contact-uri": format!("mailto:postmaster@{domain}"),
        });
        let body = serde_json::to_vec(&report)?;
        let raw = format!(
            "From: postmaster@{domain}\r\nSubject: Report Domain: {domain} Report-ID: tls-{id}\r\n\
             To: postmaster@{domain}\r\nDate: {date}\r\n\
             MIME-Version: 1.0\r\nContent-Type: application/tlsrpt+json\r\n\r\n{payload}\r\n",
            date = chrono::Utc::now().to_rfc2822(),
            payload = String::from_utf8_lossy(&body),
        );
        if let Err(e) = queue
            .enqueue(
                &env_id,
                &format!("postmaster@{domain}"),
                &[format!("postmaster@{domain}")],
                raw.as_bytes(),
                true,
            )
            .await
        {
            tracing::warn!(error = %e, %domain, "email8:mta: tls report enqueue failed");
            continue;
        }
        sqlx::query("UPDATE email8.reports_tls SET submitted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let _ = tx.commit().await;
        tracing::info!(report_id = id, %domain, "email8:mta: TLS-RPT aggregate submitted");
    }
    Ok(())
}
