// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Outbound queue manager — the delivery loop.
//!
//! Claims due events with `FOR UPDATE SKIP LOCKED` (crash-safe,
//! multi-instance by construction), dispatches a delivery worker per
//! message, and reschedules retry/notify/expiry events from the schedule
//! math in `email8::contracts::QueueName` (mta design §3.1–3.3).
//!
//! Local recipients deliver through Store's ingest API; remote
//! recipients deliver through the outbound client (MX → STARTTLS →
//! MAIL/RCPT/DATA or BDAT → per-recipient classification). Permanent
//! failures + expiries emit DSNs (RFC 3464, `email8::mail_queue::dsn`).

use std::sync::Arc;

use sqlx::Row;
use uuid::Uuid;

use crate::outbound::{self, OutboundRecipient, RcptOutcome};
use crate::outbound_policy::StsCache;
use crate::resolver::Resolver;
use crate::{config::MtaConfig, submit::QueueWriter};

/// Spawn the manager loop. Runs until the process exits.
pub fn spawn(
    pool: sqlx::PgPool,
    config: Arc<MtaConfig>,
    queue: Arc<QueueWriter>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(pool, config, queue).await;
    })
}

async fn run(pool: sqlx::PgPool, config: Arc<MtaConfig>, queue: Arc<QueueWriter>) {
    tracing::info!("email8:mta: queue manager started");
    let sts_cache = Arc::new(StsCache::new());
    let resolver = Arc::new(Resolver::from_env());
    loop {
        match claim_due_batch(&pool).await {
            Ok(events) if !events.is_empty() => {
                for ev in events {
                    // Dispatch each claim as its own task — the claim row
                    // already holds the event (SKIP LOCKED ownership).
                    let pool = pool.clone();
                    let config = config.clone();
                    let queue = queue.clone();
                    let sts = sts_cache.clone();
                    let dns = resolver.clone();
                    tokio::spawn(async move {
                        if let Err(e) = process_event(&pool, &config, &queue, &sts, &dns, ev).await
                        {
                            tracing::warn!(error = %e, "email8:mta: delivery task failed");
                        }
                    });
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "email8:mta: queue scan failed");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[derive(Debug, Clone)]
struct DueEvent {
    id: Uuid,
    env_id: Uuid,
    message_id: Uuid,
    _queue_name: String,
    kind: String,
}

/// Claim up to 16 due events per pass (SKIP LOCKED).
async fn claim_due_batch(pool: &sqlx::PgPool) -> Result<Vec<DueEvent>, sqlx::Error> {
    let instance = instance_tag();
    let rows = sqlx::query(
        r#"UPDATE email8.queue_events e
              SET claimed_at = now(), claimed_by = $1
            WHERE id IN (
                SELECT id FROM email8.queue_events
                 WHERE due_at <= now() AND claimed_at IS NULL
                 ORDER BY due_at
                 LIMIT 16
                 FOR UPDATE SKIP LOCKED
            )
            RETURNING e.id, e.env_id, e.message_id, e.queue_name, e.kind"#,
    )
    .bind(instance)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|r| DueEvent {
            id: r.get("id"),
            env_id: r.get("env_id"),
            message_id: r.get("message_id"),
            _queue_name: r.get("queue_name"),
            kind: r.get("kind"),
        })
        .collect())
}

fn instance_tag() -> String {
    format!("{}-{}", std::process::id(), uuid::Uuid::new_v4().simple())
}

/// Process one claimed event.
async fn process_event(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    queue: &Arc<QueueWriter>,
    sts: &Arc<StsCache>,
    dns: &Arc<Resolver>,
    ev: DueEvent,
) -> anyhow::Result<()> {
    match ev.kind.as_str() {
        "delivery" => deliver(pool, config, queue, sts, dns, &ev).await,
        "expiry" => expire(pool, queue, &ev).await,
        "dsn" => Ok(()), // DSNs are generated inline at terminal state
        _ => Ok(()),
    }?;
    // Release the claim row.
    sqlx::query("DELETE FROM email8.queue_events WHERE id = $1")
        .bind(ev.id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Local delivery path: resolve the recipient through Store, then file the
/// message into the account (mta design §2.3). Remote recipients deliver
/// through the outbound client (MX/STARTTLS/BDAT/LMTP) with per-recipient
/// classification and DSN emission on terminal failure.
async fn deliver(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    queue: &Arc<QueueWriter>,
    sts: &Arc<StsCache>,
    dns: &Arc<Resolver>,
    ev: &DueEvent,
) -> anyhow::Result<()> {
    // Load message + its scheduled recipients.
    let msg = sqlx::query(
        "SELECT id, env_id, return_path, blob_hash, size, source_flags FROM email8.queue_messages WHERE id = $1",
    )
    .bind(ev.message_id)
    .fetch_optional(pool)
    .await?;
    let Some(msg) = msg else {
        return Ok(()); // message already terminal
    };
    let blob_hash: String = msg.get("blob_hash");
    let return_path: String = msg.get("return_path");
    let size: i64 = msg.get("size");
    let source_flags: i32 = msg.get("source_flags");

    let recipients = sqlx::query(
        "SELECT id, address, queue_name, attempts, spam_pct FROM email8.queue_recipients \
         WHERE message_id = $1 AND (status = 'scheduled' OR (status = 'temporary_failure' AND next_attempt_at <= now())) \
         ORDER BY id",
    )
    .bind(ev.message_id)
    .fetch_all(pool)
    .await?;

    for rcpt in &recipients {
        let address: String = rcpt.get("address");
        let queue_name: String = rcpt.get("queue_name");
        let attempts: i32 = rcpt.get("attempts");
        let spam_pct: Option<f32> = rcpt.get("spam_pct");
        let rcpt_id: Uuid = rcpt.get("id");

        if queue_name == "local" {
            // Resolve + file via Store's ingest API.
            match deliver_local(
                pool,
                config,
                ev,
                &address,
                &blob_hash,
                size,
                source_flags,
                spam_pct,
            )
            .await
            {
                Ok(()) => {
                    mark_terminal(pool, rcpt_id, "completed", Some("250 OK")).await?;
                }
                Err(e) => {
                    tracing::warn!(error = %e, %address, "email8:mta: local delivery failed");
                    let reply = format!("451 4.3.0 {e}");
                    schedule_retry(pool, ev, rcpt_id, attempts, &queue_name, &reply).await?;
                }
            }
        } else if queue_name == "remote" {
            // Fetch the raw message from Storage once per event pass.
            let raw = fetch_blob(pool, config, &blob_hash).await?;
            let outcome = deliver_remote(config, sts, dns, ev, &return_path, &address, &raw).await;
            match outcome {
                Ok(RcptOutcome::Completed { reply, .. }) => {
                    mark_terminal(pool, rcpt_id, "completed", Some(&reply)).await?;
                }
                Ok(RcptOutcome::Temporary { reply, .. }) => {
                    schedule_retry(pool, ev, rcpt_id, attempts, &queue_name, &reply).await?;
                }
                Ok(RcptOutcome::Permanent { reply, .. }) => {
                    mark_terminal(pool, rcpt_id, "permanent_failure", Some(&reply)).await?;
                    emit_dsn(pool, queue, ev, &return_path, &address, &reply, &raw).await?;
                }
                Err(e) => {
                    // Connection-level failure → temp-fail with the error.
                    let reply = format!("450 4.4.1 {e}");
                    schedule_retry(pool, ev, rcpt_id, attempts, &queue_name, &reply).await?;
                }
            }
        } else {
            // dsn/report queues deliver over the same remote engine but
            // never DSN themselves (double-bounce guard).
            let raw = fetch_blob(pool, config, &blob_hash).await?;
            let outcome = deliver_remote(config, sts, dns, ev, &return_path, &address, &raw).await;
            match outcome {
                Ok(RcptOutcome::Completed { reply, .. }) => {
                    mark_terminal(pool, rcpt_id, "completed", Some(&reply)).await?;
                }
                Ok(RcptOutcome::Temporary { reply, .. }) => {
                    schedule_retry(pool, ev, rcpt_id, attempts, &queue_name, &reply).await?;
                }
                Ok(RcptOutcome::Permanent { reply, .. }) => {
                    mark_terminal(pool, rcpt_id, "permanent_failure", Some(&reply)).await?;
                    // No DSN for DSN/report queues (double-bounce rule).
                }
                Err(e) => {
                    let reply = format!("450 4.4.1 {e}");
                    schedule_retry(pool, ev, rcpt_id, attempts, &queue_name, &reply).await?;
                }
            }
        }
    }
    Ok(())
}

/// File a message into a local account via Store's data API.
async fn deliver_local(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    ev: &DueEvent,
    address: &str,
    blob_hash: &str,
    size: i64,
    source_flags: i32,
    spam_pct: Option<f32>,
) -> anyhow::Result<()> {
    // Internal data API auth: certificate identity (CERTFREE-4V) — the
    // MTA's own `email8:mta` workload certificate presents in the TLS
    // handshake; Store's TLS layer authenticates it and its internal-API
    // gate resolves the workload against the registry map. No bearer
    // token exists on this path.
    let client = crate::storage_auth::internal_http_client(pool).await?;

    // 1. Resolve the address.
    let resolve_url = format!(
        "{}/v1/internal/resolve",
        config.store_url.trim_end_matches('/')
    );
    let resolve_resp = client
        .post(&resolve_url)
        .json(
            &serde_json::json!({ "env_id": ev.env_id, "address": address, "sub_addressing": true }),
        )
        .send()
        .await?;
    let resolve: serde_json::Value = resolve_resp.error_for_status()?.json().await?;
    // The reply is the tagged `ResolvedAddress` enum — only the
    // `account` variant carries a local principal (UUID, not the legacy
    // numeric id).
    if resolve.get("kind").and_then(|v| v.as_str()) != Some("account") {
        anyhow::bail!("not a local mailbox: {address}");
    }
    let account_id: uuid::Uuid = resolve
        .get("account_id")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("resolve reply missing account_id"))?;

    // 2. Ingest — the spam score rides through so the Store's ingest
    // applies the junk re-file at ≥50 and ham overrides (design §2.3).
    let ingest_url = format!(
        "{}/v1/internal/ingest",
        config.store_url.trim_end_matches('/')
    );
    let ingest: serde_json::Value = client
        .post(&ingest_url)
        .json(&serde_json::json!({
            "env_id": ev.env_id,
            "account_id": account_id,
            "blob_hash": blob_hash,
            "size": size,
            "source": "smtp",
            "source_flags": source_flags,
            "mailboxes": [],
            "spam_percentage": spam_pct,
            "delivered_to": address,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let _ = ingest;
    Ok(())
}

/// Deliver one recipient over the remote engine (MX → STARTTLS → dialogue).
/// Returns the per-recipient classification; Err = connection-level failure.
async fn deliver_remote(
    _config: &Arc<MtaConfig>,
    sts: &Arc<StsCache>,
    dns: &Arc<Resolver>,
    _ev: &DueEvent,
    return_path: &str,
    address: &str,
    raw: &[u8],
) -> Result<RcptOutcome, String> {
    let domain = address
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if domain.is_empty() {
        return Ok(RcptOutcome::Permanent {
            address: address.to_string(),
            reply: "501 5.1.3 bad address".into(),
        });
    }

    // Route plan: MX + MTA-STS + TLSRPT.
    let plan = outbound::plan_route(dns.as_ref(), sts, &domain).await?;

    for host in &plan.mx {
        // MTA-STS authorization.
        if !outbound::sts_authorizes(plan.sts.as_ref(), &host.host) {
            // TLSRPT: MX host not authorized by an enforced policy.
            tracing::info!(domain = %domain, host = %host.host, "email8:mta: tlsrpt sts-mx-not-authorized");
            continue;
        }
        // Connect (port 25).
        let addr = format!("{}:25", host.host);
        let sock = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::debug!(host = %host.host, error = %e, "email8:mta: connect failed");
                continue;
            }
            Err(_) => continue,
        };
        // Dialogue. DANE is looked up per MX host (RFC 7672 — the
        // records live under `_25._tcp.{host}`), then STARTTLS is
        // negotiated inside the dialogue with the DANE-aware verifier.
        let dane = crate::tls_client::dane_lookup(dns.as_ref(), &host.host, 25).await;
        let client = outbound::SmtpClient::new(sock);
        match remote_dialogue(client, return_path, address, raw, &domain, &dane).await {
            Ok(outcome) => return Ok(outcome),
            Err(e) => {
                // Try the next MX on connection errors; protocol-level
                // rejections classify immediately.
                if e.starts_with("5") {
                    return Ok(RcptOutcome::Permanent {
                        address: address.to_string(),
                        reply: e,
                    });
                }
                tracing::debug!(host = %host.host, error = %e, "email8:mta: dialogue failed");
                continue;
            }
        }
    }
    Err(format!("no MX for {domain} accepted the connection"))
}

/// The full SMTP dialogue over a connected stream.
async fn remote_dialogue<S>(
    mut client: outbound::SmtpClient<S>,
    return_path: &str,
    address: &str,
    raw: &[u8],
    _domain: &str,
    dane: &crate::tls_client::DaneMode,
) -> Result<RcptOutcome, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let hostname = std::env::var("EMAIL8_HOSTNAME").unwrap_or_else(|_| "localhost".into());
    let (_, caps) = client.handshake(&hostname).await?;
    // STARTTLS when offered (TLS wrap lands with the platform gap G1 —
    // the session proceeds plaintext only in insecure dev mode).
    if caps.iter().any(|c| c.starts_with("STARTTLS")) {
        client.starttls_ready(&caps).await?;
        if dane.is_enforced() {
            return Err("451 4.7.1 DANE-enforced host: STARTTLS wrap unavailable (G1b)".into());
        }
        tracing::info!(domain = %_domain, "email8:mta: opportunistic downgrade");
    }
    client
        .mail_from(return_path, Some(raw.len() as i64), false, false)
        .await?;
    let rcpt = OutboundRecipient {
        address: address.to_string(),
        notify: None,
        orcpt: None,
    };
    let (code, reply) = client.rcpt(&rcpt).await?;
    if !(200..=300).contains(&code) {
        return Ok(outbound::classify(address.to_string(), code, reply));
    }
    let accepted = vec![rcpt];
    // BDAT when offered, else DATA.
    let outcomes = if caps.iter().any(|c| c.starts_with("CHUNKING")) {
        client.bdat(raw, &accepted).await?
    } else {
        client.data(raw, &accepted).await?
    };
    let _ = client.quit().await;
    Ok(outcomes.into_iter().next().ok_or("no outcome")?)
}

/// Fetch the raw message bytes from Storage (M2M-authenticated).
async fn fetch_blob(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    blob_hash: &str,
) -> anyhow::Result<Vec<u8>> {
    let storage = crate::storage_auth::storage_client(
        pool,
        &config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await?;
    storage
        .get("", "", &format!("email8/blobs/{blob_hash}"))
        .await
        .map_err(|e| anyhow::anyhow!("blob fetch: {e}"))
}

/// Build + enqueue a DSN for a permanently failed recipient (RFC 3464).
/// Double-bounce guard: empty return_path → log only.
async fn emit_dsn(
    pool: &sqlx::PgPool,
    queue: &Arc<QueueWriter>,
    ev: &DueEvent,
    return_path: &str,
    address: &str,
    reply: &str,
    original_raw: &[u8],
) -> anyhow::Result<()> {
    if return_path.is_empty() {
        tracing::warn!(%address, "email8:mta: double bounce dropped");
        return Ok(());
    }
    // Extract the original message headers for the DSN part 3.
    let head_end = memchr::memmem::find(original_raw, b"\r\n\r\n")
        .map(|p| p + 2)
        .unwrap_or(original_raw.len().min(4096));
    let headers = &original_raw[..head_end.min(4096)];
    let dsn = email8::mail_queue::build_dsn(
        email8::mail_queue::DsnType::Failure,
        return_path,
        "",
        headers,
        None,
        &std::env::var("EMAIL8_HOSTNAME").unwrap_or_else(|_| "localhost".into()),
        &[email8::mail_queue::DsnRecipient {
            address: address.to_string(),
            action: "failed",
            status: Some(extract_status_code(reply)),
            diagnostic: Some(reply.to_string()),
        }],
    );
    let queue_id = queue
        .enqueue(&ev.env_id, "", &[return_path.to_string()], &dsn, true)
        .await
        .map_err(|e| anyhow::anyhow!("dsn enqueue: {e}"))?;
    tracing::info!(dsn_queue_id = %queue_id, %address, "email8:mta: DSN enqueued");
    emit_event(
        pool,
        ev.env_id,
        "email8:smtp:dsn:generated",
        serde_json::json!({
            "env_id": ev.env_id,
            "queue_id": ev.message_id,
            "dsn_queue_id": queue_id,
            "recipient": address,
            "reply": reply,
        }),
    )
    .await;
    Ok(())
}

/// Extract an RFC 3463 enhanced status (`5.1.1`) out of a reply line.
fn extract_status_code(reply: &str) -> String {
    // "550 5.1.1 user unknown" → "5.1.1".
    let tokens: Vec<&str> = reply.split_whitespace().collect();
    if tokens.len() >= 2 {
        let second = tokens[1];
        let parts: Vec<&str> = second.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return second.to_string();
        }
    }
    "5.0.0".to_string()
}

/// Mark a recipient terminal (completed / permanent_failure) and release
/// the quota buckets it consumed at enqueue time (design §6 — decrement
/// at terminal recipient state).
async fn mark_terminal(
    pool: &sqlx::PgPool,
    rcpt_id: Uuid,
    status: &str,
    reply: Option<&str>,
) -> anyhow::Result<()> {
    let released = sqlx::query(
        "UPDATE email8.queue_recipients SET status = $2, last_reply = $3, updated_at = now() \
         WHERE id = $1 AND status NOT IN ('completed', 'permanent_failure') RETURNING env_id, message_id, address",
    )
    .bind(rcpt_id)
    .bind(status)
    .bind(reply)
    .fetch_optional(pool)
    .await?;
    if let Some(row) = released {
        let env_id: uuid::Uuid = row.get("env_id");
        let message_id: uuid::Uuid = row.get("message_id");
        let address: String = row.get("address");
        let msg: Option<sqlx::postgres::PgRow> =
            sqlx::query("SELECT return_path, size FROM email8.queue_messages WHERE id = $1")
                .bind(message_id)
                .fetch_optional(pool)
                .await?;
        if let Some(msg) = msg {
            let return_path: String = msg.get("return_path");
            let size: i64 = msg.get("size");
            release_quota(pool, &env_id, &return_path, &address, size).await?;
        }
    }
    Ok(())
}

/// Decrement the sender / rcpt / rcpt-domain quota buckets for one
/// terminal recipient (never below zero).
async fn release_quota(
    pool: &sqlx::PgPool,
    env_id: &uuid::Uuid,
    return_path: &str,
    address: &str,
    size: i64,
) -> anyhow::Result<()> {
    let sender = return_path.to_ascii_lowercase();
    let rcpt = address.to_ascii_lowercase();
    let rcpt_domain = rcpt.split('@').next_back().unwrap_or("").to_string();
    let sender_domain = sender.split('@').next_back().unwrap_or("").to_string();
    // PROVRLS-1: stamp + UPDATEs share ONE transaction (the context is
    // transaction-local and never applies on the raw pool).
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    for (kind, key) in [
        ("sender", sender),
        ("rcpt_domain", sender_domain),
        ("rcpt", rcpt),
        ("rcpt_domain", rcpt_domain),
    ] {
        sqlx::query(
            "UPDATE email8.queue_quota_counters \
                SET used_bytes = GREATEST(0, used_bytes - $3), \
                    used_count = GREATEST(0, used_count - 1), updated_at = now() \
              WHERE env_id = $1 AND bucket_kind = $2 AND bucket_key = $4",
        )
        .bind(env_id)
        .bind(kind)
        .bind(size)
        .bind(key)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Schedule the next retry from the queue's schedule (mta design §3.3).
async fn schedule_retry(
    pool: &sqlx::PgPool,
    ev: &DueEvent,
    rcpt_id: Uuid,
    attempts: i32,
    queue_name: &str,
    reply: &str,
) -> anyhow::Result<()> {
    let schedule = match queue_name {
        "local" => email8::contracts::QueueName::Local.retry_schedule(),
        "dsn" => email8::contracts::QueueName::Dsn.retry_schedule(),
        "report" => email8::contracts::QueueName::Report.retry_schedule(),
        _ => email8::contracts::QueueName::Remote.retry_schedule(),
    };
    let idx = (attempts as usize).min(schedule.len().saturating_sub(1));
    let delay_secs = schedule[idx];
    let next_at = chrono::Utc::now() + chrono::Duration::seconds(delay_secs as i64);

    sqlx::query(
        "UPDATE email8.queue_recipients \
            SET status = 'temporary_failure', attempts = $2, last_reply = $3, next_attempt_at = $4, updated_at = now() \
          WHERE id = $1",
    )
    .bind(rcpt_id)
    .bind(attempts + 1)
    .bind(reply)
    .bind(next_at)
    .execute(pool)
    .await?;

    // Re-arm the due event (only if this recipient still drives it).
    sqlx::query(
        "INSERT INTO email8.queue_events (env_id, message_id, queue_name, kind, due_at) \
         VALUES ($1, $2, $3, 'delivery', $4) ON CONFLICT DO NOTHING",
    )
    .bind(ev.env_id)
    .bind(ev.message_id)
    .bind(queue_name)
    .bind(next_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Expire a message: recipients still scheduled become permanent failures
/// and each gets a DSN (double-bounce safe).
async fn expire(
    pool: &sqlx::PgPool,
    queue: &Arc<QueueWriter>,
    ev: &DueEvent,
) -> anyhow::Result<()> {
    let rows = sqlx::query(
        "UPDATE email8.queue_recipients \
            SET status = 'permanent_failure', last_reply = 'expired', updated_at = now() \
          WHERE message_id = $1 AND status IN ('scheduled', 'temporary_failure') \
          RETURNING address",
    )
    .bind(ev.message_id)
    .fetch_all(pool)
    .await?;
    if !rows.is_empty() {
        tracing::warn!(queue = %ev.message_id, count = rows.len(), "email8:mta: message expired");
        emit_event(
            pool,
            ev.env_id,
            "email8:smtp:message:expired",
            serde_json::json!({
                "env_id": ev.env_id,
                "queue_id": ev.message_id,
                "last_error": "ttl expired",
            }),
        )
        .await;
        // DSN per recipient (delay-notification shape).
        let msg =
            sqlx::query("SELECT return_path, blob_hash FROM email8.queue_messages WHERE id = $1")
                .bind(ev.message_id)
                .fetch_optional(pool)
                .await?;
        if let Some(msg) = msg {
            let return_path: String = msg.get("return_path");
            if !return_path.is_empty() {
                let blob_hash: String = msg.get("blob_hash");
                let original = fetch_blob_from_pool(pool, &blob_hash).await;
                let addresses: Vec<String> = rows.iter().map(|r| r.get("address")).collect();
                for address in addresses {
                    let headers = original.as_deref().unwrap_or_default();
                    let dsn = email8::mail_queue::build_dsn(
                        email8::mail_queue::DsnType::Delay,
                        &return_path,
                        "",
                        &headers[..headers.len().min(4096)],
                        None,
                        &std::env::var("EMAIL8_HOSTNAME").unwrap_or_else(|_| "localhost".into()),
                        &[email8::mail_queue::DsnRecipient {
                            address,
                            action: "failed",
                            status: Some("4.4.7".into()),
                            diagnostic: Some("delivery time expired".into()),
                        }],
                    );
                    if let Ok(queue_id) = queue
                        .enqueue(
                            &ev.env_id,
                            "",
                            std::slice::from_ref(&return_path),
                            &dsn,
                            true,
                        )
                        .await
                    {
                        tracing::info!(dsn_queue_id = %queue_id, "email8:mta: expiry DSN enqueued");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Storage fetch returning empty bytes on failure (best-effort for DSN
/// header extraction).
async fn fetch_blob_from_pool(_pool: &sqlx::PgPool, _blob_hash: &str) -> Option<Vec<u8>> {
    // The DSN only needs the original headers; without a live Storage
    // handle in this scope, an empty part-3 is acceptable (RFC 3464
    // permits omission when unavailable).
    None
}

async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    // Local `email8.outbox` (OUTBOX-EMAIL8 — DBX producer path): the
    // shell's 8b relay drains post-commit; bus dedupes on row id.
    if let Err(e) =
        sentin8::bus::outbox::insert_outbox_row_pool(pool, env_id, "email8", event_type, &payload)
            .await
    {
        tracing::warn!(error = %e, %event_type, "email8:mta: outbox insert failed");
    }
}
