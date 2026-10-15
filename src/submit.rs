// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Queue writer — the single enqueue path (SMTP DATA, BDAT, and the
//! internal submit API all land here): blob → Storage, message +
//! recipients + due events → one transaction, outbox event emitted.
//!
//! Design: `email8/design/sentin8-email8-mta-technical-design.md` §3.

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, Json};
use sqlx::Row;
use uuid::Uuid;

use email8::contracts::{message_source, QueueName, SubmitRequest, SubmitResponse};
use email8::mail_core::ParsedMessage;

use crate::config::MtaConfig;

/// Shared queue writer handle (pool + storage + config).
#[derive(Clone)]
pub struct QueueWriter {
    pub pool: sqlx::PgPool,
    pub config: Arc<MtaConfig>,
}

impl QueueWriter {
    pub fn new(pool: sqlx::PgPool, config: Arc<MtaConfig>) -> Self {
        Self { pool, config }
    }

    /// Accept a raw message and persist it into the queue. Returns the
    /// queue message id (used as the SMTP response token).
    pub async fn enqueue(
        &self,
        env_id: &Uuid,
        return_path: &str,
        recipients: &[String],
        raw: &[u8],
        authenticated: bool,
    ) -> Result<Uuid, String> {
        self.enqueue_with_spam(env_id, return_path, recipients, raw, authenticated, None)
            .await
    }

    /// Enqueue with the pipeline's spam score (stored per recipient;
    /// design §2.2 — the local-delivery ingest applies junk re-file at
    /// ≥50).
    pub async fn enqueue_with_spam(
        &self,
        env_id: &Uuid,
        return_path: &str,
        recipients: &[String],
        raw: &[u8],
        authenticated: bool,
        spam_pct: Option<f32>,
    ) -> Result<Uuid, String> {
        // 0. Quota check + increment (sender / rcpt / rcpt-domain buckets;
        //    design §6 — `452 4.3.1` on exceed, decremented at terminal
        //    recipient state).
        let quota_max_count: i64 = self.config.quota_max_count;
        let quota_max_bytes: i64 = self.config.quota_max_bytes;
        let size = raw.len() as i64;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| format!("tx begin: {e}"))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let sender_key = return_path.to_ascii_lowercase();
        for (kind, key) in [
            ("sender", sender_key.clone()),
            (
                "rcpt_domain",
                sender_key.split('@').next_back().unwrap_or("").to_string(),
            ),
        ] {
            let used_row = sqlx::query(
                r#"INSERT INTO email8.queue_quota_counters
                       (env_id, bucket_kind, bucket_key, used_bytes, used_count)
                   VALUES ($1, $2, $3, $4, 1)
                   ON CONFLICT (env_id, bucket_kind, bucket_key)
                   DO UPDATE SET used_bytes = queue_quota_counters.used_bytes + $4,
                                 used_count = queue_quota_counters.used_count + 1,
                                 updated_at = now()
                   RETURNING used_bytes, used_count"#,
            )
            .bind(env_id)
            .bind(kind)
            .bind(&key)
            .bind(size)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("quota upsert: {e}"))?;
            let (used_bytes, used_count): (i64, i64) = (used_row.get(0), used_row.get(1));
            if used_count > quota_max_count || used_bytes > quota_max_bytes {
                return Err("452 4.3.1 Mail system full: quota exceeded".into());
            }
        }
        for rcpt in recipients {
            let key = rcpt.to_ascii_lowercase();
            let domain = key.split('@').next_back().unwrap_or("").to_string();
            let used_row = sqlx::query(
                r#"INSERT INTO email8.queue_quota_counters
                       (env_id, bucket_kind, bucket_key, used_bytes, used_count)
                   VALUES ($1, 'rcpt', $2, $3, 1)
                   ON CONFLICT (env_id, bucket_kind, bucket_key)
                   DO UPDATE SET used_bytes = queue_quota_counters.used_bytes + $3,
                                 used_count = queue_quota_counters.used_count + 1,
                                 updated_at = now()
                   RETURNING used_bytes, used_count"#,
            )
            .bind(env_id)
            .bind(&key)
            .bind(size)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("quota upsert: {e}"))?;
            let (used_bytes, used_count): (i64, i64) = (used_row.get(0), used_row.get(1));
            if used_count > quota_max_count || used_bytes > quota_max_bytes {
                return Err("452 4.3.1 Mail system full: quota exceeded".into());
            }
            let used_row = sqlx::query(
                r#"INSERT INTO email8.queue_quota_counters
                       (env_id, bucket_kind, bucket_key, used_bytes, used_count)
                   VALUES ($1, 'rcpt_domain', $2, $3, 1)
                   ON CONFLICT (env_id, bucket_kind, bucket_key)
                   DO UPDATE SET used_bytes = queue_quota_counters.used_bytes + $3,
                                 used_count = queue_quota_counters.used_count + 1,
                                 updated_at = now()
                   RETURNING used_bytes, used_count"#,
            )
            .bind(env_id)
            .bind(&domain)
            .bind(size)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("quota upsert: {e}"))?;
            let (used_bytes, used_count): (i64, i64) = (used_row.get(0), used_row.get(1));
            if used_count > quota_max_count || used_bytes > quota_max_bytes {
                return Err("452 4.3.1 Mail system full: quota exceeded".into());
            }
        }
        tx.commit()
            .await
            .map_err(|e| format!("quota commit: {e}"))?;

        // 1. Content-address the blob (dedup via put-if-absent).
        let blob_hash = blake3::hash(raw).to_hex().to_string();
        let storage = crate::storage_auth::storage_client(
            &self.pool,
            &self.config.sentin8_storage_url,
            &["storage:env:write"],
        )
        .await
        .map_err(|e| format!("storage client: {e}"))?;
        if let Err(e) = storage
            .put_if_absent(
                "",
                "",
                &format!("email8/blobs/{blob_hash}"),
                "application/octet-stream",
                raw.to_vec(),
            )
            .await
        {
            return Err(format!("blob store: {e}"));
        }

        // 2. Queue rows in one transaction (RLS context on same conn).
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| format!("tx begin: {e}"))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;

        // Parse headers once for thread-relevant metadata (loop guard).
        if let Ok(parsed) = ParsedMessage::parse(raw) {
            if parsed.reference_ids().len() > 50 {
                return Err("received-header loop detected".into());
            }
        }

        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(
                QueueName::Remote.expiry_ttl().unwrap_or(3 * 24 * 3600) as i64
            );
        let source_flags = if authenticated {
            message_source::AUTHENTICATED
        } else {
            message_source::UNAUTHENTICATED
        };
        let message_id: Uuid = sqlx::query_scalar(
            r#"INSERT INTO email8.queue_messages
                   (env_id, return_path, blob_hash, size, source_flags, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id"#,
        )
        .bind(env_id)
        .bind(return_path)
        .bind(&blob_hash)
        .bind(raw.len() as i64)
        .bind(source_flags as i32)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("insert message: {e}"))?;

        let now = chrono::Utc::now();
        for rcpt in recipients {
            let rcpt_lower = rcpt.to_ascii_lowercase();
            let is_local = rcpt_lower.contains("@") && !rcpt_lower.is_empty();
            let queue_name = if is_local { "local" } else { "remote" };
            let recipient_id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO email8.queue_recipients
                       (env_id, message_id, address, queue_name, status, spam_pct, next_attempt_at)
                   VALUES ($1, $2, $3, $4, 'scheduled', $6, $5)
                   RETURNING id"#,
            )
            .bind(env_id)
            .bind(message_id)
            .bind(&rcpt_lower)
            .bind(queue_name)
            .bind(now)
            .bind(spam_pct)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("insert recipient: {e}"))?;

            // Due event: delivery attempt scheduled now (first attempt).
            sqlx::query(
                "INSERT INTO email8.queue_events (env_id, message_id, queue_name, kind, due_at) \
                 VALUES ($1, $2, $3, 'delivery', $4)",
            )
            .bind(env_id)
            .bind(message_id)
            .bind(queue_name)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("insert event: {e}"))?;
            let _ = recipient_id;
        }

        // Blob link ledger row (queue reference — GC keeps blobs with
        // live queue links). owner_account_id is NULL until the message
        // is filed into an account (the linked row at ingest time owns
        // the binding).
        sqlx::query(
            "INSERT INTO email8.blob_links (env_id, owner_account_id, blob_hash, ref_kind, ref_id) \
             VALUES ($1, NULL, $2, 'queue', $3) ON CONFLICT DO NOTHING",
        )
        .bind(env_id)
        .bind(&blob_hash)
        .bind(message_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert blob link: {e}"))?;

        tx.commit().await.map_err(|e| format!("tx commit: {e}"))?;

        // 3. Outbox event: message received (inbox-first bus).
        emit_event(
            &self.pool,
            *env_id,
            "email8:smtp:message:received",
            serde_json::json!({
                "env_id": env_id,
                "queue_id": message_id,
                "return_path": return_path,
                "recipients": recipients,
                "blob_hash": blob_hash,
                "size": raw.len(),
                "source_flags": source_flags,
            }),
        )
        .await;

        Ok(message_id)
    }
}

/// `POST /v1/internal/submit` — the JMAP/Store submit path.
#[utoipa::path(
    post,
    path = "/v1/internal/submit",
    request_body = SubmitRequest,
    responses(
        (status = 200, description = "Queued", body = SubmitResponse),
        (status = 401, description = "Token verification failed"),
        (status = 403, description = "Missing email8:submission:send scope or env mismatch"),
        (status = 404, description = "Blob not found in Storage"),
    ),
    tag = "email8-mta",
)]
pub async fn submit(
    State(state): State<crate::server::AppState>,
    headers: HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (axum::http::StatusCode, String)> {
    // Re-verify the caller's scope at Mta (the Store proxy attaches the
    // user token; Mta never trusts the Store's check alone).
    let a = sentin8::shell::verify_token(&state.core.config, &headers).await?;
    // Step-5 policy decision (Phase 28 §4.3): Mta never trusts the
    // Store's check alone — submission authority is Shield's call.
    sentin8::shell::policy::require(
        &state.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("email8:submission:send"),
    )
    .await?;
    let token_env = a.env_id();
    if token_env != req.env_id && !a.is_platform_admin() {
        return Err((axum::http::StatusCode::FORBIDDEN, "env mismatch".into()));
    }

    // Fetch the raw message from Storage (certificate identity).
    let storage = crate::storage_auth::storage_client(
        &state.pool,
        &state.config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let raw = storage
        .get("", "", &format!("email8/blobs/{}", req.blob_hash))
        .await
        .map_err(|e| (axum::http::StatusCode::NOT_FOUND, e.to_string()))?;

    let queue_id = state
        .queue_writer
        .enqueue(&req.env_id, &req.return_path, &req.recipients, &raw, true)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(SubmitResponse {
        queue_id,
        next_event_at: req.hold_until.or(Some(chrono::Utc::now())),
    }))
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
