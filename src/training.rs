// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! FTRL training worker (story 5.4) - bus-triggered spam/ham training
//! with Storage-persisted model artifacts and the hot-swap event
//! `email8:spam:model:updated` (design §P4).
//!
//! Training samples arrive as `email8:mail:spam:train` events
//! `{env_id, account_id, email_id, label}` (label true = spam) - the
//! Store emits them when a user moves mail to/from Junk. The worker:
//! 1. drains training samples per env from `spam_training`,
//! 2. builds features from the stored search corpus + subject,
//! 3. runs FTRL-Proximal steps per (account, label) - per-recipient
//!    personalization via per-account model artifacts,
//! 4. serializes the model (serde) into Storage at
//!    `email8/models/spam/{account}.json`,
//! 5. emits the hot-swap event so pipeline instances reload.

use std::sync::Arc;

use uuid::Uuid;

use email8::spam::{classify, Features, FtrlModel};

use crate::config::MtaConfig;
use crate::submit::QueueWriter;

/// Spawn the training worker loop (5-minute cadence; samples are
/// batched per account).
pub fn spawn(pool: sqlx::PgPool, config: Arc<MtaConfig>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = tick.tick().await;
        loop {
            if let Err(e) = training_pass(&pool, &config).await {
                tracing::warn!(error = %e, "email8:mta: spam training pass failed");
            }
            let _ = tick.tick().await;
        }
    });
}

/// One training pass: drain pending samples per (env, account), train,
/// persist artifacts, emit the hot-swap event.
async fn training_pass(pool: &sqlx::PgPool, config: &Arc<MtaConfig>) -> Result<(), String> {
    use sqlx::Row;
    // Pending samples grouped by account (drained via a claiming mark).
    let rows = sqlx::query(
        "UPDATE email8.spam_training \
            SET trained_at = now() \
          WHERE id IN ( \
              SELECT id FROM email8.spam_training \
               WHERE trained_at IS NULL ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED) \
          RETURNING env_id, account_id, email_id, label",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(());
    }

    // Group samples by (env, account).
    let mut by_account: std::collections::BTreeMap<(Uuid, Uuid), Vec<(Uuid, bool)>> =
        Default::default();
    for r in &rows {
        let env_id: Uuid = r.get("env_id");
        let account_id: Uuid = r.get("account_id");
        let email_id: Uuid = r.get("email_id");
        let label: bool = r.get("label");
        by_account
            .entry((env_id, account_id))
            .or_default()
            .push((email_id, label));
    }

    for ((env_id, account_id), samples) in by_account {
        if let Err(e) = train_account(pool, config, env_id, account_id, &samples).await {
            tracing::warn!(error = %e, account_id = %account_id, "email8:mta: account training failed");
        }
    }
    Ok(())
}

/// Train one account's model from its sample rows; persist + hot-swap.
async fn train_account(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    env_id: Uuid,
    account_id: Uuid,
    samples: &[(Uuid, bool)],
) -> Result<(), String> {
    use sqlx::Row;
    // PROVRLS-1: the context stamp is transaction-local - run the whole
    // training pass (stamp + sample reads + model persist) inside ONE
    // transaction so every query sees the env context.
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    // Load (or seed) the current model artifact (Storage-only fetch -
    // no DB query, so the pool is fine here; the sample reads below run
    // inside the stamped transaction).
    let mut model = load_model(pool, config, env_id, account_id).await?;

    // Fetch each sampled email's subject + search corpus and train.
    for (email_id, label) in samples {
        let row = sqlx::query(
            "SELECT subject, search_text FROM email8.emails \
             WHERE account_id = $1 AND id = $2",
        )
        .bind(account_id)
        .bind(email_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        let Some(row) = row else {
            continue; // deleted - skip
        };
        let subject: Option<String> = row.get("subject");
        let corpus: Option<String> = row.get("search_text");
        let mut f = Features { pairs: Vec::new() };
        if let Some(s) = subject {
            for word in s.split_whitespace().take(32) {
                f.add("subject", word);
            }
        }
        if let Some(c) = corpus {
            for word in c.split_whitespace().take(256) {
                f.add("body", word);
            }
        }
        model.train(&f, *label);
    }

    // Persist the artifact + emit hot-swap.
    let artifact = serde_json::to_vec(&model).map_err(|e| e.to_string())?;
    let storage = crate::storage_auth::storage_client(
        pool,
        &config.sentin8_storage_url,
        &["storage:env:write"],
    )
    .await
    .map_err(|e| format!("storage client: {e}"))?;
    let hash = blake3::hash(&artifact).to_hex().to_string();
    storage
        .put(
            "",
            "",
            &format!("email8/models/spam/{account_id}.json"),
            "application/json",
            artifact.to_vec(),
        )
        .await
        .map_err(|e| format!("model artifact store: {e}"))?;
    tx.commit().await.map_err(|e| e.to_string())?;

    // Local `email8.outbox` (OUTBOX-EMAIL8 - DBX producer path): the
    // shell's 8b relay drains post-commit; bus dedupes on row id.
    sentin8::bus::outbox::insert_outbox_row_pool(
        pool,
        env_id,
        "email8",
        "email8:spam:model:updated",
        &serde_json::json!({ "account_id": account_id, "artifact": hash }),
    )
    .await
    .map_err(|e| e.to_string())?;
    tracing::info!(account_id = %account_id, samples = samples.len(), "email8:mta: spam model updated");
    Ok(())
}

/// Load the account's model artifact from Storage (or a fresh cold
/// model when none exists yet).
async fn load_model(
    pool: &sqlx::PgPool,
    config: &Arc<MtaConfig>,
    env_id: Uuid,
    account_id: Uuid,
) -> Result<FtrlModel, String> {
    let storage = crate::storage_auth::storage_client(
        pool,
        &config.sentin8_storage_url,
        &["storage:env:read"],
    )
    .await
    .ok();
    // A cold model is the correct fallback for every miss here (no
    // artifact yet, or the workload certificate still minting - the
    // next training pass re-attempts).
    if let Some(storage) = storage {
        if let Ok(bytes) = storage
            .get("", "", &format!("email8/models/spam/{account_id}.json"))
            .await
        {
            if let Ok(m) = serde_json::from_slice::<FtrlModel>(&bytes) {
                return Ok(m);
            }
        }
    }
    let _ = pool;
    let _ = env_id;
    Ok(FtrlModel::default())
}

/// Score one message's features with the account's model (hot-reload
/// friendly: artifacts are fetched per call site in the pipeline).
pub fn score_features(model: &FtrlModel, features: &Features) -> Option<u8> {
    classify(model, features)
}

// QueueWriter is not used by the trainer today (samples drain from
// the table), but the module is wired from the same startup as the
// other workers; keep the import honest.
#[allow(unused)]
fn _qw_marker(_q: &Arc<QueueWriter>) {}
