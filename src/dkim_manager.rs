// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! DKIM management — active-key resolution, signing at queue time, and
//! the Cron-driven rotation state machine (design §5).
//!
//! Private keys are **secret references** (`sentin8-secrets` URI in the
//! `secret_ref` column) — never plaintext. The `LocalFileSecrets`
//! resolver reads `backend://path` URIs where path is relative to
//! `SENTIN8_SECRETS_DIR` (dev default `/etc/sentin8/secrets`); the
//! platform vault backend swaps in via the same trait.

use sentin8_secrets_sdk::secrets::{SecretError, SecretRef, SecretValue};
use sqlx::Row;

/// A `SecretResolver` over the local secrets directory.
pub struct LocalFileSecrets {
    base: std::path::PathBuf,
}

impl LocalFileSecrets {
    pub fn from_env() -> Self {
        let base = std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "/etc/sentin8/secrets".into());
        Self { base: base.into() }
    }

    pub fn with_dir(base: impl Into<std::path::PathBuf>) -> Self {
        Self { base: base.into() }
    }

    pub fn resolve(&self, uri: &str) -> Result<SecretValue, SecretError> {
        let r = SecretRef::parse(uri)?;
        let path = self.base.join(&r.path);
        let bytes = std::fs::read(&path).map_err(|e| {
            SecretError::InvalidRef(format!("read {}: {e}", path.display()))
        })?;
        Ok(SecretValue::new(bytes))
    }
}

/// One active signing configuration resolved from `dkim_keys`.
#[derive(Debug, Clone)]
pub struct ActiveSigner {
    pub key_id: i64,
    pub domain: String,
    pub selector: String,
    /// Algorithm tag for the DKIM-Signature (a=).
    pub algorithm: &'static str,
    /// The signing key material.
    pub key: email8::mail_auth::DkimKey,
}

/// Load the active signers for an env's domains. Rows join
/// `dkim_keys` (stage='active') with the domain table.
pub async fn load_active_signers(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
) -> Result<Vec<ActiveSigner>, String> {
    let rows = sqlx::query(
        "SELECT k.id, d.name AS domain, k.selector, k.algorithm, k.secret_ref \
         FROM email8.dkim_keys k \
         JOIN email8.domains d ON d.id = k.domain_id \
         WHERE k.env_id = $1 AND k.stage = 'active'",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| format!("dkim key query: {e}"))?;
    let secrets = LocalFileSecrets::from_env();
    let mut out = Vec::new();
    for r in rows {
        let secret_ref: String = r.get("secret_ref");
        let algorithm: String = r.get("algorithm");
        let Ok(value) = secrets.resolve(&secret_ref) else {
            tracing::warn!(secret_ref = %secret_ref, "dkim: secret resolution failed; skipping key");
            continue;
        };
        let bytes = value.as_bytes().to_vec();
        let (algorithm, key) = match algorithm.as_str() {
            "ed25519" => ("ed25519-sha256", email8::mail_auth::DkimKey::Ed25519(bytes)),
            _ => ("rsa-sha256", email8::mail_auth::DkimKey::Rsa2048(bytes)),
        };
        out.push(ActiveSigner {
            key_id: r.get("id"),
            domain: r.get("domain"),
            selector: r.get("selector"),
            algorithm,
            key,
        });
    }
    Ok(out)
}

/// The legacy `sign_chained` header list — Received/AR first, then the
/// stable set.
pub const SIGN_HEADERS: &[&str] = &[
    "Received",
    "Authentication-Results",
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Subject",
    "Date",
    "Message-ID",
    "Content-Type",
    "MIME-Version",
];

/// Sign a raw message with every active signer for the given signing
/// domain (envelope domain by default). Returns the header blocks to
/// prepend, outermost-first.
pub fn sign_message(
    signers: &[ActiveSigner],
    signing_domain: &str,
    raw: &[u8],
) -> Vec<String> {
    let mut blocks = Vec::new();
    for signer in signers {
        if !signer.domain.eq_ignore_ascii_case(signing_domain) {
            continue;
        }
        match email8::mail_auth::dkim_sign(&signer.key, &signer.domain, &signer.selector, SIGN_HEADERS, raw) {
            Ok(header) => blocks.push(header),
            Err(e) => tracing::warn!(error = %e, domain = %signer.domain, "dkim signing failed"),
        }
    }
    blocks
}

// ── Rotation state machine (Cron-driven) ────────────────────────────────

/// Advance a key's stage. Called by the Cron worker:
/// - pending → active (after the TXT record confirms published)
/// - active → retiring (after `rotate_after`)
/// - retiring → retired (after `retire_after` — unpublish DNS first)
pub async fn advance_rotation(
    pool: &sqlx::PgPool,
    key_id: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<&'static str>, String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let row: Option<(String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT stage, next_transition FROM email8.dkim_keys WHERE id = $1 FOR UPDATE",
    )
    .bind(key_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("select: {e}"))?;
    let Some((stage, next_transition)) = row else {
        return Ok(None);
    };
    let Some(due) = next_transition else {
        return Ok(None);
    };
    if now < due {
        return Ok(None);
    }
    let new_stage = match stage.as_str() {
        "pending" => "active",
        "active" => "retiring",
        "retiring" => "retired",
        _ => return Ok(None),
    };
    // The next transition window (24h steps; config rows can override).
    let next = now + chrono::Duration::seconds(86400);
    sqlx::query(
        "UPDATE email8.dkim_keys SET stage = $1, next_transition = $2, updated_at = now() \
         WHERE id = $3",
    )
    .bind(new_stage)
    .bind(next)
    .bind(key_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("update: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(Some(new_stage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrip_local_file() {
        let dir = std::env::temp_dir().join(format!("e8-secrets-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dkim")).unwrap();
        std::fs::write(dir.join("dkim/key1.pem"), b"not-a-real-key").unwrap();
        let s = LocalFileSecrets::with_dir(&dir);
        let v = s.resolve("local-file://dkim/key1.pem").unwrap();
        assert_eq!(v.as_bytes(), b"not-a-real-key");
        assert!(s.resolve("local-file://missing.pem").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}