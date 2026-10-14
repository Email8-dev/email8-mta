// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! SMTP AUTH — the SASL/token bridge (master design §4.4).
//!
//! XOAUTH2/OAUTHBEARER present a Sentin8:Auth bearer token directly;
//! PLAIN/LOGIN forward credentials to the platform token-exchange endpoint
//! (bridge mode, config-gated). Passwords are NEVER stored or verified
//! locally — Email8 has no credential store.

use axum::http::HeaderMap;

use crate::config::MtaConfig;

/// Authenticated SMTP session identity.
#[derive(Debug, Clone)]
pub struct SmtpAuth {
    pub user_sub: String,
    pub env_id: uuid::Uuid,
    pub scopes: Vec<String>,
    pub addresses: Vec<String>,
}

/// Decode a SASL XOAUTH2/OAUTHBEARER initial response into the bearer
/// token. Returns `None` on malformed input (the session answers 501).
pub fn decode_xoauth2(initial: &str) -> Option<String> {
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, initial.as_bytes()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    // `user=...\x01auth=Bearer <token>\x01\x01` (or XOAUTH2 `auth=<token>`).
    for part in text.split('\x01') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("auth=") {
            return Some(rest.trim_start_matches("Bearer ").trim().to_string());
        }
    }
    None
}

/// Verify the bearer token against Sentin8:Auth and enforce the
/// `email8:submission:send` scope for submission sessions.
pub async fn verify_submission_token(
    config: &MtaConfig,
    engine: &sentin8::shield::PolicyEngine,
    token: &str,
) -> Result<SmtpAuth, String> {
    let headers = bearer_headers(token);
    let ctx = sentin8::auth::client::verify_bearer_token(&config.sentin8_auth_client, &headers)
        .await
        .map_err(|(_code, msg)| msg)?;
    // Step-5 policy decision (Phase 28 §4.3): submission authority is
    // Shield's call over the SASL-authenticated token — the scope-mirror
    // carries the submission/send + mail/receive permits.
    sentin8::shell::policy::require(
        engine,
        &ctx,
        &headers,
        sentin8::shield::EvalTarget::new("email8:submission:send"),
    )
    .await
    .map_err(|(_code, msg)| msg)?;
    Ok(SmtpAuth {
        user_sub: ctx.sub().to_string(),
        env_id: ctx.env_id(),
        scopes: vec!["email8:submission:send".to_string()],
        addresses: vec![],
    })
}

fn bearer_headers(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("Bearer {token}")) {
        let _ = h.insert(axum::http::header::AUTHORIZATION, v);
    }
    h
}

/// Bridge mode: forward PLAIN credentials to Sentin8:Auth's password grant
/// and receive a scoped token. Disabled unless
/// `EMAIL8_SASL_BRIDGE=on` — the platform default is OAuth-only.
pub async fn bridge_plain(
    config: &MtaConfig,
    engine: &sentin8::shield::PolicyEngine,
    username: &str,
    password: &str,
) -> Result<SmtpAuth, String> {
    if env_string("EMAIL8_SASL_BRIDGE").as_deref() != Some("on") {
        return Err("PLAIN authentication is disabled on this server".to_string());
    }
    let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer());
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{issuer}/oauth/token"))
        .form(&[
            ("grant_type", "password"),
            ("username", username),
            ("password", password),
            ("scope", "email8:submission:send"),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err("authentication failed".to_string());
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or("no access token in bridge response")?
        .to_string();
    verify_submission_token(config, engine, &token).await
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}