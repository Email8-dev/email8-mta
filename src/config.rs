// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Email8:Mta configuration — listener ports, policy defaults, platform URLs.

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Raw-TCP listener spec (SMTP/LMTP).
#[derive(Debug, Clone)]
pub struct TcpListenerSpec {
    /// Port to bind (0 = disabled — dev shells often run HTTP only).
    pub port: u16,
    /// `true` = implicit TLS (SMTPS); `false` = plaintext + STARTTLS.
    pub implicit_tls: bool,
    /// Session role: SMTP or LMTP.
    pub lmtp: bool,
}

#[derive(Debug, Clone)]
pub struct MtaConfig {
    /// Assigned HTTP port (captain) for the internal/admin surface.
    pub port: u16,
    pub database_url: String,
    pub sentin8_bus_url: String,
    pub sentin8_storage_url: String,
    pub store_url: String,
    /// SMTP submission (587) — authenticated MUAs.
    pub submission: TcpListenerSpec,
    /// SMTP relay (25) — inbound MX traffic.
    pub smtp: TcpListenerSpec,
    /// SMTPS implicit-TLS relay (465).
    pub smtps: TcpListenerSpec,
    /// LMTP delivery listener (24) — platform-internal.
    pub lmtp: TcpListenerSpec,
    /// Valkey for rate limits / greylisting / fail2ban.
    pub valkey_url: String,
    /// Queue quota caps (design §6): per-sender/rcpt/rcpt-domain count and
    /// bytes; exceeded → `452 4.3.1`. Zero disables the gate.
    pub quota_max_count: i64,
    pub quota_max_bytes: i64,
    /// Stat telemetry (design §P4.9): Sentin8:Stat URL + property id.
    pub sentin8_stat_url: String,
    pub sentin8_stat_property_id: String,
    pub sentin8_auth_client: AuthClient,
}

impl MtaConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env_u16("EMAIL8_MTA_PORT", 0),
            database_url: env_string("EMAIL8_MTA_DATABASE_URL")
                .or_else(|| env_string("DATABASE_URL"))
                .unwrap_or_else(|| sentin8::config::Sentin8Config::default_database_url().to_string()),
            sentin8_bus_url: env_string("SENTIN8_BUS_URL").unwrap_or_else(|| cfg.sentin8_bus_url()),
            sentin8_storage_url: env_string("SENTIN8_STORAGE_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("storage"))),
            store_url: env_string("EMAIL8_STORE_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("email8-store"))),
            submission: TcpListenerSpec {
                // Raw listeners default to OS-EPHEMERAL (port 0): with the
                // Gate owning the well-known ports, concurrent instances
                // (rolling upgrades) must never contend for a fixed port.
                // Each instance publishes its actual listener map to the
                // Valkey registry (gate reads it). An EMAIL8_MTA_*_PORT env
                // (dev direct-bind mode) pins a port explicitly.
                port: env_u16("EMAIL8_MTA_SUBMISSION_PORT", 0),
                implicit_tls: false,
                lmtp: false,
            },
            smtp: TcpListenerSpec { port: env_u16("EMAIL8_MTA_SMTP_PORT", 0), implicit_tls: false, lmtp: false },
            smtps: TcpListenerSpec { port: env_u16("EMAIL8_MTA_SMTPS_PORT", 0), implicit_tls: true, lmtp: false },
            lmtp: TcpListenerSpec { port: env_u16("EMAIL8_MTA_LMTP_PORT", 0), implicit_tls: false, lmtp: true },
            valkey_url: env_string("VALKEY_URL")
                .or_else(|| env_string("SENTIN8_VALKEY_URL"))
                .unwrap_or_else(|| sentin8::config::Sentin8Config::default_valkey_url().to_string()),
            quota_max_count: std::env::var("EMAIL8_QUOTA_MAX_COUNT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
            quota_max_bytes: std::env::var("EMAIL8_QUOTA_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2 * 1024 * 1024 * 1024),
            sentin8_stat_url: env_string("SENTIN8_STAT_URL")
                .unwrap_or_else(|| format!("https://{}", cfg.platform_domain("stat"))),
            sentin8_stat_property_id: env_string("SENTIN8_STAT_PROPERTY_ID")
                .unwrap_or_else(|| "email8".to_string()),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env_string("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}

impl Default for MtaConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn env_u16(key: &str, default: u16) -> u16 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}