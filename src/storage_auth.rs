// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Storage client factory (design `sentin8-email8-technical-design.md`
//! "Service-to-service" row).
//!
//! Email8 services call Sentin8:Storage for message blobs. The client is
//! **certificate-presenting** (CERTFREE-1/4V): every call presents the
//! MTA's own Acme-issued workload certificate (`CN=m2m-email8:mta`) in
//! the TLS handshake - Storage's TLS layer authenticates it and the
//! registry map authorizes the scopes. No M2M token exists on this
//! path.

use std::sync::Arc;

/// Build a certificate-presenting Storage client (the MTA's own
/// `email8:mta` workload identity). Falls back to the plain dev client
/// when the workload certificate cannot be ensured yet (Acme still
/// coming up) - the caller retries on the next boot; Storage rejects a
/// tokenless dev client loudly at its authorization gate.
///
/// # Errors
/// Returns the certificate-ensure failure for the caller to log.
pub async fn storage_client(
    _pool: &sqlx::PgPool,
    storage_url: &str,
    scopes: &[&str],
) -> anyhow::Result<sentin8_storage_sdk::client::StorageClient> {
    let _ = scopes; // the registry map carries the granted scopes (enroll)
    let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer());
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(&issuer, "email8:mta", &ca_cert_path)
            .await?;
    sentin8_storage_sdk::client::StorageClient::with_workload_identity(
        storage_url,
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    )
    .map_err(|e| anyhow::anyhow!("email8:mta: Storage mTLS transport: {e}"))
}

/// Shared handle wrapper so callers can clone cheaply.
pub type SharedStorage = Arc<sentin8_storage_sdk::client::StorageClient>;

/// A cert-presenting HTTP client for the Store's internal data API
/// (the same `email8:mta` workload identity the Storage client presents
/// - CERTFREE-4V). Store's TLS layer authenticates the handshake and its
/// internal-API gate resolves the workload against the registry map; no
/// bearer header is attached.
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure.
pub async fn internal_http_client(_pool: &sqlx::PgPool) -> anyhow::Result<reqwest::Client> {
    let issuer = std::env::var("SENTIN8_AUTH_ISSUER")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer());
    let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
    let cert =
        sentin8::auth::m2m::ensure_workload_certificate(&issuer, "email8:mta", &ca_cert_path)
            .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("email8:mta: internal mTLS transport: {e}"))
}
