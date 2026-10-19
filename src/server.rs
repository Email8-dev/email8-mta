// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Email8:Mta - HTTP surface + raw-TCP listeners.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::config::MtaConfig;
use crate::submit::QueueWriter;

/// Service state: the service config + the shell `ServiceCore`
/// (pool + Sentin8:Policy engine + shared admin surface - Phase 28 §3.6).
/// The engine inside `core.admin` is the SAME instance the step-5 gate
/// evaluates, so admin writes and request-time decisions agree.
/// (`ServiceCore` is not `Clone`; `Arc` gives the cheap state clone.)
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<MtaConfig>,
    pub pool: sqlx::PgPool,
    pub queue_writer: Arc<QueueWriter>,
    pub core: std::sync::Arc<sentin8::shell::ServiceCore>,
}

pub async fn build_state(core: sentin8::shell::ServiceCore) -> anyhow::Result<AppState> {
    let config = Arc::new(MtaConfig::from_env());
    let queue_writer = Arc::new(QueueWriter::new(core.pool.clone(), config.clone()));
    let core = std::sync::Arc::new(core);
    let state = AppState {
        config: config.clone(),
        pool: core.pool.clone(),
        queue_writer: queue_writer.clone(),
        core,
    };

    // Sentin8:Policy (Phase 28, §4.2b - shell-owned boot): the shell's
    // boot step 8 already booted the engine (refuse-to-start, shared deps,
    // hot-reload consumer, stat emitter). Services only consume it.

    // Queue manager loop (mta design §3.1).
    crate::queue::spawn(
        state.core.pool.clone(),
        config.clone(),
        queue_writer.clone(),
    );

    // Report window close loop (mta design §4 - DMARC/TLS-RPT).
    crate::reports::spawn(
        state.core.pool.clone(),
        config.clone(),
        queue_writer.clone(),
    );

    // Metric telemetry (design §P4.9, SDD §2.6): hourly sweeps publishing
    // frames on the shared MemBus telemetry path - the shell boot
    // initialized the emitter; a disabled emitter no-ops each pass.
    crate::telemetry::spawn_telemetry(state.core.pool.clone());

    // Raw-TCP protocol listeners - the same dedicated-task pattern as
    // exchange8-gateway's FIX listeners. Port 0 = OS-ephemeral bind (the
    // Gate owns the well-known ports; each instance publishes its actual
    // listener map to Valkey for gate discovery). An explicit env-pinned
    // port (dev direct-bind mode) is honored as-is.
    let mut bound = Vec::new();
    bound.extend(
        spawn_tcp_listener(
            config.clone(),
            queue_writer.clone(),
            state.core.pool.clone(),
            state.core.admin.policy.clone(),
            config.submission.clone(),
            "submission",
        )
        .await?,
    );
    bound.extend(
        spawn_tcp_listener(
            config.clone(),
            queue_writer.clone(),
            state.core.pool.clone(),
            state.core.admin.policy.clone(),
            config.smtp.clone(),
            "smtp",
        )
        .await?,
    );
    bound.extend(
        spawn_tcp_listener(
            config.clone(),
            queue_writer.clone(),
            state.core.pool.clone(),
            state.core.admin.policy.clone(),
            config.smtps.clone(),
            "submissions",
        )
        .await?,
    );
    bound.extend(
        spawn_tcp_listener(
            config.clone(),
            queue_writer.clone(),
            state.core.pool.clone(),
            state.core.admin.policy.clone(),
            config.lmtp.clone(),
            "lmtp",
        )
        .await?,
    );

    // Publish the actual listener map for the gate (best-effort).
    let instance_key = format!(
        "{}:{}",
        std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_else(|_| "127.0.0.1".into()),
        std::env::var("EMAIL8_MTA_PORT").unwrap_or_else(|_| "?".into()),
    );
    email8::gate::contracts::listener_registry::publish(
        &config.valkey_url,
        "email8:mta",
        "email8-mta",
        &instance_key,
        &bound,
    )
    .await;
    // Un-publish the map on SIGTERM/Ctrl-C so the gate stops advertising
    // this instance's ports the moment it drains (gate design §3.3).
    email8::gate::contracts::listener_registry::spawn_unpublish_on_shutdown(
        config.valkey_url.clone(),
        "email8:mta",
        "email8-mta",
        instance_key,
    );

    Ok(state)
}

/// Bind one raw-TCP protocol listener and serve sessions on it.
/// Returns the bound listener(s) for the registry publisher (empty when
/// the spec's port is 0 AND no ephemeral bind was requested - an env of
/// "0" now means OS-ephemeral, not disabled; disabling requires a
/// negative env which the parser rejects, so raw listeners are always on).
async fn spawn_tcp_listener(
    config: Arc<MtaConfig>,
    queue: Arc<QueueWriter>,
    pool: sqlx::PgPool,
    engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    spec: crate::config::TcpListenerSpec,
    proto: &'static str,
) -> anyhow::Result<Vec<email8::gate::contracts::listener_registry::BoundListener>> {
    // Bind: port 0 → OS-assigned ephemeral (the default under the gate);
    // an env-pinned port binds as-is (dev direct-bind mode).
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", spec.port)).await?;
    let bound_port = listener.local_addr()?.port();
    // STARTTLS upgrader (platform story 0.1): built from the platform
    // TLS cert resolver when provisioning succeeds; dev shells without
    // certs keep `starttls: None` (the command is answered but the
    // swap is unavailable - logged).
    let starttls = build_starttls_upgrader().await;
    let cfg = config.clone();
    let q = queue.clone();
    let pool = pool.clone();
    let engine = engine.clone();
    // Valkey rate/greylist/fail2ban handles (design §6) - one shared
    // connection manager per listener; unavailable Valkey degrades the
    // session to no limits.
    let limits = crate::valkey_limits::ValkeyLimits::connect(&cfg.valkey_url)
        .await
        .ok();
    if limits.is_none() {
        tracing::warn!(url = %cfg.valkey_url, "email8:mta: valkey unavailable - rate limits/greylisting disabled");
    }
    // Story 5.2 - per-env DNSBL zone cache shared across sessions.
    let dnsbl_zones = crate::dnsbl_config::DnsblZoneCache::new(pool.clone());
    tokio::spawn(async move {
        tracing::info!(
            port = bound_port,
            lmtp = spec.lmtp,
            implicit_tls = spec.implicit_tls,
            "email8:mta: listener bound"
        );
        loop {
            match listener.accept().await {
                Ok((socket, peer)) => {
                    let cfg = cfg.clone();
                    let q = q.clone();
                    let pool = pool.clone();
                    let engine = engine.clone();
                    let limits = limits.clone();
                    let starttls = starttls.clone();
                    let dnsbl_zones = dnsbl_zones.clone();
                    tokio::spawn(async move {
                        let session = crate::smtp_session::Session::new(
                            Box::new(socket) as crate::smtp_session::BoxedStream,
                            cfg,
                            q,
                            pool,
                            engine,
                            None, // env resolved at AUTH; MX traffic is per-domain
                            Some(peer.ip()),
                        )
                        .with_limits(limits)
                        .with_starttls(starttls)
                        .with_dnsbl_zones(dnsbl_zones);
                        if let Err(e) = session.run().await {
                            tracing::debug!(error = %e, "email8:mta: session ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "email8:mta: accept failed");
                }
            }
        }
    });
    Ok(vec![
        email8::gate::contracts::listener_registry::BoundListener {
            proto,
            port: bound_port,
            implicit_tls: spec.implicit_tls,
        },
    ])
}

pub fn routes(router: axum::Router<AppState>) -> axum::Router<AppState> {
    router
        .route("/v1/health", get(health))
        // Internal submit (Store proxies JMAP EmailSubmission/set here).
        .route("/v1/internal/submit", post(crate::submit::submit))
        // Admin API + RFW (queue viewer, DKIM, reports).
        .route(
            "/v1/admin/{*page}",
            post(crate::admin::admin_data).get(crate::admin::get_admin_ui),
        )
        // ── Sentin8:Policy admin API (Phase 28 §3.6 - shared
        // implementation; handlers generic over this state via
        // HasPolicyAdmin).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<AppState>)
                .put(sentin8::shield::admin::put_policy_set::<AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<AppState>)
                .put(sentin8::shield::admin::put_relation::<AppState>)
                .delete(sentin8::shield::admin::delete_relation::<AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<AppState>)
                .put(sentin8::shield::admin::put_attribute::<AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<AppState>),
        )
}

/// Shared policy-admin surface accessor (Phase 28 §3.6): the boot
/// loaded the engine into `core.admin`; the shared handlers extract it
/// via `HasPolicyAdmin` so the admin surface and the request path
/// evaluate the SAME cache.
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.core.admin
    }
}

/// Build the STARTTLS upgrader from the platform TLS cert resolver
/// (platform story 0.1). Returns None in dev shells where cert
/// provisioning is unavailable - STARTTLS is then answered-but-not-
/// wrapped and the gap is logged once per listener.
async fn build_starttls_upgrader() -> Option<crate::smtp_session::StartTlsUpgrader> {
    // The platform resolver loads Acme certs from the DB cache; on
    // failure the builder degrades (dev shell, no infra).
    let tls = sentin8::tls::Sentin8Tls::builder()
        .build()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "email8:mta: platform TLS unavailable - STARTTLS unwrapped (dev mode)");
        })
        .ok()?;
    // A probe listener on an ephemeral port is the platform-approved
    // way to obtain the PQ-TLS acceptor (same SNI cert resolution as
    // the real listeners; the socket is released immediately).
    let raw = tls
        .raw_tcp_listener("127.0.0.1:0")
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "email8:mta: raw TCP TLS acceptor construction failed");
        })
        .ok()?;
    Some(crate::smtp_session::StartTlsUpgrader::new(
        std::sync::Arc::new(raw.tls_acceptor_handle()),
    ))
}

#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build)", body = serde_json::Value),
    ),
    security(),
    tag = "meta",
)]
pub async fn health() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "email8:mta",
        "version": sentin8::build_info::id(),
            "build": sentin8::build_info::build_hash(),
    }))
}
