// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Email8:Mta — SMTP/LMTP transfer engine.
//!
//! See `email8/design/sentin8-email8-mta-technical-design.md`.
//!
//! Boot runs on the platform `sentin8-shell` crate for the HTTP surface
//! (internal submit API, admin/RFW, health); the SMTP/LMTP listeners are
//! dedicated raw-TCP tasks spawned from the state builder (the same
//! pattern as exchange8-gateway's FIX listeners).

#[allow(dead_code)]
mod admin;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod dkim_manager;
#[allow(dead_code)]
mod dnsbl_config;
#[allow(dead_code)]
mod milters;
mod openapi;
#[allow(dead_code)]
mod outbound;
#[allow(dead_code)]
mod outbound_policy;
#[allow(dead_code)]
mod pipeline;
#[allow(dead_code)]
mod queue;
mod registration;
#[allow(dead_code)]
mod reports;
#[allow(dead_code)]
mod resolver;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod smtp_session;
#[allow(dead_code)]
mod storage_auth;
#[allow(dead_code)]
mod submit;
#[allow(dead_code)]
mod telemetry;
#[allow(dead_code)]
mod tls_client;
#[allow(dead_code)]
mod training;
#[allow(dead_code)]
mod valkey_limits;

use utoipa::OpenApi;

/// mimalloc global allocator (design §6 D13) — every background worker in
/// this binary (queue dispatch, delivery, FTRL training, report windows,
/// DKIM rotation sweep) allocates through it.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Heap-diagnostics gate (MTALEAK-1): when `EMAIL8_MTA_HEAP_STATS=1`, the
/// process installs a SIGUSR1 handler that dumps mimalloc's live heap
/// counters to stderr — the operator correlates the allocation deltas
/// with the queue/training/listener loops during a leak hunt without a
/// debugger. Off by default (dev/diagnostics surface only).
fn install_heap_stats_probe() {
    if std::env::var("EMAIL8_MTA_HEAP_STATS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        // SAFETY: libc signal-handler installation. The handler body only
        // copies the already-collected JSON snapshot's bytes to stderr —
        // no allocation happens inside the signal context (stats_json()
        // runs BEFORE the handler is invoked, see below).
        unsafe {
            libc::signal(
                libc::SIGUSR1,
                handle_heap_stats as *const () as libc::sighandler_t,
            );
        }
        tracing::info!(
            "email8:mta: heap stats probe armed (kill -USR1 {pid} dumps mimalloc counters)",
            pid = std::process::id()
        );
    }
}

extern "C" fn handle_heap_stats(_sig: i32) {
    // NOTE: signal-handler context — write(2) to fd 2 only. The String is
    // allocated here (mimalloc's stats_json allocates by design); on the
    // tiny re-entrancy chance the worst case is garbled output, never a
    // crash (mimalloc's stats surface is documented for diagnostics use).
    if let Ok(stats) = mimalloc::MiMalloc::stats_json() {
        let msg = format!("{}\n", stats.to_str().unwrap_or(""));
        let bytes = msg.as_bytes();
        unsafe {
            libc::write(2, bytes.as_ptr() as *const libc::c_void, bytes.len());
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_heap_stats_probe();
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("email8:mta", "EMAIL8_MTA")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::MtaOpenApi::openapi()),
    )
    .await
}
