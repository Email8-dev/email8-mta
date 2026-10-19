// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Email8:Mta - SMTP/LMTP transfer engine.
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
