// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Email8:Mta admin - queue viewer, DKIM keys, report status (RFW pages
//! + data endpoints). Enforces §5.1 hardening on every handler.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::policy_pages::AdminDataRows;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use uuid::Uuid;

use crate::server::AppState;

#[derive(Debug, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct AdminQuery {
    /// REQUIRED - the env being administered (§5.1 hardening).
    pub target_env_id: Option<Uuid>,
}

/// `GET /v1/admin/ui/{page}` - RFW definitions.
#[utoipa::path(
    get,
    path = "/v1/admin/{page}",
    params(("page" = String, Path, description = "RFW page name (queue, dkim, reports)")),
    responses(
        (status = 200, description = "RFW page definition", body = AdminUiResponse),
        (status = 403, description = "Policy deny"),
        (status = 404, description = "Unknown page"),
    ),
    security(("email8:admin:queue" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<AdminUiResponse>, (StatusCode, String)> {
    let a = sentin8::shell::verify_token(&state.core.config, &headers).await?;
    // Step-5 policy decision (Phase 28 §4.3): the queue action governs
    // the RFW page read - the scope-mirror carries the sibling admin
    // scopes + platform-admin permits for it.
    sentin8::shell::policy::require(
        &state.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("email8:admin:queue"),
    )
    .await?;

    let page_def = match page.as_str() {
        "queue" => queue_page(),
        "dkim" => dkim_page(),
        "reports" => reports_page(),
        "spam" => spam_page(),
        "hooks" => hooks_page(),
        "domains" => domains_page(),
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(AdminUiResponse::page(page_def)))
}

/// `POST /v1/admin/{page}` - data endpoints.
#[utoipa::path(
    post,
    path = "/v1/admin/{page}",
    params(
        ("page" = String, Path, description = "Admin page id: queue|dkim|reports"),
        ("target_env_id" = Option<Uuid>, Query, description = "REQUIRED target env"),
    ),
    responses(
        (status = 200, description = "Page data", body = AdminDataRows),
        (status = 400, description = "Missing target_env_id"),
        (status = 403, description = "Missing email8 admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    tag = "email8-mta",
)]
pub async fn admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<AdminQuery>,
) -> Result<Json<AdminDataRows>, (StatusCode, String)> {
    let env_id = q
        .target_env_id
        .ok_or((StatusCode::BAD_REQUEST, "missing target_env_id".into()))?;
    let a = sentin8::shell::verify_token(&state.core.config, &headers).await?;
    // Step-5 policy decision (Phase 28 §4.3) - queue governs.
    sentin8::shell::policy::require(
        &state.core.admin.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("email8:admin:queue"),
    )
    .await?;

    // PROVRLS-1: stamp + queries share ONE transaction (the context is
    // transaction-local and evaporates on autocommit).
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    let result = match page.as_str() {
        "queue" => {
            use sqlx::Row;
            let rows = sqlx::query(
                "SELECT m.id, m.return_path, m.size, m.created_at, \
                        COUNT(*) FILTER (WHERE r.status = 'scheduled') AS pending, \
                        COUNT(*) FILTER (WHERE r.status = 'completed') AS done, \
                        COUNT(*) FILTER (WHERE r.status = 'permanent_failure') AS failed, \
                        COUNT(*) FILTER (WHERE r.status = 'temporary_failure') AS deferred \
                 FROM email8.queue_messages m \
                 LEFT JOIN email8.queue_recipients r ON r.message_id = m.id \
                 WHERE m.env_id = $1 \
                 GROUP BY m.id ORDER BY m.created_at DESC LIMIT 200",
            )
            .bind(env_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(err_db)?;
            let items: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.get::<uuid::Uuid, _>("id"),
                        "return_path": r.get::<String, _>("return_path"),
                        "size": r.get::<i64, _>("size"),
                        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                        "pending": r.get::<i64, _>("pending"),
                        "done": r.get::<i64, _>("done"),
                        "failed": r.get::<i64, _>("failed"),
                        "deferred": r.get::<i64, _>("deferred"),
                    })
                })
                .collect();
            Ok(Json(AdminDataRows::Items { items }))
        }
        "dkim" => {
            use sqlx::Row;
            let rows = sqlx::query(
                "SELECT id, domain, selector, created_at, last_checked_at, success                  FROM email8.dkim_checks WHERE env_id = $1                  ORDER BY created_at DESC LIMIT 200",
            )
            .bind(env_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(err_db)?;
            let items: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.get::<i64, _>("id"),
                        "domain": r.get::<String, _>("domain"),
                        "selector": r.get::<Option<String>, _>("selector"),
                        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                        "last_checked_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_checked_at"),
                        "success": r.get::<bool, _>("success"),
                    })
                })
                .collect();
            Ok(Json(AdminDataRows::Items { items }))
        }
        "reports" => {
            use sqlx::Row;
            let rows = sqlx::query(
                "SELECT 'dmarc' AS kind, domain, window_end, submitted_at, created_at \
                 FROM email8.reports_dmarc WHERE env_id = $1 \
                 UNION ALL \
                 SELECT 'tls' AS kind, domain, window_end, submitted_at, created_at \
                 FROM email8.reports_tls WHERE env_id = $1 \
                 ORDER BY created_at DESC LIMIT 200",
            )
            .bind(env_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(err_db)?;
            let items: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "kind": r.get::<String, _>("kind"),
                        "domain": r.get::<String, _>("domain"),
                        "window_end": r.get::<chrono::DateTime<chrono::Utc>, _>("window_end"),
                        "submitted_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("submitted_at"),
                    })
                })
                .collect();
            Ok(Json(AdminDataRows::Items { items }))
        }
        "spam" => spam_data(&mut *tx, env_id).await.map(Json),
        "hooks" => hooks_data(&mut *tx, env_id).await.map(Json),
        "domains" => domains_data(&mut *tx, env_id).await.map(Json),
        "external_reports" => external_reports_data(&mut *tx, env_id).await.map(Json),
        other => {
            let _ = tx.commit().await;
            return Err((
                StatusCode::NOT_FOUND,
                format!("Unknown admin data page: {other}"),
            ));
        }
    };
    tx.commit().await.map_err(err_db)?;
    result
}

/// `POST /v1/admin/{page}` - data endpoints.
fn queue_page() -> AdminUiPage {
    AdminPage::new("Delivery Queue")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "return_path".into(),
                    label: "Sender".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "pending".into(),
                    label: "Pending".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "deferred".into(),
                    label: "Deferred".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "failed".into(),
                    label: "Failed".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Accepted".into(),
                    sortable: true,
                    width: None,
                    format: Some("date".into()),
                },
            ],
            data_endpoint: "/queue".into(),
            sortable: true,
            filterable: false,
            page_size: 50,
            empty_message: Some("Queue is empty".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn dkim_page() -> AdminUiPage {
    AdminPage::new("DKIM Keys")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "domain".into(),
                    label: "Domain".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "selector".into(),
                    label: "Selector".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "algorithm".into(),
                    label: "Algorithm".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "stage".into(),
                    label: "Stage".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/dkim".into(),
            sortable: false,
            filterable: false,
            page_size: 50,
            empty_message: None,
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn reports_page() -> AdminUiPage {
    AdminPage::new("Reports")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "kind".into(),
                    label: "Kind".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "domain".into(),
                    label: "Domain".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "window_end".into(),
                    label: "Window End".into(),
                    sortable: true,
                    width: None,
                    format: Some("date".into()),
                },
                WidgetDataTableColumn {
                    key: "submitted_at".into(),
                    label: "Submitted".into(),
                    sortable: false,
                    width: None,
                    format: Some("date".into()),
                },
            ],
            data_endpoint: "/reports".into(),
            sortable: true,
            filterable: false,
            page_size: 50,
            empty_message: None,
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

/// Inbound external reports viewer (DMARC rua / TLS-RPT / ARF ruf
/// feedback) - design §P4.6.
async fn external_reports_data(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> Result<AdminDataRows, (StatusCode, String)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT report_kind, domain, source_address, received_at, payload \
         FROM email8.reports_external WHERE env_id = $1 \
         ORDER BY received_at DESC LIMIT 200",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": r.get::<String, _>("report_kind"),
                "domain": r.get::<String, _>("domain"),
                "source_address": r.get::<Option<String>, _>("source_address"),
                "received_at": r.get::<chrono::DateTime<chrono::Utc>, _>("received_at"),
                "payload": r.get::<serde_json::Value, _>("payload"),
            })
        })
        .collect();
    Ok(AdminDataRows::Items { items })
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    tracing::error!(error = %e, "email8:mta: admin database error");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Spam policy view - the env's MTA policy row (thresholds, size caps,
/// relay posture - the tunables the spam gate consults; design §7
/// `spam` page).
async fn spam_data(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> Result<AdminDataRows, (StatusCode, String)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT hostname, max_message_size, max_recipients_per_message, \
                max_messages_per_session, require_auth, allow_relaying, \
                dsn_name, dsn_address \
         FROM email8.mta_policy WHERE env_id = $1",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "hostname": r.get::<String, _>("hostname"),
                "max_message_size": r.get::<i64, _>("max_message_size"),
                "max_recipients_per_message": r.get::<i32, _>("max_recipients_per_message"),
                "max_messages_per_session": r.get::<i32, _>("max_messages_per_session"),
                "require_auth": r.get::<bool, _>("require_auth"),
                "allow_relaying": r.get::<bool, _>("allow_relaying"),
                "dsn_name": r.get::<String, _>("dsn_name"),
                "dsn_address": r.get::<String, _>("dsn_address"),
            })
        })
        .collect();
    Ok(AdminDataRows::Items { items })
}

/// Hooks view - stage scripts (Sieve), milter endpoints, MTA hook URLs
/// (design §7 `hooks` page).
async fn hooks_data(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> Result<AdminDataRows, (StatusCode, String)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT stage, hook_kind, target, is_enabled \
         FROM email8.mta_hooks WHERE env_id = $1 ORDER BY stage, hook_kind",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "stage": r.get::<String, _>("stage"),
                "hook_kind": r.get::<String, _>("hook_kind"),
                "target": r.get::<String, _>("target"),
                "is_enabled": r.get::<bool, _>("is_enabled"),
            })
        })
        .collect();
    Ok(AdminDataRows::Items { items })
}

/// Domains view - the mail domains this tenant serves (design §7
/// `domains` page). The rows live in the Store-owned schema (mta
/// design §7: "domain rows themselves live in Store schema") but the
/// same database + RLS context governs both services, so the Mta admin
/// viewer reads them directly.
async fn domains_data(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
) -> Result<AdminDataRows, (StatusCode, String)> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT name, is_enabled, allow_relaying, report_address \
         FROM email8.domains WHERE env_id = $1 ORDER BY name",
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.get::<String, _>("name"),
                "is_enabled": r.get::<bool, _>("is_enabled"),
                "allow_relaying": r.get::<bool, _>("allow_relaying"),
                "report_address": r.get::<Option<String>, _>("report_address"),
            })
        })
        .collect();
    Ok(AdminDataRows::Items { items })
}

fn spam_page() -> AdminUiPage {
    AdminPage::new("Spam Policy")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "hostname".into(),
                    label: "Hostname".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "max_message_size".into(),
                    label: "Max Size".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "max_recipients_per_message".into(),
                    label: "Max Rcpts".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "require_auth".into(),
                    label: "Require Auth".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "allow_relaying".into(),
                    label: "Relay".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/spam".into(),
            sortable: false,
            filterable: false,
            page_size: 50,
            empty_message: Some("No spam policy configured".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn hooks_page() -> AdminUiPage {
    AdminPage::new("MTA Hooks")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "stage".into(),
                    label: "Stage".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "hook_kind".into(),
                    label: "Kind".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "target".into(),
                    label: "Target".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "is_enabled".into(),
                    label: "Enabled".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/hooks".into(),
            sortable: false,
            filterable: false,
            page_size: 50,
            empty_message: Some("No hooks configured".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn domains_page() -> AdminUiPage {
    AdminPage::new("Domains")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "domain".into(),
                    label: "Domain".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "is_active".into(),
                    label: "Active".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "allow_relaying".into(),
                    label: "Relay".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "report_address".into(),
                    label: "Report Address".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/domains".into(),
            sortable: false,
            filterable: false,
            page_size: 50,
            empty_message: Some("No domains configured".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}
