// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Email8:Mta.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, ErrorCode, M2mGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, SqlMigration,
};
#[cfg(not(test))]
use utoipa::OpenApi;

/// The Shield text of the declared scope-mirror set - public so the
/// policy wiring tests (POLICY-7) assert against the REAL seed.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"email8:submission:send\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"email8:mail:receive\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:submission:send\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:mail:receive\", resource) when { principal.scopes.contains(\"email8:mail:receive\") };
permit(principal, action == Action::\"email8:mail:receive\", resource) when { principal.scopes.contains(\"email8:submission:send\") };
permit(principal, action == Action::\"email8:mail:receive\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:mail:receive\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:mail:receive\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:admin:queue\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:admin:reports\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:admin:domains\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:admin:spam\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:admin:users\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"email8:admin:quotas\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"email8:admin:users\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"email8:admin:domains\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"email8:admin:queue\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"email8:admin:reports\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"email8:admin:spam\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };
permit(principal, action == Action::\"email8:admin:quotas\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Enforced (decision 2026-09-07): step 5 is the
/// only gate; shadow is the emergency one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for email8:mta over the LIVE effective scope set (policy design §3.1d). Enforced (decision 2026-09-07) - step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by this
/// service today; env admins author their own graph (delegate /
/// shared-mailbox edges) via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

/// M2M workload declarations (CERTFREE-4V): the `email8:mta` workload
/// row drives `vertical enroll`'s Valkey ACL-user provisioning (the CN
/// `m2m-email8:mta` maps to the ACL user of the same name - group
/// DESIGN.md §3.1, without which the MTA's GLIDE rate-limit connections
/// can never connect) and carries the scopes Store's internal-data-API
/// gate checks for SMTP ingestion.
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "email8:mta",
        scopes: &[
            // The outbox relay's produce scope (OUTBOX-EMAIL8 - DBX
            // producer path): the shell's 8b relay presents this
            // workload's cert to Bus `POST /v1/produce`.
            "sentin8:bus:produce",
            "email8:mail:read",
            "email8:mail:write",
            "email8:mail:receive",
        ],
    },
    M2mGrant {
        // Shield hot-reload consumer (BUSPOLICY-1 - see email8-access).
        workload: "email8:mta-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        // Audit-journal pusher's sys-ingest scope (AUDJOUR-1): the shell's
        // boot-8c pusher presents the `mta-audit` certificate to Sys
        // `POST /v1/audit` - this grant row is what makes the workload
        // enrollable (the BUSPOLICY-1 class: an undeclared cert mints but
        // can never be authorized).
        workload: "mta-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
];

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "email8:mail:read,email8:mail:write,email8:queue:read,email8:queue:write",
    role: "email8_mta_service",
    bypass_rls: false,
    database: "email8",
    cross_schema_grants: &[],
}];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:queue",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:dkim",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:reports",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:spam",
    },
    AdminScope::Typed {
        role: "email8:admin",
        scope: "email8:admin:scripts",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "email8:mta:admin",
        scope: "email8:mta:policy:read",
    },
    AdminScope::Typed {
        role: "email8:mta:admin",
        scope: "email8:mta:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "Email8DmarcPolicyReject",
        error_code: "email8_dmarc_policy_reject",
        status_code: 422,
    },
    ErrorCode {
        enum_name: "Email8SpamScoreReject",
        error_code: "email8_spam_score_reject",
        status_code: 422,
    },
    ErrorCode {
        enum_name: "Email8Greylisted",
        error_code: "email8_greylisted",
        status_code: 429,
    },
    ErrorCode {
        enum_name: "Email8QueueFull",
        error_code: "email8_queue_full",
        status_code: 402,
    },
    ErrorCode {
        enum_name: "Email8RelayDenied",
        error_code: "email8_relay_denied",
        status_code: 403,
    },
    ErrorCode {
        enum_name: "Email8SenderAddressRejected",
        error_code: "email8_sender_address_rejected",
        status_code: 403,
    },
    ErrorCode {
        enum_name: "Email8DkimKeyNotFound",
        error_code: "email8_dkim_key_not_found",
        status_code: 404,
    },
    ErrorCode {
        enum_name: "Email8DomainNotFound",
        error_code: "email8_domain_not_found",
        status_code: 404,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "queue",
        label: "Queue",
        ui_endpoint: "/v1/admin/ui/queue",
        data_endpoint: "/v1/admin/queue",
        icon: "0xe8d3",
    },
    AdminUiPage {
        route: "dkim",
        label: "DKIM Keys",
        ui_endpoint: "/v1/admin/ui/dkim",
        data_endpoint: "/v1/admin/dkim",
        icon: "0xe068",
    },
    AdminUiPage {
        route: "reports",
        label: "Reports",
        ui_endpoint: "/v1/admin/ui/reports",
        data_endpoint: "/v1/admin/reports",
        icon: "0xe873",
    },
    AdminUiPage {
        route: "spam",
        label: "Spam Policy",
        ui_endpoint: "/v1/admin/ui/spam",
        data_endpoint: "/v1/admin/spam",
        icon: "0xe868",
    },
    AdminUiPage {
        route: "hooks",
        label: "MTA Hooks",
        ui_endpoint: "/v1/admin/ui/hooks",
        data_endpoint: "/v1/admin/hooks",
        icon: "0xe8e1",
    },
    AdminUiPage {
        route: "domains",
        label: "Domains",
        ui_endpoint: "/v1/admin/ui/domains",
        data_endpoint: "/v1/admin/domains",
        icon: "0xe80b",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// OUTBOX-EMAIL8 migration v3: the per-service leaf-schema outbox
/// (the DBX producer path - sql/outbox.sql). v1 already applied on live
/// DBs; the version bump provisions the outbox without recreation
/// (greenfield versioning, no migration code).
const SQL_2_OUTBOX: &str = include_str!("../sql/outbox.sql");

/// AUDJOUR-1 migration v4: the local audit journal in the `mta` leaf
/// schema (sql/audit.sql) - the 15-column contract of
/// `sentin8_audit::audit_journal_sql` (design/sentin8-audit-journal-
/// provisioning-design.md §2.1). The shell's boot-8c pusher drains it
/// to Sys `POST /v1/audit`.
const SQL_3_AUDIT: &str = include_str!("../sql/audit.sql");

fn openapi_spec() -> serde_json::Value {
    // Portable stub when #[path]-included from tests (POLICY-7): the real
    // derive lives in the crate's openapi module, which tests don't link.
    #[cfg(not(test))]
    {
        serde_json::to_value(crate::openapi::MtaOpenApi::openapi())
            .unwrap_or(serde_json::Value::Null)
    }
    #[cfg(test)]
    return serde_json::Value::Null;
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "email8:mta",
        subdomain: "email8-mta",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "MTA",
            icon: "0xe8d3",
            service_flag: "email8",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![
            SqlMigration {
                version: 1,
                name: "init",
                sql: SQL_1_INIT,
            },
            SqlMigration {
                version: 3,
                name: "outbox",
                sql: SQL_2_OUTBOX,
            },
            SqlMigration {
                version: 4,
                name: "audit",
                sql: SQL_3_AUDIT,
            },
        ],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        pg_roles: PG_ROLES,
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
