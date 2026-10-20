// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Email8:Mta.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_delete_attribute,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_test_set,
        crate::submit::submit,
        crate::admin::admin_data,
        crate::admin::get_admin_ui,
        crate::server::health,
    ),
    components(schemas(
        email8::contracts::SubmitRequest,
        email8::contracts::SubmitResponse,
    )),
    security(),
    tags(
        (name = "policy", description = "Shield policy administration (shared surface)"),
        (name = "email8-mta", description = "Sentin8 Email8:Mta - SMTP transfer engine, queue, DKIM, reports"),
    ),
)]
pub struct MtaOpenApi;
