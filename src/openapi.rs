// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for Email8:Mta.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::submit::submit,
        crate::admin::admin_data,
    ),
    components(schemas(
        email8::contracts::SubmitRequest,
        email8::contracts::SubmitResponse,
    )),
    security(),
    tags(
        (name = "email8-mta", description = "Sentin8 Email8:Mta — SMTP transfer engine, queue, DKIM, reports"),
    ),
)]
pub struct MtaOpenApi;
