// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Story 5.2 - per-environment DNSBL zone configuration.
//!
//! Zones are persisted in `email8.dnsbl_zones` (applied by
//! `sentin8-cli vertical init` from the store's init.sql) and cached
//! per env by the MTA. The gate is refreshed on a 60 s TTL so operators
//! can add/remove zones without a service restart.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use uuid::Uuid;

use email8::spam::DnsblZone;

/// One configured zone row (`dnsbl_zones`).
#[derive(Debug, Clone)]
pub struct DnsblZoneRow {
    pub zone: String,
    /// Comma-separated scope list (`ip,helo,ptr`).
    pub scopes: String,
    /// Max lookups against this zone per message (0 → unlimited).
    pub cap: u32,
}

/// The process-wide per-env zone cache (60 s TTL).
pub struct DnsblZoneCache {
    pool: sqlx::PgPool,
    entries: RwLock<HashMap<Uuid, (Vec<DnsblZone>, Instant)>>,
}

const TTL: Duration = Duration::from_secs(60);

impl DnsblZoneCache {
    pub fn new(pool: sqlx::PgPool) -> Arc<Self> {
        Arc::new(Self {
            pool,
            entries: RwLock::new(HashMap::new()),
        })
    }

    /// The active zone set for `env_id` (loads and caches on miss/expiry).
    pub async fn zones_for(&self, env_id: Uuid) -> Vec<DnsblZone> {
        {
            let entries = self.entries.read().await;
            if let Some((zones, loaded_at)) = entries.get(&env_id) {
                if loaded_at.elapsed() < TTL {
                    return zones.clone();
                }
            }
        }
        let rows: Vec<(String, String, i32)> = match self.pool.begin().await {
            Ok(mut tx) => {
                // stamp + SELECT share ONE transaction.
                let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                    .bind(env_id)
                    .execute(&mut *tx)
                    .await;
                match sqlx::query_as(
                    "SELECT zone, scopes, max_checks FROM email8.dnsbl_zones \
                     WHERE env_id = $1 ORDER BY zone",
                )
                .bind(env_id)
                .fetch_all(&mut *tx)
                .await
                {
                    Ok(rows) => {
                        let _ = tx.commit().await;
                        rows
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "email8:mta: dnsbl zone load failed");
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "email8:mta: dnsbl zone pool acquire failed");
                Vec::new()
            }
        };
        let zones: Vec<DnsblZone> = rows
            .iter()
            .map(|(zone, scopes, cap)| DnsblZoneRow {
                zone: zone.clone(),
                scopes: scopes.clone(),
                cap: *cap as u32,
            })
            .collect::<Vec<_>>()
            .iter()
            .filter_map(|r| {
                // Reuse the spam-crate parser (`zone|scopes|cap` rows).
                email8::spam::dnsbl::zones_from_config(&[(r.zone.clone(), r.scopes.clone(), r.cap)])
                    .into_iter()
                    .next()
            })
            .collect();
        let mut entries = self.entries.write().await;
        entries.insert(env_id, (zones.clone(), Instant::now()));
        zones
    }
}
