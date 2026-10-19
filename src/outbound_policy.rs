// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Outbound policy - MTA-STS (RFC 8460 predecessor, RFC 8461) policy
//! fetch + cache, and TLSRPT (RFC 8460) `_smtp._tls` TXT lookup.
//! DNS arrives via the injected `DnsTxt`; the `.well-known` fetch uses
//! reqwest with a short timeout (the policy is cached per max_age).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// A parsed MTA-STS policy (`/.well-known/mta-sts.txt`).
#[derive(Debug, Clone, PartialEq)]
pub struct MtaStsPolicy {
    pub version: String,
    /// none | testing | enforce.
    pub mode: String,
    pub mx: Vec<String>,
    pub max_age_secs: u64,
}

impl MtaStsPolicy {
    /// Parse the `key: value` policy text.
    pub fn parse(text: &str) -> Option<Self> {
        let mut version = String::new();
        let mut mode = String::new();
        let mut mx = Vec::new();
        let mut max_age = 0u64;
        for line in text.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "version" => version = v.to_string(),
                "mode" => mode = v.to_ascii_lowercase(),
                "mx" => mx.push(v.to_ascii_lowercase()),
                "max_age" => max_age = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        if version != "STSv1" || mode.is_empty() || mx.is_empty() || max_age == 0 {
            return None;
        }
        Some(Self {
            version,
            mode,
            mx,
            max_age_secs: max_age,
        })
    }
}

/// TLSRPT policy TXT row (`_smtp._tls.<domain>`).
#[derive(Debug, Clone)]
pub struct TlsrptPolicy {
    pub rua: Vec<String>,
}

impl TlsrptPolicy {
    /// `v=TLSRPTv1; rua=mailto:reports@example.com` (multiple rua
    /// comma-separated).
    pub async fn lookup(dns: &dyn email8::mail_auth::DnsTxt, domain: &str) -> Option<Self> {
        let name = format!("_smtp._tls.{domain}");
        let rows = dns.lookup_txt(&name).await.ok()?;
        let row = rows.iter().find(|r| {
            r.trim_start()
                .to_ascii_lowercase()
                .starts_with("v=tlsrptv1")
        })?;
        let mut rua = Vec::new();
        for tag in row.split(';') {
            if let Some(v) = tag
                .trim()
                .strip_prefix("rua=")
                .or_else(|| tag.trim().strip_prefix("RUA="))
            {
                rua.extend(v.split(',').map(|s| s.trim().to_string()));
            }
        }
        if rua.is_empty() {
            return None;
        }
        Some(Self { rua })
    }
}

/// In-process MTA-STS policy cache (per (domain, policy-id), honoring
/// max_age). The DNS TXT `_mta-sts.<domain>` row carries the policy id;
/// a changed id triggers a re-fetch.
pub struct StsCache {
    entries: Arc<RwLock<HashMap<String, CachedPolicy>>>,
    /// Test hook: when set, policies are fetched through this closure
    /// instead of HTTP.
    fetch_hook: Option<StsFetchHook>,
}

type StsFetchHook = Arc<dyn Fn(&str) -> String + Send + Sync>;

struct CachedPolicy {
    id: String,
    policy: Option<MtaStsPolicy>,
    fetched_at: Instant,
}

impl Default for StsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl StsCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            fetch_hook: None,
        }
    }

    /// Test-only: install a fetch hook.
    pub fn with_fetch_hook(mut self, f: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        self.fetch_hook = Some(Arc::new(f));
        self
    }

    /// The effective policy for a domain (None when no STS DNS record).
    pub async fn policy_for(
        &self,
        dns: &dyn email8::mail_auth::DnsTxt,
        domain: &str,
    ) -> Option<MtaStsPolicy> {
        // 1. DNS TXT _mta-sts.<domain> → "v=STSv1; id=<id>"
        let name = format!("_mta-sts.{domain}");
        let rows = dns.lookup_txt(&name).await.ok()?;
        let row = rows
            .iter()
            .find(|r| r.trim_start().to_ascii_lowercase().starts_with("v=stsv1"))?;
        let id = row
            .split(';')
            .find_map(|tag| tag.trim().strip_prefix("id=").map(|s| s.to_string()))
            .or_else(|| {
                row.split(';')
                    .find_map(|tag| tag.trim().strip_prefix("id=").map(|s| s.to_string()))
            })?;

        // 2. Cached?
        {
            let entries = self.entries.read().await;
            if let Some(cached) = entries.get(domain) {
                if cached.id == id
                    && cached.fetched_at.elapsed()
                        < Duration::from_secs(
                            cached
                                .policy
                                .as_ref()
                                .map(|p| p.max_age_secs)
                                .unwrap_or(86400),
                        )
                {
                    return cached.policy.clone();
                }
            }
        }

        // 3. Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt
        let policy = match &self.fetch_hook {
            Some(hook) => MtaStsPolicy::parse(&hook(domain)),
            None => fetch_policy_http(domain).await,
        };

        // 4. Cache (including the None case - negative caching with the
        // DNS id still pinned).
        let mut entries = self.entries.write().await;
        entries.insert(
            domain.to_string(),
            CachedPolicy {
                id,
                policy: policy.clone(),
                fetched_at: Instant::now(),
            },
        );
        policy
    }
}

async fn fetch_policy_http(domain: &str) -> Option<MtaStsPolicy> {
    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;
    let body = client.get(&url).send().await.ok()?.text().await.ok()?;
    MtaStsPolicy::parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use email8::mail_auth::FnDnsTxt;

    #[test]
    fn parses_policy_text() {
        let p = MtaStsPolicy::parse(
            "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 123456\n",
        )
        .unwrap();
        assert_eq!(p.mode, "enforce");
        assert_eq!(p.mx.len(), 2);
        assert_eq!(p.max_age_secs, 123456);
    }

    #[test]
    fn rejects_malformed_policy() {
        assert!(MtaStsPolicy::parse("version: STSv1\nmode: enforce\n").is_none());
        assert!(MtaStsPolicy::parse("").is_none());
    }

    #[tokio::test]
    async fn caches_per_policy_id() {
        let dns = FnDnsTxt(|name: &str| {
            if name == "_mta-sts.example.com" {
                Ok(vec!["v=STSv1; id=abc123".into()])
            } else {
                Err("nx".into())
            }
        });
        let cache = StsCache::new().with_fetch_hook(|domain| {
            format!("version: STSv1\nmode: enforce\nmx: mx.{domain}\nmax_age: 60\n")
        });
        let p = cache.policy_for(&dns, "example.com").await.unwrap();
        assert_eq!(p.mode, "enforce");
        // Second read hits the cache (same id).
        let p2 = cache.policy_for(&dns, "example.com").await.unwrap();
        assert_eq!(p, p2);
        // No DNS record → None.
        assert!(cache.policy_for(&dns, "other.com").await.is_none());
    }

    #[tokio::test]
    async fn tlsrpt_lookup_parses_rua() {
        let dns = FnDnsTxt(|name: &str| {
            if name == "_smtp._tls.example.com" {
                Ok(vec![
                    "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,mailto:two@example.org".into(),
                ])
            } else {
                Err("nx".into())
            }
        });
        let p = TlsrptPolicy::lookup(&dns, "example.com").await.unwrap();
        assert_eq!(p.rua.len(), 2);
        assert_eq!(p.rua[0], "mailto:tlsrpt@example.com");
    }
}
