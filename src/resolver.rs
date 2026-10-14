// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! DNS resolver adapter — implements `email8::mail_auth::DnsTxt` for the
//! Mta. Uses the system resolver via `tokio::net::lookup_host` for A /
//! MX-shaped queries where possible, and a configurable DNS-over-HTTPS
//! endpoint for TXT lookups (the platform gap G3 tracks a hickory
//! DNSSEC-validated resolver; until then DoH is the default with a
//! localhost:5353 plain fallback for dev).
//!
//! Wire shapes surfaced to the auth crate (kept stable for tests):
//! - TXT records: raw strings.
//! - MX records (via `_mx.<domain>`): `"10 mail.example.com"` rows.
//! - A records (via `_a.<host>`): address strings.

use async_trait::async_trait;

/// The resolver used by the pipeline.
pub struct Resolver {
    /// DoH base URL (e.g. `https://dns.example/dns-query`). Empty →
    /// skip TXT lookups (dev mode without DNS).
    doh_url: Option<String>,
    /// Optional DoH bearer token.
    doh_token: Option<String>,
}

impl Resolver {
    pub fn from_env() -> Self {
        Self {
            doh_url: std::env::var("EMAIL8_DOH_URL").ok().filter(|s| !s.is_empty()),
            doh_token: std::env::var("EMAIL8_DOH_TOKEN").ok().filter(|s| !s.is_empty()),
        }
    }
}

#[async_trait]
impl email8::mail_auth::DnsTxt for Resolver {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, String> {
        // Synthetic namespaces used by the SPF machinery (a/mx/exists).
        if let Some(host) = name.strip_prefix("_a.") {
            return lookup_a(host).await;
        }
        if let Some(domain) = name.strip_prefix("_mx.") {
            return lookup_mx_doh(&self.doh_url, &self.doh_token, domain).await;
        }
        if name.starts_with("_exists.") {
            // RFC 7208 exists: — any A record proves the name exists.
            let host = &name["_exists.".len()..];
            let records = lookup_a(host).await?;
            return Ok(if records.is_empty() { vec![] } else { vec!["1".into()] });
        }
        // Plain TXT record.
        lookup_txt_doh(&self.doh_url, &self.doh_token, name).await
    }
}

async fn lookup_a(host: &str) -> Result<Vec<String>, String> {
    // Use the system resolver (no DNSSEC in dev; hickory lands with G3).
    let addrs = tokio::net::lookup_host((host, 0u16))
        .await
        .map_err(|e| format!("resolve {host}: {e}"))?;
    Ok(addrs.map(|a| a.ip().to_string()).collect())
}

/// DNSBL bridge (story 5.2): the spam crate's DNSBL gate needs an A
/// lookup against `{reversed}.{zone}` — same system-resolver path.
#[async_trait]
impl email8::spam::DnsblResolver for Resolver {
    async fn lookup_a(&self, name: &str) -> Result<Vec<String>, String> {
        lookup_a(name).await
    }
}

async fn doh_query(
    base: Option<&str>,
    token: Option<&str>,
    name: &str,
    rrtype: &str,
) -> Result<Vec<String>, String> {
    let Some(base) = base else {
        return Err(format!("no DoH configured for {name} {rrtype}"));
    };
    let url = format!(
        "{base}?name={}&type={rrtype}",
        percent_encoding(name)
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.map_err(|e| format!("doh: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("doh status {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
        for a in answers {
            if let Some(data) = a.get("data").and_then(|d| d.as_str()) {
                out.push(data.trim_matches('"').to_string());
            }
        }
    }
    Ok(out)
}

async fn lookup_txt_doh(
    base: &Option<String>,
    token: &Option<String>,
    name: &str,
) -> Result<Vec<String>, String> {
    doh_query(base.as_deref(), token.as_deref(), name, "TXT").await
}

async fn lookup_mx_doh(
    base: &Option<String>,
    token: &Option<String>,
    domain: &str,
) -> Result<Vec<String>, String> {
    doh_query(base.as_deref(), token.as_deref(), domain, "MX").await
}

fn percent_encoding(s: &str) -> String {
    // Minimal URL encode for DNS names.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}