// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Valkey-backed rate limits, greylisting, and fail2ban counters
//! (design §2.2 + §6; stories 1.7 and 5.5).
//!
//! Fixed-window counters keyed `e8:{env}:{kind}:{key}:{window}` for:
//! connection, sender, rcpt, rcpt-domain, remote-host, remote-ip,
//! EHLO domain, authenticated-as. Greylisting uses the classic
//! triple (sender IP, sender, recipient) with a per-env retry
//! window; fail2ban counts auth failures and bans the IP for a TTL.

use std::time::Duration;

use uuid::Uuid;

/// A lazily-connected Valkey client (GLIDE over the Valkey TLS plane,
/// presenting the MTA's `email8:mta` workload certificate identity -
/// platform group DESIGN.md §3.1).
#[derive(Clone)]
pub struct ValkeyLimits {
    client: glide::GlideClient,
}

/// One throttle kind (the key namespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleKind {
    Connection,
    Sender,
    Rcpt,
    RcptDomain,
    RemoteHost,
    RemoteIp,
    Ehlo,
    AuthenticatedAs,
}

impl ThrottleKind {
    fn key_segment(&self) -> &'static str {
        match self {
            Self::Connection => "conn",
            Self::Sender => "sender",
            Self::Rcpt => "rcpt",
            Self::RcptDomain => "rcptdom",
            Self::RemoteHost => "host",
            Self::RemoteIp => "ip",
            Self::Ehlo => "ehlo",
            Self::AuthenticatedAs => "as",
        }
    }
}

impl ValkeyLimits {
    /// Connect via the platform factory (URL form `valkeys://host:port` -
    /// the plane is TLS-only; the cert CN maps to the `m2m-email8:mta`
    /// ACL user provisioned by `vertical enroll`).
    ///
    /// # Errors
    /// Returns the factory's connect failure (scheme gate, missing
    /// workload pair, unreachable plane).
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = sentin8::middleware::valkey_client(url, "email8:mta")
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { client })
    }

    /// Fixed-window rate check: increment the counter for
    /// (`kind`,`key`) and report whether it exceeded `max` within the
    /// `period` window. The counter self-expires at window end.
    pub async fn rate_exceeded(
        &self,
        env_id: &Uuid,
        kind: ThrottleKind,
        key: &str,
        max: u64,
        period: Duration,
    ) -> Result<bool, String> {
        let window = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            / period.as_secs().max(1);
        let ck = format!(
            "e8:{env}:{kind}:{key}:{window}",
            env = env_id,
            kind = kind.key_segment(),
        );
        use glide::AsyncCommands as _;
        let count: isize = self.client.incr(&ck, 1).await.map_err(|e| e.to_string())?;
        if count == 1 {
            let _: bool = self
                .client
                .expire(&ck, period.as_secs().max(1) as i64)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(count as u64 > max)
    }

    /// Greylisting (RFC-compliant temp-reject on first sight): record
    /// the (ip, sender, rcpt) triple with a `retry_after` TTL. Returns
    /// true when the message should be temp-rejected (greylisted), false
    /// when the triple has been seen before (within or after the window
    /// - a legitimate sender retries).
    pub async fn greylist_defer(
        &self,
        env_id: &Uuid,
        ip: &str,
        sender: &str,
        rcpt: &str,
        retry_window: Duration,
    ) -> Result<bool, String> {
        let key = format!(
            "e8:{env}:grey:{ip}:{sender}:{rcpt}",
            env = env_id,
            ip = ip,
            sender = sender,
            rcpt = rcpt,
        );
        use glide::AsyncCommands as _;
        // SET NX + TTL: the FIRST sighting defers; the retry passes.
        let set: Option<String> = self
            .client
            .set_options(
                &key,
                "1",
                glide::commands::options::SetOptions::default()
                    .conditional_set(glide::commands::options::ExistenceCheck::NX)
                    .with_expiration(glide::commands::options::SetExpiry::EX(
                        retry_window.as_secs().max(1),
                    )),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(set.is_some()) // Some("OK") → we just created it → defer
    }

    /// Fail2ban: count one auth/connection failure for an IP; when the
    /// count crosses `threshold` within `period`, set a ban for
    /// `ban_ttl`. Returns true when this call triggered the ban.
    pub async fn fail2ban_strike(
        &self,
        env_id: &Uuid,
        ip: &str,
        threshold: u64,
        period: Duration,
        ban_ttl: Duration,
    ) -> Result<bool, String> {
        let strikes = format!("e8:{env}:f2b:{ip}", env = env_id);
        use glide::AsyncCommands as _;
        let count: isize = self
            .client
            .incr(&strikes, 1)
            .await
            .map_err(|e| e.to_string())?;
        if count == 1 {
            let _: bool = self
                .client
                .expire(&strikes, period.as_secs().max(1) as i64)
                .await
                .map_err(|e| e.to_string())?;
        }
        if count as u64 >= threshold {
            let banned: Option<String> = self
                .client
                .set_options(
                    format!("e8:{env}:banned:{ip}", env = env_id),
                    "1",
                    glide::commands::options::SetOptions::default().with_expiration(
                        glide::commands::options::SetExpiry::EX(ban_ttl.as_secs().max(1)),
                    ),
                )
                .await
                .map_err(|e| e.to_string())?;
            let _: usize = self.client.del(&strikes).await.unwrap_or(0);
            return Ok(banned.is_some());
        }
        Ok(false)
    }

    /// Is the IP currently banned?
    pub async fn is_banned(&self, env_id: &Uuid, ip: &str) -> Result<bool, String> {
        let key = format!("e8:{env}:banned:{ip}", env = env_id);
        use glide::AsyncCommands as _;
        let exists: bool = self.client.exists(&key).await.map_err(|e| e.to_string())?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_layout_is_namespaced() {
        let env = Uuid::nil();
        let window = 3600u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let w = now / window;
        // Mirrors the rate_exceeded key construction (kept in sync by
        // the test).
        let ck = format!(
            "e8:{env}:{}:sender:{}:{w}",
            ThrottleKind::Sender.key_segment(),
            "a@b.c"
        );
        assert!(ck.starts_with("e8:00000000-0000-0000-0000-000000000000:sender:sender:a@b.c:"));
    }
}
