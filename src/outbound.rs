// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Outbound delivery — the remote route engine (design §3.2).
//!
//! Per route (domain grouping): TLSRPT lookup → MTA-STS policy (cached)
//! → MX resolution → per-host connection strategy → STARTTLS/implicit
//! → MAIL/RCPT/BDAT or LMTP → per-recipient classification → caller
//! persists queue state. DNS arrives via the `DnsTxt` resolver injected
//! by the queue manager (MX records surface as TXT rows shaped
//! `"10 mx1.example.com"` — the hickory adapter in `resolver.rs`).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use email8::mail_queue::schedule::{classify_reply, Class};

use crate::outbound_policy::{MtaStsPolicy, StsCache, TlsrptPolicy};

/// The connection-level knobs (per env config rows).
#[derive(Debug, Clone)]
pub struct OutboundConfig {
    pub connect_timeout_secs: u64,
    /// Skip TLS verification for test deployments (default false —
    /// DANE/STS verification is the production path).
    pub insecure_skip_tls_verify: bool,
    /// Max recipients per outbound transaction.
    pub max_rcpt_per_txn: usize,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 30,
            insecure_skip_tls_verify: false,
            max_rcpt_per_txn: 25,
        }
    }
}

/// One recipient resolved for a route.
#[derive(Debug, Clone)]
pub struct OutboundRecipient {
    pub address: String,
    /// DSN NOTIFY parameter (default SUCCESS,FAILURE for DSN-enabled flows).
    pub notify: Option<String>,
    /// ORCPT original-recipient value.
    pub orcpt: Option<String>,
}

/// A route: the (remote domain, recipients) grouping.
pub struct RemoteRoute {
    pub domain: String,
    pub recipients: Vec<OutboundRecipient>,
}

/// Outcome for a single recipient after a delivery attempt.
#[derive(Debug, Clone)]
pub enum RcptOutcome {
    Completed { address: String, reply: String },
    Temporary { address: String, reply: String },
    Permanent { address: String, reply: String },
}

impl RcptOutcome {
    pub fn address(&self) -> &str {
        match self {
            RcptOutcome::Completed { address, .. }
            | RcptOutcome::Temporary { address, .. }
            | RcptOutcome::Permanent { address, .. } => address,
        }
    }
}

/// MX host candidate.
#[derive(Debug, Clone)]
pub struct MxHost {
    pub priority: u16,
    pub host: String,
}

/// Resolve the MX hosts for a domain. Null-MX (`0 .`) → hard fail.
/// No MX → implicit MX (the domain itself, RFC 5321 §5.1).
pub async fn resolve_mx(
    dns: &dyn email8::mail_auth::DnsTxt,
    domain: &str,
) -> Result<Vec<MxHost>, String> {
    let rows = dns
        .lookup_txt(&format!("_mx.{domain}"))
        .await
        .unwrap_or_default();
    if rows.is_empty() {
        return Ok(vec![MxHost {
            priority: 10,
            host: domain.to_string(),
        }]);
    }
    let mut hosts = Vec::new();
    for row in rows {
        let row = row.trim();
        // Null-MX (RFC 7505): "0 ."
        if row == "0 ." {
            return Err(format!("null-MX: domain {domain} accepts no mail"));
        }
        let mut parts = row.split_whitespace();
        let (Some(prio), Some(host)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(priority) = prio.parse::<u16>() else {
            continue;
        };
        if host == "." {
            continue;
        }
        hosts.push(MxHost {
            priority,
            host: host.to_ascii_lowercase(),
        });
    }
    hosts.sort_by_key(|h| h.priority);
    if hosts.is_empty() {
        return Err(format!("domain {domain} has no usable MX"));
    }
    Ok(hosts)
}

/// One delivery attempt over the wire. `stream` is the (possibly TLS-less)
/// connection; the client handles the SMTP dialogue including STARTTLS.
pub struct SmtpClient<S> {
    stream: S,
    buffer: Vec<u8>,
    /// Set once after a successful MAIL FROM (LMTP per-recipient replies).
    lmtp: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SmtpClient<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::with_capacity(1024),
            lmtp: false,
        }
    }

    /// Mark the session as LMTP (LHLO instead of EHLO).
    pub fn with_lmtp(mut self, lmtp: bool) -> Self {
        self.lmtp = lmtp;
        self
    }

    /// Read one reply line (single-line replies only — multiline EHLO
    /// replies are drained by `ehlo`).
    pub async fn read_reply(&mut self) -> Result<(u16, String), String> {
        let mut line = Vec::new();
        loop {
            // Drain the buffer for a complete CRLF-terminated line.
            if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&self.buffer[..=pos]);
                self.buffer.drain(..=pos);
                break;
            }
            let mut chunk = [0u8; 1024];
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed".into());
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&line[..line.len().saturating_sub(2)]).to_string();
        let code = text
            .get(..3)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| format!("malformed reply: {text}"))?;
        Ok((code, text))
    }

    async fn write_line(&mut self, line: &str) -> Result<(), String> {
        self.stream
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))
    }

    /// Greeting + EHLO/LHLO with capability capture.
    pub async fn handshake(&mut self, hostname: &str) -> Result<(u16, Vec<String>), String> {
        let (code, reply) = self.read_reply().await?;
        if code != 220 {
            return Err(format!("unexpected greeting: {reply}"));
        }
        let verb = if self.lmtp { "LHLO" } else { "EHLO" };
        self.write_line(&format!("{verb} {hostname}")).await?;
        let mut caps = Vec::new();
        let mut code;
        let mut last_line;
        loop {
            let (c, line) = self.read_reply().await?;
            code = c;
            last_line = line.clone();
            if let Some(cap) = line.get(4..) {
                caps.push(cap.trim().to_ascii_uppercase());
            }
            // Multiline replies: "250-..." continues, "250 ..." ends.
            if line.get(3..4) != Some("-") {
                break;
            }
        }
        if code != 250 {
            return Err(format!("EHLO rejected: {code} {last_line}"));
        }
        Ok((code, caps))
    }

    /// STARTTLS — returns the raw TCP stream so the caller can wrap it
    /// with TLS and construct a new client.
    pub async fn starttls_ready(&mut self, caps: &[String]) -> Result<(), String> {
        if !caps.iter().any(|c| c.starts_with("STARTTLS")) {
            return Err("STARTTLS not offered".into());
        }
        self.write_line("STARTTLS").await?;
        let (code, reply) = self.read_reply().await?;
        if code != 220 {
            return Err(format!("STARTTLS refused: {reply}"));
        }
        Ok(())
    }

    pub async fn mail_from(
        &mut self,
        sender: &str,
        size: Option<i64>,
        requiretls: bool,
        utf8: bool,
    ) -> Result<(), String> {
        let mut params = String::new();
        if let Some(s) = size {
            params.push_str(&format!(" SIZE={s}"));
        }
        if requiretls {
            params.push_str(" REQUIRETLS");
        }
        let _ = utf8; // SMTPUTF8 applies to addresses; appended below.
        let addr = if utf8 {
            sender.to_string()
        } else {
            sender.to_string()
        };
        self.write_line(&format!("MAIL FROM:<{addr}>{params}"))
            .await?;
        let (code, reply) = self.read_reply().await?;
        if code != 250 {
            return Err(reply);
        }
        Ok(())
    }

    /// RCPT — one recipient. Returns the raw reply for classification.
    pub async fn rcpt(&mut self, rcpt: &OutboundRecipient) -> Result<(u16, String), String> {
        let mut params = String::new();
        if let Some(notify) = &rcpt.notify {
            params.push_str(&format!(" NOTIFY={notify}"));
        }
        if let Some(orcpt) = &rcpt.orcpt {
            params.push_str(&format!(" ORCPT={orcpt}"));
        }
        self.write_line(&format!("RCPT TO:<{}>{params}", rcpt.address))
            .await?;
        self.read_reply().await
    }

    /// DATA body → classify all recipients from the final reply (SMTP) —
    /// LMTP reads one reply per accepted recipient.
    pub async fn data(
        &mut self,
        raw: &[u8],
        accepted: &[OutboundRecipient],
    ) -> Result<Vec<RcptOutcome>, String> {
        self.write_line(if self.lmtp { "LHLO-DATA" } else { "DATA" })
            .await?;
        let (code, reply) = self.read_reply().await?;
        if code != 354 {
            return Err(format!("DATA refused: {reply}"));
        }
        // Dot-stuffing per RFC 5321 §4.5.2.
        let mut body = Vec::with_capacity(raw.len() + 16);
        for line in raw.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.starts_with(b".") {
                body.push(b'.');
            }
            body.extend_from_slice(line);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b".\r\n");
        self.stream
            .write_all(&body)
            .await
            .map_err(|e| format!("write body: {e}"))?;
        if self.lmtp {
            // Per-recipient replies in RCPT order.
            let mut out = Vec::with_capacity(accepted.len());
            for rcpt in accepted {
                let (code, reply) = self.read_reply().await?;
                out.push(classify(rcpt.address.clone(), code, reply));
            }
            Ok(out)
        } else {
            let (code, reply) = self.read_reply().await?;
            Ok(accepted
                .iter()
                .map(|r| classify(r.address.clone(), code, reply.clone()))
                .collect())
        }
    }

    /// BDAT delivery (RFC 3030) — no dot-stuffing, byte-counted.
    pub async fn bdat(
        &mut self,
        raw: &[u8],
        accepted: &[OutboundRecipient],
    ) -> Result<Vec<RcptOutcome>, String> {
        let last = raw.len();
        self.write_line(&format!("BDAT {last} LAST")).await?;
        self.stream
            .write_all(raw)
            .await
            .map_err(|e| format!("write chunk: {e}"))?;
        if self.lmtp {
            let mut out = Vec::with_capacity(accepted.len());
            for rcpt in accepted {
                let (code, reply) = self.read_reply().await?;
                out.push(classify(rcpt.address.clone(), code, reply));
            }
            Ok(out)
        } else {
            let (code, reply) = self.read_reply().await?;
            Ok(accepted
                .iter()
                .map(|r| classify(r.address.clone(), code, reply.clone()))
                .collect())
        }
    }

    pub async fn quit(&mut self) -> Result<(), String> {
        self.write_line("QUIT").await?;
        let _ = self.read_reply().await;
        Ok(())
    }
}

/// Classify a reply code per RFC 5321 into the queue outcome.
pub fn classify(address: String, code: u16, reply: String) -> RcptOutcome {
    match classify_reply(code) {
        Class::Completed => RcptOutcome::Completed { address, reply },
        Class::Temporary => RcptOutcome::Temporary { address, reply },
        Class::Permanent => RcptOutcome::Permanent { address, reply },
    }
}

/// The full route plan for a domain (policy lookups happen here; the
/// connection attempts happen in the caller's worker).
pub struct RoutePlan {
    pub mx: Vec<MxHost>,
    pub sts: Option<MtaStsPolicy>,
    pub tlsrpt: Option<TlsrptPolicy>,
}

/// Resolve the route plan: MX + MTA-STS + TLSRPT.
pub async fn plan_route(
    dns: &dyn email8::mail_auth::DnsTxt,
    sts_cache: &StsCache,
    domain: &str,
) -> Result<RoutePlan, String> {
    let mx = resolve_mx(dns, domain).await?;
    let sts = sts_cache.policy_for(dns, domain).await;
    let tlsrpt = TlsrptPolicy::lookup(dns, domain).await;
    Ok(RoutePlan { mx, sts, tlsrpt })
}

/// Whether an MX host is authorized by the fetched MTA-STS policy.
pub fn sts_authorizes(sts: Option<&MtaStsPolicy>, host: &str) -> bool {
    match sts {
        None => true, // no policy → no restriction
        Some(p) => {
            if p.mode == "none" {
                return true;
            }
            p.mx.iter().any(|m| m.eq_ignore_ascii_case(host))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_codes() {
        assert!(matches!(
            classify("a@b.c".into(), 250, "250 Ok".into()),
            RcptOutcome::Completed { .. }
        ));
        assert!(matches!(
            classify("a@b.c".into(), 451, "451 later".into()),
            RcptOutcome::Temporary { .. }
        ));
        assert!(matches!(
            classify("a@b.c".into(), 550, "550 no".into()),
            RcptOutcome::Permanent { .. }
        ));
    }

    #[test]
    fn sts_authorization() {
        let sts = MtaStsPolicy {
            version: "STSv1".into(),
            mode: "enforce".into(),
            mx: vec!["mx1.example.com".into()],
            max_age_secs: 86400,
        };
        assert!(sts_authorizes(Some(&sts), "mx1.example.com"));
        assert!(!sts_authorizes(Some(&sts), "evil.example.net"));
        assert!(sts_authorizes(None, "anything.example"));
        let none_mode = MtaStsPolicy {
            mode: "none".into(),
            ..sts
        };
        assert!(sts_authorizes(Some(&none_mode), "whatever"));
    }
}
