// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Inbound SMTP session — the protocol state machine over a raw TCP stream.
//!
//! P1 scope: greeting, EHLO/HELO, AUTH (XOAUTH2/OAUTHBEARER + gated PLAIN
//! bridge), MAIL/RCPT envelope, DATA → blob → queue rows, with the
//! policy/limit gates from the mta design §2.1. STARTTLS is answered with
//! the ready line — the listener task owns the stream swap (platform TLS).
//!
//! The session is transport-agnostic: it drives an `AsyncRead + AsyncWrite`
//! pair, so the same code serves plaintext + STARTTLS and implicit TLS.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use email8::smtp_proto::{Command, Element, Receiver, Reply};

use crate::{auth::SmtpAuth, config::MtaConfig, submit::QueueWriter};

const SESSION_TIMEOUT_SECS: u64 = 15 * 60;
const MAX_TRANSFER_BYTES: i64 = 250 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 100;

/// A transport the session can drive: plain TCP, STARTTLS-wrapped, or
/// implicit TLS — boxed so the STARTTLS upgrade can swap it mid-session
/// (platform story 0.1: `sentin8::tls::RawTcpListener::upgrade_starttls`).
pub type BoxedStream = Box<dyn AsyncStream + Send + Unpin>;

/// Combined async read/write object trait for the boxed transport.
pub trait AsyncStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncStream for T {}

/// STARTTLS upgrade handle: wraps the current plain transport in TLS
/// in place. Built by the listener from the `sentin8-tls` acceptor
/// (SNI-aware PQ cert selection — no classical fallback).
#[derive(Clone)]
pub struct StartTlsUpgrader {
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
}

impl StartTlsUpgrader {
    pub fn new(acceptor: Arc<tokio_rustls::TlsAcceptor>) -> Self {
        Self { acceptor }
    }

    /// Wrap the plain stream. The caller has already replied `220
    /// Ready` and drained buffered plaintext (pipelining after STARTTLS
    /// is a protocol violation — rejected before this point).
    pub async fn upgrade(
        &self,
        plain: BoxedStream,
    ) -> Result<BoxedStream, String> {
        // rustls needs a concrete TcpStream for SNI; the boxed stream is
        // re-wrapped via the acceptor's generic `accept` on a shim.
        // tokio_rustls accepts any AsyncRead+AsyncWrite: use the
        // `TlsAcceptor::accept` on the boxed object.
        let tls = self
            .acceptor
            .accept(Shim(plain))
            .await
            .map_err(|e| format!("STARTTLS handshake: {e}"))?;
        Ok(Box::new(tls))
    }
}

/// Unwrap shim: rustls's acceptor needs ownership of the IO object;
/// the shim forwards the boxed stream through.
struct Shim(BoxedStream);

impl AsyncRead for Shim {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Shim {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// Session-level state machine (mta design §2.1).
pub struct Session {
    stream: BoxedStream,
    receiver: Receiver,
    config: Arc<MtaConfig>,
    queue: Arc<QueueWriter>,
    /// Read pool for tenant-scoped DKIM key lookups at queue time.
    pool: sqlx::PgPool,
    /// The service policy engine (step-5 gate; Phase 28).
    engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
    /// Tenant binding for unauthenticated (MX) traffic — resolved by the
    /// listener from SNI/destination domain; authenticated sessions use
    /// the token's env.
    env_id: Option<Uuid>,
    /// Remote client IP (for Received/SPF/iprev).
    client_ip: Option<std::net::IpAddr>,
    helo: Option<String>,
    authenticated: Option<SmtpAuth>,
    mail_from: Option<String>,
    rcpts: Vec<String>,
    bytes_left: i64,
    /// Terminal-chunk marker (BDAT LAST / plain DATA terminator).
    bdat_last: bool,
    /// Accumulated message body under DATA/BDAT.
    data_buffer: Vec<u8>,
    /// Valkey rate/greylist/fail2ban handles (None when Valkey is
    /// unavailable — the session degrades to no limits, design §6).
    limits: Option<crate::valkey_limits::ValkeyLimits>,
    /// STARTTLS upgrade handle (None on dev/plain listeners without
    /// platform TLS — the command then falls back to the ready-line
    /// acknowledgement).
    starttls: Option<StartTlsUpgrader>,
    /// Set once the transport is TLS (double-STARTTLS guard).
    starttls_taken: bool,
    /// Story 5.2 — per-env DNSBL zone cache (None disables the gate).
    dnsbl_zones: Option<Arc<crate::dnsbl_config::DnsblZoneCache>>,
}

impl Session {
    /// The STARTTLS transport swap (platform story 0.1): take the boxed
    /// plain stream, wrap it in place with the sentin8-tls acceptor.
    pub async fn swap_stream_tls(
        &mut self,
        upgrader: &StartTlsUpgrader,
    ) -> bool {
        let plain = std::mem::replace(
            &mut self.stream,
            Box::new(tokio::io::empty()) as BoxedStream,
        );
        match upgrader.upgrade(plain).await {
            Ok(tls) => {
                self.stream = tls;
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "email8:mta: STARTTLS handshake failed");
                false
            }
        }
    }
}

impl Session {
    pub fn new(
        stream: BoxedStream,
        config: Arc<MtaConfig>,
        queue: Arc<QueueWriter>,
        pool: sqlx::PgPool,
        engine: std::sync::Arc<sentin8::shield::PolicyEngine>,
        env_id: Option<Uuid>,
        client_ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            stream,
            receiver: Receiver::new(),
            config,
            queue,
            pool,
            engine,
            env_id,
            client_ip,
            helo: None,
            authenticated: None,
            mail_from: None,
            rcpts: Vec::new(),
            bytes_left: MAX_TRANSFER_BYTES,
            bdat_last: false,
            data_buffer: Vec::new(),
            dnsbl_zones: None,
            limits: None,
            starttls: None,
            starttls_taken: false,
        }
    }

    /// Attach the STARTTLS upgrade handle (listener wires the
    /// sentin8-tls acceptor; platform story 0.1).
    pub fn with_starttls(mut self, upgrader: Option<StartTlsUpgrader>) -> Self {
        self.starttls = upgrader;
        self
    }

    /// Attach Valkey limits (call once after construction; the
    /// listener connects lazily and passes the handle).
    pub fn with_limits(mut self, limits: Option<crate::valkey_limits::ValkeyLimits>) -> Self {
        self.limits = limits;
        self
    }

    /// Attach the per-env DNSBL zone cache (story 5.2).
    pub fn with_dnsbl_zones(
        mut self,
        cache: Arc<crate::dnsbl_config::DnsblZoneCache>,
    ) -> Self {
        self.dnsbl_zones = Some(cache);
        self
    }

    /// Run the session until QUIT, timeout, or socket close.
    /// Read + strip a leading PROXY v2 header from the stream, using
    /// the parsed source address as the session's client IP.
    async fn consume_proxy_v2(&mut self) -> Result<(), email8::gate::contracts::proxy_parse::ProxyV2Error> {
        use tokio::io::AsyncReadExt;
        let mut head = [0u8; 16];
        self.stream.read_exact(&mut head).await.map_err(|_| {
            email8::gate::contracts::proxy_parse::ProxyV2Error::Truncated {
                needed: 16,
                got: 0,
            }
        })?;
        // The length lives in bytes 14..16; read the address block.
        let addr_len = u16::from_be_bytes([head[14], head[15]]) as usize;
        let mut block = vec![0u8; addr_len];
        self.stream.read_exact(&mut block).await.map_err(|_| {
            email8::gate::contracts::proxy_parse::ProxyV2Error::Truncated {
                needed: addr_len,
                got: 0,
            }
        })?;
        let mut full = Vec::with_capacity(16 + addr_len);
        full.extend_from_slice(&head);
        full.extend_from_slice(&block);
        let (addrs, _len) = email8::gate::contracts::proxy_parse::parse_v2_header(&full)?;
        self.client_ip = Some(addrs.source.ip());
        tracing::debug!(client = %addrs.source, dst = %addrs.destination, "email8:mta: PROXY v2 consumed");
        Ok(())
    }

    pub async fn run(mut self) -> std::io::Result<()> {
        // PROXY protocol v2 (gate design §3.3, story 7.4): when the
        // listener accepted this session behind Email8:Gate, the gate
        // prepended a v2 header with the real client address. Consume it
        // before the banner; a malformed header is a desync — drop the
        // connection.
        if email8::gate::contracts::proxy_parse::accept_proxy_from_env("EMAIL8_MTA_ACCEPT_PROXY") {
            if let Err(e) = self.consume_proxy_v2().await {
                tracing::warn!(error = %e, "email8:mta: PROXY v2 parse failed — dropping");
                return Ok(());
            }
        }
        self.write_reply(Reply::new(220, format!("{} Email8 Mta at your service.", self.hostname())))
            .await?;
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(SESSION_TIMEOUT_SECS),
                self.stream.read(&mut buf),
            )
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "session timed out"))??;
            if n == 0 {
                return Ok(()); // client closed
            }
            for element in self.receiver.parse(&buf[..n]) {
                match element {
                    Element::Command(cmd) => {
                        if self.handle(cmd).await? {
                            self.write_reply(Reply::new(
                                221,
                                format!("{} closing connection", self.hostname()),
                            ))
                            .await?;
                            return Ok(());
                        }
                    }
                    Element::Invalid(_) => {
                        self.write_reply(Reply::new(500, "Command not recognized")).await?;
                    }
                    Element::DataChunk { data, last: _ } => {
                        // Terminal detection uses the session's bdat_last
                        // marker — the receiver strips the DATA terminator.
                        if let Some(reply) = self.accept_data(data).await? {
                            self.write_reply(reply).await?;
                        }
                    }
                }
            }
        }
    }

    /// Handle one command. Returns `true` when the session must QUIT.
    async fn handle(&mut self, cmd: Command) -> std::io::Result<bool> {
        match cmd {
            Command::Quit => return Ok(true),
            Command::Helo { host } => {
                self.helo = Some(host.clone());
                self.write_reply(Reply::new(250, format!("{host} at your service."))).await?;
            }
            Command::Ehlo { host } | Command::Lhlo { host } => {
                self.helo = Some(host);
                let caps = vec![
                    "8BITMIME".to_string(),
                    "SMTPUTF8".to_string(),
                    "PIPELINING".to_string(),
                    "CHUNKING".to_string(),
                    "DSN".to_string(),
                    "ENHANCEDSTATUSCODES".to_string(),
                    "AUTH XOAUTH2 OAUTHBEARER".to_string(),
                ];
                for line in email8::smtp_proto::ehlo(&self.hostname(), &caps) {
                    self.write_raw(&line).await?;
                }
            }
            Command::Auth { mechanism, initial } => {
                let reply = self.handle_auth(mechanism, initial).await;
                self.write_reply(reply).await?;
            }
            Command::MailFrom { address, .. } => {
                if self.helo.is_none() {
                    self.write_reply(email8::smtp_proto::need_ehlo()).await?;
                    return Ok(false);
                }
                // Sender rate limit (design §6 — fixed-window per env;
                // authenticated senders use their own namespace).
                if let (Some(limits), Some(env)) = (&self.limits, self.env_id) {
                    let kind = if self.authenticated.is_some() {
                        crate::valkey_limits::ThrottleKind::AuthenticatedAs
                    } else {
                        crate::valkey_limits::ThrottleKind::Sender
                    };
                    let key = address.clone().unwrap_or_default();
                    match limits
                        .rate_exceeded(&env, kind, &key, 100, std::time::Duration::from_secs(60))
                        .await
                    {
                        Ok(true) => {
                            crate::telemetry::audit(
                                &self.pool,
                                &env,
                                "email8_rate_limited",
                                "sender",
                                &key,
                                serde_json::json!({ "kind": "sender" }),
                            )
                            .await;
                            self.write_reply(email8::smtp_proto::rate_limited()).await?;
                            return Ok(false);
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "email8:mta: rate limiter unavailable — bypass");
                        }
                        _ => {}
                    }
                }
                self.mail_from = address;
                self.write_reply(Reply::enhanced(250, 2, 1, 0, "OK")).await?;
            }
            Command::RcptTo { address, .. } => {
                if self.mail_from.is_none() {
                    self.write_reply(Reply::new(503, "Need MAIL command before RCPT")).await?;
                    return Ok(false);
                }
                if self.rcpts.len() >= MAX_RECIPIENTS {
                    self.write_reply(email8::smtp_proto::too_many_recipients()).await?;
                    return Ok(false);
                }
                // Recipient throttle + greylisting (unauthenticated inbound
                // only — authenticated senders are trusted; design §P4.5).
                if let (Some(limits), Some(env), false) =
                    (&self.limits, self.env_id, self.authenticated.is_some())
                {
                    let ip = self
                        .client_ip
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    let sender = self.mail_from.clone().unwrap_or_default();
                    match limits
                        .rate_exceeded(
                            &env,
                            crate::valkey_limits::ThrottleKind::Rcpt,
                            &address,
                            200,
                            std::time::Duration::from_secs(60),
                        )
                        .await
                    {
                        Ok(true) => {
                            self.write_reply(email8::smtp_proto::rate_limited()).await?;
                            return Ok(false);
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "email8:mta: rcpt limiter unavailable")
                        }
                        _ => {}
                    }
                    match limits
                        .greylist_defer(&env, &ip, &sender, &address, std::time::Duration::from_secs(300))
                        .await
                    {
                        Ok(true) => {
                            // Greylisted: temp-fail with the classic 4xx — a
                            // legitimate sender retries and passes.
                            self.write_reply(Reply::enhanced(
                                450,
                                4,
                                2,
                                0,
                                "Greylisted, please retry",
                            ))
                            .await?;
                            return Ok(false);
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "email8:mta: greylist unavailable")
                        }
                        _ => {}
                    }
                }
                self.rcpts.push(address);
                self.write_reply(Reply::enhanced(250, 2, 1, 5, "OK")).await?;
            }
            Command::Data => {
                if self.mail_from.is_none() || self.rcpts.is_empty() {
                    self.write_reply(Reply::new(503, "Need RCPT command before DATA")).await?;
                    return Ok(false);
                }
                self.write_reply(Reply::new(354, "Start mail input; end with <CRLF>.<CRLF>")).await?;
                // Plain DATA (RFC 5321 §4.1.1.4): switch the receiver to
                // data mode — it accumulates dot-unstuffed body lines and
                // emits them as a DataChunk ending when the lone `.`
                // terminator is stripped. The session finalizes on that
                // final chunk (bdat_last marker).
                self.receiver.begin_data();
                self.bdat_last = true;
            }
            Command::Bdat { size, last } => {
                if self.mail_from.is_none() || self.rcpts.is_empty() {
                    self.write_reply(Reply::new(503, "Need RCPT command before BDAT")).await?;
                    return Ok(false);
                }
                if size as i64 > self.bytes_left {
                    self.write_reply(email8::smtp_proto::transfer_quota()).await?;
                    return Ok(false);
                }
                self.bdat_last = last;
            }
            Command::Reset => {
                self.mail_from = None;
                self.rcpts.clear();
                self.write_reply(Reply::new(250, "OK")).await?;
            }
            Command::Noop => self.write_reply(Reply::new(250, "OK")).await?,
            Command::Vrfy { .. } => {
                self.write_reply(Reply::new(252, "Cannot VRFY user, but will accept message and attempt delivery")).await?;
            }
            Command::StartTls => {
                // RFC 3207: reject double STARTTLS + require it before AUTH
                // (credentials must never cross plaintext).
                if self.starttls_taken {
                    self.write_reply(Reply::new(501, "TLS already active")).await?;
                    return Ok(false);
                }
                if self.authenticated.is_some() {
                    self.write_reply(Reply::new(501, "TLS already active")).await?;
                    return Ok(false);
                }
                self.write_reply(email8::smtp_proto::starttls_ready()).await?;
                let upgrader = self.starttls.clone();
                match upgrader {
                    Some(upgrader) => {
                        // Swap the transport: take the plain stream, wrap it
                        // in-place with the platform PQ-TLS acceptor.
                        if self.swap_stream_tls(&upgrader).await {
                            self.starttls_taken = true;
                            // RFC 3207 §4: the session state resets —
                            // EHLO must restart; MAIL/RCPT reset.
                            self.mail_from = None;
                            self.rcpts.clear();
                            self.helo = None;
                        } else {
                            tracing::warn!("email8:mta: STARTTLS requested but the transport cannot swap (generic session)");
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "STARTTLS requires a boxed transport",
                            ));
                        }
                    }
                    None => {
                        // No platform TLS handle (dev shell / plain HTTP
                        // listener): the ready line was sent; the client
                        // aborts. Log + close.
                        tracing::debug!("email8:mta: STARTTLS requested but no TLS handle wired");
                    }
                }
            }
            Command::Sasl { .. } | Command::Expn { .. } | Command::Help => {
                self.write_reply(Reply::new(502, "Command not implemented")).await?;
            }
        }
        Ok(false)
    }

    async fn handle_auth(&mut self, mechanism: String, initial: Option<String>) -> Reply {
        // Fail2ban strike + audit on every failure (design §6: 3 strikes
        // in 60s bans the IP for 1h).
        macro_rules! auth_fail {
            () => {{
                if let (Some(limits), Some(env)) = (&self.limits, &self.env_id) {
                    let ip = self
                        .client_ip
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    if let Ok(true) = limits
                        .fail2ban_strike(
                            env,
                            &ip,
                            3,
                            std::time::Duration::from_secs(60),
                            std::time::Duration::from_secs(3600),
                        )
                        .await
                    {
                        tracing::warn!(ip = %ip, "email8:mta: fail2ban ban triggered");
                    }
                    crate::telemetry::audit(
                        &self.pool,
                        env,
                        "email8_auth_failed",
                        "ip",
                        &ip,
                        serde_json::json!({ "mechanism": mechanism }),
                    )
                    .await;
                }
                email8::smtp_proto::auth_failed()
            }};
        }
        match mechanism.as_str() {
            "XOAUTH2" | "OAUTHBEARER" => {
                let Some(initial) = initial else {
                    return email8::smtp_proto::auth_continue("");
                };
                let Some(token) = crate::auth::decode_xoauth2(&initial) else {
                    return auth_fail!();
                };
                match crate::auth::verify_submission_token(&self.config, &self.engine, &token).await {
                    Ok(a) => {
                        self.authenticated = Some(a);
                        email8::smtp_proto::auth_success()
                    }
                    Err(_) => auth_fail!(),
                }
            }
            "PLAIN" => {
                let Some(initial) = initial else {
                    return email8::smtp_proto::auth_continue("");
                };
                let Ok(decoded) = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    initial.as_bytes(),
                ) else {
                    return auth_fail!();
                };
                let decoded = String::from_utf8_lossy(&decoded);
                let parts: Vec<&str> = decoded.split('\0').collect();
                if parts.len() < 3 {
                    return auth_fail!();
                }
                match crate::auth::bridge_plain(&self.config, &self.engine, parts[1], parts[2]).await {
                    Ok(a) => {
                        self.authenticated = Some(a);
                        email8::smtp_proto::auth_success()
                    }
                    Err(_) => auth_fail!(),
                }
            }
            _ => email8::smtp_proto::auth_mechanism_unknown(),
        }
    }

    /// Accumulate message bytes; finalize on the terminal chunk.
    async fn accept_data(&mut self, data: Vec<u8>) -> std::io::Result<Option<Reply>> {
        self.bytes_left -= data.len() as i64;
        self.data_buffer.extend_from_slice(&data);
        // The final chunk (DATA terminator or BDAT LAST) finalizes the
        // message. A data-mode terminator with an empty body still emits
        // one empty final DataChunk — which must finalize too.
        if self.bdat_last {
            self.bdat_last = false;
            let reply = self.finalize_message().await?;
            return Ok(Some(reply));
        }
        Ok(None)
    }

    /// Persist the collected message: inbound pipeline (SPF/DKIM/DMARC/
    /// spam gate/Received headers) → DKIM sign at queue time → blob →
    /// Storage, queue rows → DB — the single enqueue path shared with
    /// the JMAP submit API.
    async fn finalize_message(&mut self) -> std::io::Result<Reply> {
        let raw = std::mem::take(&mut self.data_buffer);
        let mail_from = self.mail_from.take().unwrap_or_default();
        let rcpts = std::mem::take(&mut self.rcpts);
        if raw.is_empty() || rcpts.is_empty() {
            return Ok(Reply::enhanced(554, 5, 6, 0, "Empty message"));
        }
        // Tenant env: AUTH binds it for submissions; inbound MX traffic
        // resolves it from the first local recipient's domain via the
        // `email8.domains` registry (multi-tenant MX — design §2.2).
        let env_id = match self
            .authenticated
            .as_ref()
            .map(|a| a.env_id)
            .or(self.env_id)
        {
            Some(env_id) => Some(env_id),
            None => {
                let mut conn = self.pool.acquire().await.map_err(|e| {
                    std::io::Error::other(format!("pool: {e}"))
                })?;
                let mut found: Option<Uuid> = None;
                for rcpt in &rcpts {
                    let domain = rcpt
                        .rsplit_once('@')
                        .map(|(_, d)| d.to_ascii_lowercase())
                        .unwrap_or_default();
                    if domain.is_empty() {
                        continue;
                    }
                    let hit: Option<Uuid> = sqlx::query_scalar(
                        "SELECT env_id FROM email8.domains \
                         WHERE lower(name) = $1 AND is_enabled",
                    )
                    .bind(&domain)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(|e| std::io::Error::other(format!("domains: {e}")))?;
                    if hit.is_some() {
                        found = hit;
                        break;
                    }
                }
                found
            }
        };
        let Some(env_id) = env_id else {
            return Ok(email8::smtp_proto::auth_required());
        };
        let authenticated = self.authenticated.is_some();

        // Inbound pipeline (design §2.2): auth results, spam gate,
        // Received/Return-Path headers. Authenticated submissions skip
        // SPF/DMARC evaluation (we issued them).
        let resolver = crate::resolver::Resolver::from_env();
        let client_ip = self.client_ip.unwrap_or_else(|| {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        });
        let helo = self.helo.clone().unwrap_or_default();
        // Story 5.2 — resolve the tenant env (AUTH token or the MX
        // recipient domain) and load its configured DNSBL zones.
        let from_domain = mail_from
            .rsplit_once('@')
            .map(|(_, d)| d.to_ascii_lowercase());
        let reply_to_domain = None; // parsed from headers in pipeline P2
        // Story 5.2 — resolve the tenant env (AUTH token or the MX
        // recipient domain) and load its configured DNSBL zones. The
        // zone Vec lives to the end of the function (the gate borrows it).
        let dnsbl_zones = match (self.dnsbl_zones.clone(), self.env_id) {
            (Some(cache), Some(env_id)) if self.authenticated.is_none() => {
                Some(cache.zones_for(env_id).await)
            }
            _ => None,
        };
        let dnsbl_gate = dnsbl_zones
            .as_deref()
            .filter(|z| !z.is_empty())
            .map(|zones| crate::pipeline::DnsblGate {
                zones,
                resolver: &resolver,
                elements: email8::spam::DnsblElements {
                    ip: vec![client_ip.to_string()],
                    helo: (!helo.is_empty()).then(|| helo.clone()),
                    from_domain: from_domain.clone(),
                    to_domains: rcpts.iter().filter_map(|r| r.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase())).collect(),
                    reply_to_domain,
                    urls: Vec::new(), // URL scopes are filled by the body scan at P2
                },
            });
        let input = crate::pipeline::PipelineInput {
            client_ip,
            helo_domain: &helo,
            mail_from: &mail_from,
            rcpt_addresses: &rcpts,
            raw: &raw,
            authenticated,
            hostname: &self.hostname(),
            dnsbl: dnsbl_gate,
        };
        let out = crate::pipeline::process(&resolver, None, &input).await;
        if let Some(reject) = out.reject {
            tracing::info!("email8:mta: pipeline rejected message");
            return Ok(Reply::new(550, reject));
        }
        let mut processed = out.raw;

        // DMARC aggregate recording (RFC 7489 §7.2) + inbound external
        // report classification (DMARC rua / TLS-RPT / ARF) — inbound
        // MX traffic only; authenticated submissions are our own mail.
        if !authenticated {
            let from_domain = mail_from
                .rsplit('@')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            crate::reports::record_dmarc_result(
                &self.pool,
                &env_id,
                &from_domain,
                matches!(out.spf, email8::mail_auth::SpfResult::Pass),
                out.dmarc.dkim_aligned.is_some(),
                &format!("{:?}", out.dmarc.disposition).to_ascii_lowercase(),
            )
            .await;
            crate::reports::record_external_report(&self.pool, &env_id, &raw, &mail_from).await;
        }

        // DKIM sign at queue time (active keys for the signing domain —
        // the envelope domain; authenticated senders sign their own mail).
        let signing_domain = mail_from
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !signing_domain.is_empty() {
            if let Ok(mut conn) = self.pool.acquire().await {
                let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                    .bind(env_id)
                    .execute(&mut *conn)
                    .await;
                if let Ok(signers) =
                    crate::dkim_manager::load_active_signers(&mut conn, env_id).await
                {
                    let blocks =
                        crate::dkim_manager::sign_message(&signers, &signing_domain, &processed);
                    for b in blocks {
                        let header_text = b.trim_end_matches("\r\n").to_string();
                        let header_line = format!("{header_text}\r\n");
                        let sep = memchr::memmem::find(&processed, b"\r\n\r\n")
                            .map(|p| p + 2)
                            .unwrap_or(processed.len());
                        let mut signed = Vec::with_capacity(header_line.len() + processed.len());
                        signed.extend_from_slice(&processed[..sep]);
                        signed.extend_from_slice(header_line.as_bytes());
                        signed.extend_from_slice(&processed[sep..]);
                        processed = signed;
                    }
                }
            }
        }

        // Per-recipient spam score rides the queue row (design §2.2 — the
        // Store's ingest applies junk re-file at ≥50 for local delivery).
        let spam_pct = (!authenticated).then_some(out.spam.score_pct as f32);
        match self
            .queue
            .enqueue_with_spam(&env_id, &mail_from, &rcpts, &processed, authenticated, spam_pct)
            .await
        {
            Ok(queue_id) => {
                tracing::info!(queue = %queue_id, rcpts = rcpts.len(), "email8:mta: message accepted");
                Ok(Reply::new(250, format!("Message accepted for delivery (queue {queue_id})")))
            }
            Err(e) => {
                tracing::warn!(error = %e, "email8:mta: enqueue failed");
                Ok(email8::smtp_proto::queue_full())
            }
        }
    }

    fn hostname(&self) -> String {
        std::env::var("EMAIL8_MTA_HOSTNAME").unwrap_or_else(|_| "mail.local".to_string())
    }

    async fn write_reply(&mut self, reply: Reply) -> std::io::Result<()> {
        self.write_raw(&reply.to_wire()).await
    }

    async fn write_raw(&mut self, s: &str) -> std::io::Result<()> {
        self.stream.write_all(s.as_bytes()).await
    }
}