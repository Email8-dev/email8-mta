// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Milter client (protocol v2/v6) + MTA HTTP hooks (JSON contract) —
//! story 4.11, design §2.2 stage chain.
//!
//! The legacy milter protocol is a length-prefixed macro/command
//! exchange over a socket: the MTA sends SMFIC_* commands per stage
//! with macros, the milter responds SMFIR_* (continue / reject /
//! tempfail / discard / add-header …). This module implements the
//! client side — connect, negotiate options, run the stage chain,
//! apply responses.
//!
//! HTTP hooks (the `http` hook_kind rows in `mta_hooks`) use a
//! simpler JSON contract: `{stage, env_id, message: {headers,
//! blob_hash, size, envelope}}` → `{action: continue|reject|discard|
//! tempfail|add_header, reason?, header?}`.

use std::sync::Arc;

use uuid::Uuid;

use crate::config::MtaConfig;

// ── Milter wire protocol (sendmail 8 milter v2/v6) ──────────────────────

/// Milter command codes (SMFIC_*) — the subset the client sends.
mod smfic {
    pub const BODY: u8 = b'B'; // SMFIC_BODY
    pub const CONNECT: u8 = b'C'; // SMFIC_CONNECT
    pub const BODYEOB: u8 = b'E'; // SMFIC_BODYEOB
    pub const ENVFROM: u8 = b'M'; // SMFIC_MAILFROM
    pub const ENVRCPT: u8 = b'R'; // SMFIC_RCPTTO
    pub const HEADER: u8 = b'L'; // SMFIC_HEADER
    pub const HELO: u8 = b'H'; // SMFIC_HELO
    pub const QUIT: u8 = b'Q'; // SMFIC_QUIT
    pub const NEGOTIATE: u8 = b'O'; // SMFIC_OPTNEG
}

/// Milter response codes (SMFIR_*).
mod smfir {
    pub const CONTINUE: u8 = b'c'; // SMFIR_CONTINUE
    pub const REJECT: u8 = b'r'; // SMFIR_REJECT
    pub const DISCARD: u8 = b'd'; // SMFIR_DISCARD
    pub const TEMPFAIL: u8 = b't'; // SMFIR_TEMPFAIL
    pub const ADDHEADER: u8 = b'h'; // SMFIR_ADDHEADER
    pub const QUARANTINE: u8 = b'q'; // SMFIR_QUARANTINE
}

/// One milter endpoint as configured in `mta_hooks` (target =
/// `host:port`).
#[derive(Debug, Clone)]
pub struct MilterHook {
    pub name: String,
    pub stage_filter: Vec<String>, // empty = all stages
    pub target: String,
}

/// The response from one milter stage exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MilterAction {
    Continue,
    Reject(String),
    TempFail(String),
    Discard,
    AddHeader { name: String, value: String },
}

/// Negotiate + run the full stage chain against one milter. The
/// simplified v2 exchange: OPTNEG → CONNECT → HELO → MAIL → RCPT* →
/// DATA → headers → EOB, each answered Continue or a terminal action.
pub async fn run_milter(
    hook: &MilterHook,
    client_ip: &str,
    helo: &str,
    mail_from: &str,
    rcpts: &[String],
    headers: &[(String, String)],
    body: &[u8],
) -> Result<MilterAction, String> {
    let mut sock = tokio::net::TcpStream::connect(&hook.target)
        .await
        .map_err(|e| e.to_string())?;
    use tokio::io::AsyncWriteExt;

    // OPTNEG: version 6, actions (ADDHDRS|DISCARD), protocol steps 0.
    let mut sock = {
        let mut buf = Vec::new();
        buf.push(smfic::NEGOTIATE);
        buf.extend_from_slice(&6u32.to_be_bytes());
        buf.extend_from_slice(&0x00000004u32.to_be_bytes()); // ADDHDRS|DISCARD
        buf.extend_from_slice(&0x00000001u32.to_be_bytes()); // CONNECT only
        sock.write_all(&(buf.len() as u32).to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        sock.write_all(&buf).await.map_err(|e| e.to_string())?;
        let reply = read_packet(&mut sock).await?;
        if reply.is_empty() || reply[0] != smfir::CONTINUE {
            return Err("milter optneg rejected".into());
        }
        sock
    };

    // CONNECT (ip).
    let mut buf = Vec::new();
    buf.push(smfic::CONNECT);
    buf.extend_from_slice(client_ip.as_bytes());
    buf.push(0);
    let action = exchange(&mut sock, buf).await?;
    match action {
        MilterAction::Continue => {}
        other => {
            quit(&mut sock).await;
            return Ok(other);
        }
    }

    // HELO.
    let mut buf = Vec::new();
    buf.push(smfic::HELO);
    buf.extend_from_slice(helo.as_bytes());
    buf.push(0);
    let action = exchange(&mut sock, buf).await?;
    match action {
        MilterAction::Continue => {}
        other => {
            quit(&mut sock).await;
            return Ok(other);
        }
    }

    // MAIL FROM.
    let mut buf = Vec::new();
    buf.push(smfic::ENVFROM);
    buf.extend_from_slice(mail_from.as_bytes());
    buf.push(0);
    let action = exchange(&mut sock, buf).await?;
    match action {
        MilterAction::Continue => {}
        other => {
            quit(&mut sock).await;
            return Ok(other);
        }
    }

    // RCPT TO (each recipient).
    for r in rcpts {
        let mut buf = Vec::new();
        buf.push(smfic::ENVRCPT);
        buf.extend_from_slice(r.as_bytes());
        buf.push(0);
        let action = exchange(&mut sock, buf).await?;
        match action {
            MilterAction::Continue => {}
            other => {
                quit(&mut sock).await;
                return Ok(other);
            }
        }
    }

    // HEADERS.
    for (name, value) in headers {
        let mut buf = Vec::new();
        buf.push(smfic::HEADER);
        buf.extend_from_slice(name.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
        let action = exchange(&mut sock, buf).await?;
        match action {
            MilterAction::Continue => {}
            other => {
                quit(&mut sock).await;
                return Ok(other);
            }
        }
    }

    // BODY (chunked ≤64KB) + EOB.
    for chunk in body.chunks(64 * 1024) {
        let mut buf = Vec::new();
        buf.push(smfic::BODY);
        buf.extend_from_slice(chunk);
        let action = exchange(&mut sock, buf).await?;
        match action {
            MilterAction::Continue => {}
            other => {
                quit(&mut sock).await;
                return Ok(other);
            }
        }
    }
    let mut buf = Vec::new();
    buf.push(smfic::BODYEOB);
    let action = exchange(&mut sock, buf).await?;
    quit(&mut sock).await;
    Ok(action)
}

/// Read one milter packet (4-byte BE length + payload).
async fn read_packet(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf)
}

/// One command → response exchange.
async fn exchange(
    sock: &mut tokio::net::TcpStream,
    mut cmd: Vec<u8>,
) -> Result<MilterAction, String> {
    use tokio::io::AsyncWriteExt;
    sock.write_all(&(cmd.len() as u32).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    sock.write_all(&cmd).await.map_err(|e| e.to_string())?;
    cmd.clear();
    let reply = read_packet(sock).await?;
    parse_response(&reply)
}

fn parse_response(reply: &[u8]) -> Result<MilterAction, String> {
    let Some(&code) = reply.first() else {
        return Ok(MilterAction::Continue);
    };
    let rest = &reply[1..];
    let cstr = |b: &[u8]| {
        String::from_utf8_lossy(b)
            .trim_end_matches('\0')
            .to_string()
    };
    Ok(match code {
        smfir::CONTINUE => MilterAction::Continue,
        smfir::REJECT => MilterAction::Reject(cstr(rest)),
        smfir::TEMPFAIL => MilterAction::TempFail(cstr(rest)),
        smfir::DISCARD => MilterAction::Discard,
        smfir::ADDHEADER => {
            // name\0value\0
            let split = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let name = cstr(&rest[..split]);
            let value = cstr(rest.get(split + 1..).unwrap_or(&[]));
            MilterAction::AddHeader { name, value }
        }
        smfir::QUARANTINE => MilterAction::TempFail("quarantined".into()),
        other => return Err(format!("unknown milter response 0x{other:02x}")),
    })
}

async fn quit(sock: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncWriteExt;
    let cmd = vec![smfic::QUIT];
    let _ = sock.write_all(&(cmd.len() as u32).to_be_bytes()).await;
    let _ = sock.write_all(&cmd).await;
}

// ── HTTP hooks (JSON contract) ──────────────────────────────────────────

/// One HTTP hook as configured in `mta_hooks` (target = URL).
#[derive(Debug, Clone)]
pub struct HttpHook {
    pub name: String,
    pub stage: String, // connect|ehlo|mail|rcpt|data
    pub target: String,
    pub is_enabled: bool,
}

/// Run every enabled HTTP hook for a stage. First non-continue wins
/// (reject beats tempfail beats add_header).
pub async fn run_http_hooks(
    hooks: &[HttpHook],
    stage: &str,
    env_id: &Uuid,
    envelope: &serde_json::Value,
) -> Result<MilterAction, String> {
    let mut outcome = MilterAction::Continue;
    for hook in hooks.iter().filter(|h| h.is_enabled && h.stage == stage) {
        let client = reqwest::Client::new();
        let body = serde_json::json!({
            "stage": stage,
            "env_id": env_id,
            "envelope": envelope,
        });
        let resp = client
            .post(&hook.target)
            .timeout(std::time::Duration::from_secs(5))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("hook {}: {e}", hook.name))?;
        let verdict: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("hook {}: {e}", hook.name))?;
        let action = verdict
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("continue");
        let reason = verdict
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let this = match action {
            "reject" => MilterAction::Reject(reason),
            "tempfail" => MilterAction::TempFail(reason),
            "discard" => MilterAction::Discard,
            "add_header" => MilterAction::AddHeader {
                name: verdict
                    .get("header")
                    .and_then(|h| h.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("X-Hook")
                    .into(),
                value: verdict
                    .get("header")
                    .and_then(|h| h.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .into(),
            },
            _ => MilterAction::Continue,
        };
        outcome = combine(outcome, this);
        if matches!(outcome, MilterAction::Reject(_) | MilterAction::Discard) {
            break; // terminal — no further hooks
        }
    }
    Ok(outcome)
}

/// Precedence: Reject > Discard > TempFail > AddHeader > Continue.
fn combine(a: MilterAction, b: MilterAction) -> MilterAction {
    let rank = |a: &MilterAction| match a {
        MilterAction::Continue => 0,
        MilterAction::AddHeader { .. } => 1,
        MilterAction::TempFail(_) => 2,
        MilterAction::Discard => 3,
        MilterAction::Reject(_) => 4,
    };
    // Keep whichever side has the higher precedence; ties keep `a`.
    match rank(&a).cmp(&rank(&b)) {
        std::cmp::Ordering::Less => b,
        _ => a,
    }
}

/// Load the configured hooks for an env from `mta_hooks`.
pub async fn load_hooks(
    pool: &sqlx::PgPool,
    env_id: &Uuid,
) -> Result<(Vec<MilterHook>, Vec<HttpHook>), String> {
    use sqlx::Row;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(pool)
        .await;
    let rows = sqlx::query(
        "SELECT stage, hook_kind, target, is_enabled, config \
         FROM email8.mta_hooks WHERE env_id = $1",
    )
    .bind(env_id)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    let mut milters = Vec::new();
    let mut http = Vec::new();
    for r in rows {
        let stage: String = r.get("stage");
        let kind: String = r.get("hook_kind");
        let target: String = r.get("target");
        let enabled: bool = r.get("is_enabled");
        let config: serde_json::Value = r.get("config");
        if kind == "milter" && enabled {
            milters.push(MilterHook {
                name: format!("{stage}-milter"),
                stage_filter: config
                    .get("stages")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                target,
            });
        } else if kind == "http" {
            http.push(HttpHook {
                name: format!("{stage}-http"),
                stage,
                target,
                is_enabled: enabled,
            });
        }
    }
    Ok((milters, http))
}

// The config is unused by the helpers today; the state wires it at
// startup. Silence the unused warning without dead_code noise.
#[allow(unused)]
fn _config_marker(_c: &Arc<MtaConfig>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_parsing() {
        assert_eq!(parse_response(b"c").unwrap(), MilterAction::Continue);
        assert_eq!(
            parse_response(b"rnope\0").unwrap(),
            MilterAction::Reject("nope".into())
        );
        assert_eq!(
            parse_response(b"tbusy\0").unwrap(),
            MilterAction::TempFail("busy".into())
        );
        assert_eq!(parse_response(b"d").unwrap(), MilterAction::Discard);
        assert_eq!(
            parse_response(b"hX-Custom\0yes\0").unwrap(),
            MilterAction::AddHeader {
                name: "X-Custom".into(),
                value: "yes".into()
            }
        );
    }

    #[test]
    fn combine_precedence() {
        let c = MilterAction::Continue;
        assert!(matches!(
            combine(c.clone(), MilterAction::Reject("x".into())),
            MilterAction::Reject(_)
        ));
        assert!(matches!(
            combine(MilterAction::Discard, c.clone()),
            MilterAction::Discard
        ));
        assert!(matches!(
            combine(
                MilterAction::TempFail("t".into()),
                MilterAction::AddHeader {
                    name: "a".into(),
                    value: "b".into()
                }
            ),
            MilterAction::TempFail(_)
        ));
    }
}
