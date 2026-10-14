// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Inbound message pipeline (design §2.2) — the end-of-DATA processing
//! shared by the SMTP session and the internal submit path:
//!
//! Received-loop guard → DKIM verify → Authentication-Results build →
//! DMARC evaluate → spam gate (unauthenticated only) → header
//! completion → DKIM sign (at queue time) → enqueue.
//!
//! The session calls `process()` and gets back either the queue-bound
//! bytes or a protocol-level rejection.

use email8::mail_auth::{
    build_results, dkim_verify, dmarc_evaluate, dmarc_lookup, received_spf, spf_check, DmarcResult,
    SpfParams, SpfResult,
};
use email8::spam::{check_dnsbl, DnsblElements, DnsblResolver, DnsblZone};
use email8::spam::{
    evaluate_tags, scan_urls, SpamReport, SpamVerdict, TagSet, TagThresholds, UrlFindings,
};

/// Pipeline inputs from the SMTP session.
pub struct PipelineInput<'a> {
    pub client_ip: std::net::IpAddr,
    pub helo_domain: &'a str,
    pub mail_from: &'a str,
    pub rcpt_addresses: &'a [String],
    pub raw: &'a [u8],
    /// Whether the session authenticated (spam gate is skipped).
    pub authenticated: bool,
    /// Our hostname for Received/AR authserv-id.
    pub hostname: &'a str,
    /// DNSBL zones + resolver for the spam gate (None → skip DNSBL
    /// checks; design §P4.2).
    pub dnsbl: Option<DnsblGate<'a>>,
}

/// The DNSBL side of the gate (zones + resolver + the message's
/// element set).
pub struct DnsblGate<'a> {
    pub zones: &'a [DnsblZone],
    pub resolver: &'a dyn DnsblResolver,
    pub elements: DnsblElements,
}

/// The pipeline outcome.
pub struct PipelineOutput {
    /// The message bytes with prepended headers (Received, Return-Path,
    /// Authentication-Results, Received-SPF, X-Spam-*) ready for queueing.
    pub raw: Vec<u8>,
    pub spf: SpfResult,
    pub dmarc: DmarcResult,
    pub spam: SpamReport,
    /// Set when the message must be refused at the protocol level.
    pub reject: Option<String>,
}

/// Run the pipeline. `dns` injects the resolver; `thresholds` the env
/// spam policy (None → skip the tag gate but still report).
pub async fn process(
    dns: &dyn email8::mail_auth::DnsTxt,
    thresholds: Option<&TagThresholds>,
    input: &PipelineInput<'_>,
) -> PipelineOutput {
    let parsed = email8::mail_core::ParsedMessage::parse(input.raw).unwrap_or_default();
    let from_domain = parsed
        .from_address()
        .and_then(|a| a.rsplit_once('@').map(|(_, d)| d.to_string()))
        .unwrap_or_default();

    // 1. SPF (HELO identity for null senders).
    let spf = spf_check(
        dns,
        &SpfParams {
            client_ip: input.client_ip,
            helo_domain: input.helo_domain.to_string(),
            sender: input.mail_from.to_string(),
        },
    )
    .await;

    // 2. DKIM verify.
    let dkim = dkim_verify(dns, input.raw).await;

    // 3. DMARC.
    let policy = if from_domain.is_empty() {
        None
    } else {
        dmarc_lookup(dns, &from_domain).await
    };
    let dmarc = dmarc_evaluate(policy, &from_domain, &spf, &dkim.results);

    // 4. Authentication-Results + Received-SPF.
    let ar = build_results(input.hostname, &spf, &from_domain, &dkim.results, &dmarc);
    let mut prepend = ar.render(input.hostname);
    prepend.push_str(&received_spf(
        &spf,
        &format!("{} client-ip={}", input.helo_domain, input.client_ip),
    ));

    // 5. Spam gate (unauthenticated sessions only).
    let mut tags: Vec<TagSet> = Vec::new();
    let mut urls = UrlFindings {
        urls: vec![],
        ip_literal: false,
        zero_width: false,
        mixed_script: false,
        homograph: false,
    };
    if !input.authenticated {
        let body_text =
            String::from_utf8_lossy(&input.raw[input.raw.len().min(raw_body_offset(input.raw))..])
                .to_string();
        urls = scan_urls(&body_text);
        if urls.ip_literal {
            tags.push(TagSet::Url);
        }
        if urls.zero_width || urls.mixed_script || urls.homograph {
            tags.push(TagSet::Url);
        }
        if matches!(
            dmarc.disposition,
            email8::mail_auth::DmarcDisposition::Reject
                | email8::mail_auth::DmarcDisposition::Quarantine
        ) {
            tags.push(TagSet::Dmarc);
        }
        // Message-ID presence heuristic.
        if parsed.message_id().is_none() && !input.authenticated {
            tags.push(TagSet::MessageId);
        }
        // DNSBL stage (design §P4.2): any hit fires the Dnsbl tag.
        if let Some(gate) = &input.dnsbl {
            let hits = check_dnsbl(gate.zones, &gate.elements, gate.resolver).await;
            if !hits.is_empty() {
                tags.push(TagSet::Dnsbl);
                tracing::info!(
                    zones = ?email8::spam::dnsbl::hits_by_zone(&hits),
                    "email8:mta: dnsbl hit"
                );
            }
        }
    }
    let (verdict, outcomes) = match thresholds {
        Some(t) => evaluate_tags(&tags, t),
        None => (SpamVerdict::Allow, vec![]),
    };
    let spam = SpamReport {
        verdict,
        score_pct: outcomes
            .iter()
            .map(|o| o.weight as u32)
            .sum::<u32>()
            .min(100) as u8,
        tags: outcomes,
        urls: vec![urls],
        model_pct: None,
    };
    if !input.authenticated {
        prepend.push_str(&format!("X-Spam-Status: {}\r\n", spam.status_header()));
        prepend.push_str(&format!("X-Spam-Score: {}\r\n", spam.score_header()));
        prepend.push_str(&format!("X-Spam-Result: {}\r\n", spam.result_header()));
    }

    // 6. Protocol-level reject (DMARC p=reject strict mode or spam
    // threshold Reject).
    let reject = if spam.verdict == SpamVerdict::Reject {
        Some("550 5.7.1 spam policy rejected this message".to_string())
    } else if matches!(
        dmarc.disposition,
        email8::mail_auth::DmarcDisposition::Reject
    ) && !input.authenticated
    {
        Some("550 5.7.1 DMARC policy (p=reject)".to_string())
    } else {
        None
    };

    // 7. Received header (our hop) + Return-Path.
    let received = format!(
        "Received: from {helo} ([{ip}])\r\n\tby {host} with ESMTP;\r\n\t{date}\r\n",
        helo = input.helo_domain,
        ip = input.client_ip,
        host = input.hostname,
        date = chrono::Utc::now().to_rfc2822(),
    );
    let return_path = format!("Return-Path: <{}>\r\n", input.mail_from);

    let raw = Vec::from(input.raw);
    let mut out =
        Vec::with_capacity(prepend.len() + received.len() + return_path.len() + raw.len());
    out.extend_from_slice(received.as_bytes());
    out.extend_from_slice(return_path.as_bytes());
    out.extend_from_slice(prepend.as_bytes());
    out.extend_from_slice(&raw);

    PipelineOutput {
        raw: out,
        spf,
        dmarc,
        spam,
        reject,
    }
}

fn raw_body_offset(raw: &[u8]) -> usize {
    memchr::memmem::find(raw, b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(raw.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use email8::mail_auth::FnDnsTxt;

    const RAW: &[u8] = b"From: alice@football.example.com\r\nTo: bob@example.net\r\nSubject: Hello\r\nDate: Sat, 07 Feb 2026 10:00:00 +0000\r\nMessage-ID: <q1@football.example.com>\r\n\r\nBuy widgets now!\r\n";

    #[tokio::test]
    async fn pipeline_headers_and_allow() {
        // SPF pass + DMARC none.
        let dns = FnDnsTxt(|name: &str| match name {
            "football.example.com" => Ok(vec!["v=spf1 +all".into()]),
            _ => Err("nx".into()),
        });
        let out = process(
            &dns,
            Some(&TagThresholds::default()),
            &PipelineInput {
                client_ip: "192.0.2.7".parse().unwrap(),
                helo_domain: "mail.example.com",
                mail_from: "alice@football.example.com",
                rcpt_addresses: &["bob@example.net".to_string()],
                raw: RAW,
                authenticated: false,
                hostname: "mx.example.net",
                dnsbl: None,
            },
        )
        .await;
        let text = String::from_utf8_lossy(&out.raw);
        assert!(text.contains("Received: from mail.example.com"));
        assert!(text.contains("Return-Path: <alice@football.example.com>"));
        assert!(text.contains("Authentication-Results: mx.example.net"));
        assert!(text.contains("spf=pass"));
        assert!(text.contains("Received-SPF: pass"));
        assert!(text.contains("X-Spam-Result: Allow"));
        assert!(out.reject.is_none());
    }

    #[tokio::test]
    async fn authenticated_skips_spam_gate() {
        let dns = FnDnsTxt(|_: &str| Err("nx".into()));
        let out = process(
            &dns,
            Some(&TagThresholds::default()),
            &PipelineInput {
                client_ip: "192.0.2.7".parse().unwrap(),
                helo_domain: "h",
                mail_from: "a@b.c",
                rcpt_addresses: &[],
                raw: RAW,
                authenticated: true,
                hostname: "mx.example.net",
                dnsbl: None,
            },
        )
        .await;
        let text = String::from_utf8_lossy(&out.raw);
        assert!(!text.contains("X-Spam-Status"));
        assert!(out.reject.is_none());
    }

    #[tokio::test]
    async fn spam_trap_rejects() {
        let dns = FnDnsTxt(|_: &str| Err("nx".into()));
        let mut t = TagThresholds::default();
        // Force the URL tag to reject-level weight.
        t.tag_weights.insert("url".into(), 100);
        // Body with IP-literal URL.
        let raw =
            b"From: a@b.c\r\nSubject: s\r\nMessage-ID: <m@x>\r\n\r\nVisit http://192.0.2.9/x\r\n";
        let out = process(
            &dns,
            Some(&t),
            &PipelineInput {
                client_ip: "192.0.2.7".parse().unwrap(),
                helo_domain: "h",
                mail_from: "a@b.c",
                rcpt_addresses: &[],
                raw,
                authenticated: false,
                hostname: "mx.example.net",
                dnsbl: None,
            },
        )
        .await;
        assert!(out.reject.is_some(), "expected protocol reject");
        assert_eq!(out.spam.verdict, SpamVerdict::Reject);
    }
}
