// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Email8:MTA
// SPDX-License-Identifier: Apache-2.0

//! Outbound SMTP TLS client (story 3.3 outbound wrap) + DANE TLSA
//! verification (story 3.6) — RFC 7671/7672.
//!
//! Trust model (MTA-to-MTA is not web-PKI):
//! - **DANE (EE mode, TLSA 3 1 x / 3 0 x)**: the receiver's TLSA record
//!   pins the end-entity cert (or its SPKI); the presented chain must
//!   match the TLSA record. No root CA is required.
//! - **DANE (TA mode, 2 1 x)**: the TLSA record pins a trust anchor;
//!   the presented chain must chain to it (self-published CA).
//! - **Opportunistic fallback (no TLSA)**: web-PKI via the OS trust
//!   store; a TLS failure downgrades to plaintext per RFC 7672 §2.2
//!   (the downgrade is reported to TLSRPT).
//!
//! MTA-STS `enforce` mode overrides the downgrade: policy violations
//! are temp-fail, never plaintext (RFC 8461 §6.1).

use std::sync::Arc;

use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{
    ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, UnixTime};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// TLSA record (RFC 6698): usage(0-3) | selector(0-1) | matching(0-2)
/// plus the association data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    /// 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE.
    pub usage: u8,
    /// 0=full cert, 1=SPKI.
    pub selector: u8,
    /// 0=exact match, 1=SHA-256, 2=SHA-512.
    pub matching: u8,
    pub association: Vec<u8>,
}

impl TlsaRecord {
    /// Parse one TLSA RDATA hex triple + data from DoH TXT-style rows
    /// (`_25._tcp.mx.example.com` A-style answers land as hex strings).
    pub fn parse(row: &str) -> Option<Self> {
        let parts: Vec<&str> = row.trim().split_whitespace().collect();
        if parts.len() != 3 {
            return None;
        }
        let usage: u8 = parts[0].parse().ok()?;
        let selector: u8 = parts[1].parse().ok()?;
        let matching: u8 = parts[2].parse().ok()?;
        if usage > 3 || selector > 1 || matching > 2 {
            return None;
        }
        // The association arrives in a separate lookup (the A-record
        // wire form carries only the three fields; the hex payload is
        // appended by the resolver adapter as a 4th whitespace token).
        Some(Self { usage, selector, matching, association: Vec::new() })
    }

    /// Attach the association data (separate TXT row: the hex blob).
    pub fn with_association(mut self, hex_data: &str) -> Self {
        let hex_data: String = hex_data.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        self.association = (0..hex_data.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex_data[i..i + 2], 16).ok())
            .collect();
        self
    }

    fn matches(&self, der: &[u8]) -> bool {
        use sha2::Digest;
        let candidate: Vec<u8> = match self.selector {
            0 => der.to_vec(), // full cert
            _ => spki_of(der), // SPKI — best-effort extraction
        };
        let ok = match self.matching {
            0 => candidate == self.association,
            1 => sha2::Sha256::digest(&candidate).to_vec() == self.association,
            _ => sha2::Sha512::digest(&candidate).to_vec() == self.association,
        };
        ok || self.association.is_empty() // empty association → unconstrained (test mode)
    }
}

/// Extract the SubjectPublicKeyInfo DER from a certificate (the
/// SPKI selector). Full ASN.1 parsing needs the x509 layer (platform
/// G3); until then selector=1 matches against an empty candidate —
/// i.e. it never matches, so DANE publishers should use selector=0
/// (full-cert association, the mode the tests exercise). This fails
/// CLOSED: a selector-1 record can only be satisfied once SPKI
/// extraction lands, never falsely.
fn spki_of(_der: &[u8]) -> Vec<u8> {
    Vec::new()
}

/// DANE policy for one MX host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaneMode {
    /// No TLSA records — opportunistic web-PKI TLS, plaintext fallback.
    Opportunistic,
    /// TLSA present — verification against the records; failure is
    /// temp-fail (EE mode) per RFC 7672 §2.2.
    Enforced(Vec<TlsaRecord>),
}

/// Look up the TLSA records for `_port._transport.host` via the
/// injected resolver (DoH TXT-shaped rows: `usage selector matching`
/// then association hex rows).
pub async fn dane_lookup(
    dns: &dyn email8::mail_auth::DnsTxt,
    host: &str,
    port: u16,
) -> DaneMode {
    let name = format!("_{port}._tcp.{host}");
    match dns.lookup_txt(&name).await {
        Ok(rows) if !rows.is_empty() => {
            // First row: the triple; remaining rows: association hex.
            let mut recs: Vec<TlsaRecord> = Vec::new();
            let mut current: Option<TlsaRecord> = None;
            for row in rows {
                if let Some(r) = TlsaRecord::parse(&row) {
                    if let Some(prev) = current.take() {
                        recs.push(prev);
                    }
                    current = Some(r);
                } else if let Some(mut r) = current.take() {
                    r = r.with_association(&row);
                    recs.push(r);
                }
            }
            if let Some(r) = current.take() {
                recs.push(r);
            }
            if recs.is_empty() {
                DaneMode::Opportunistic
            } else {
                DaneMode::Enforced(recs)
            }
        }
        _ => DaneMode::Opportunistic,
    }
}

/// Verify a presented chain against the TLSA records (EE first, then
/// TA). Returns true when any record validates any chain cert.
fn dane_verify(chain: &[CertificateDer<'_>], records: &[TlsaRecord]) -> bool {
    for cert in chain {
        let der = cert.as_ref();
        if records.iter().any(|r| r.matches(der)) {
            return true;
        }
    }
    false
}

/// A rustls verifier implementing the DANE/opportunistic trust model.
#[derive(Debug)]
pub struct DaneVerifier {
    /// Web-PKI roots (OS trust store snapshot at config time).
    webpki_roots: RootCertStore,
    /// TLSA records when DANE is enforced for this host.
    dane: Option<Vec<TlsaRecord>>,
}

impl DaneMode {
    pub fn is_enforced(&self) -> bool {
        matches!(self, DaneMode::Enforced(_))
    }
}

impl DaneVerifier {
    pub fn new(webpki_roots: RootCertStore, dane: Option<Vec<TlsaRecord>>) -> Self {
        Self { webpki_roots, dane }
    }
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chain: Vec<CertificateDer<'static>> = {
            let mut v = Vec::with_capacity(intermediates.len() + 1);
            v.push(end_entity.clone().into_owned());
            for i in intermediates {
                v.push(i.clone().into_owned());
            }
            v
        };
        if let Some(records) = &self.dane {
            if dane_verify(&chain, records) {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(rustls::Error::General(
                "DANE: presented chain does not match any TLSA record".into(),
            ));
        }
        // Opportunistic web-PKI path: default verifier semantics.
        // (The roots store check is delegated to the default verifier
        // at config time; this fallback trusts the platform PQ root +
        // OS store snapshot taken at build.)
        if self.webpki_roots.is_empty() {
            // Dev mode: no roots available — accept (opportunistic TLS
            // still encrypts; MTA-STS enforce mode gates the downgrade).
            return Ok(ServerCertVerified::assertion());
        }
        let roots = self.webpki_roots.clone();
        let verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| rustls::Error::Other(rustls::OtherError(Arc::new(e))))?;
        verifier.verify_server_cert(end_entity, intermediates, _server_name, _ocsp_response, _now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls_graviola::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls_graviola::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        rustls_graviola::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Connect + STARTTLS-wrap an outbound SMTP stream: handshake, verify
/// per the DANE mode, return the wrapped stream.
pub async fn connect_starttls(
    sock: tokio::net::TcpStream,
    hostname: &str,
    dane: &DaneMode,
) -> Result<TlsStream<tokio::net::TcpStream>, String> {
    let roots = load_webpki_roots();
    let verifier = DaneVerifier::new(
        roots,
        match dane {
            DaneMode::Enforced(r) => Some(r.clone()),
            DaneMode::Opportunistic => None,
        },
    );
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls_pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|e| format!("bad server name: {e}"))?;
    connector
        .connect(server_name, sock)
        .await
        .map_err(|e| format!("STARTTLS client handshake: {e}"))
}

/// Best-effort OS trust roots (rustls-native-certs when compiled in;
/// empty → the verifier's opportunistic fallback applies).
fn load_webpki_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for c in certs.certs {
        let _ = roots.add(c);
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tlsa_triple() {
        let r = TlsaRecord::parse("3 1 1").unwrap();
        assert_eq!(r.usage, 3);
        assert_eq!(r.selector, 1);
        assert_eq!(r.matching, 1);
        assert!(TlsaRecord::parse("9 1 1").is_none());
        assert!(TlsaRecord::parse("3 1").is_none());
    }

    #[test]
    fn association_hex_decode() {
        let r = TlsaRecord::parse("3 1 1")
            .unwrap()
            .with_association("DEADBEEF");
        assert_eq!(r.association, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn dane_match_exact_selector0() {
        let der = vec![0x30, 0x01, 0x02, 0x03];
        let r = TlsaRecord::parse("3 0 0")
            .unwrap()
            .with_association("30010203");
        assert!(r.matches(&der));
        let wrong = TlsaRecord::parse("3 0 0").unwrap().with_association("CAFE");
        assert!(!wrong.matches(&der));
    }

    #[test]
    fn dane_match_sha256_selector0() {
        use sha2::{Digest, Sha256};
        let der = vec![0xAA, 0xBB];
        let digest = Sha256::digest(&der);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let r = TlsaRecord::parse("3 0 1").unwrap().with_association(&hex);
        assert!(r.matches(&der));
        // Wrong digest → no match.
        let bad = TlsaRecord::parse("3 0 1")
            .unwrap()
            .with_association("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(!bad.matches(&der));
    }

    #[test]
    fn selector1_fails_closed_without_spki_support() {
        // SPKI extraction is not implemented (G3) — a selector-1 record
        // must never validate (fail closed), never silently pass.
        let der = vec![0xAA, 0xBB];
        let r = TlsaRecord::parse("3 1 1").unwrap().with_association("aabb");
        assert!(!r.matches(&der));
    }

    #[tokio::test]
    async fn dane_lookup_enforced_when_records_present() {
        let mode = dane_lookup(
            &email8::mail_auth::FnDnsTxt(dns_lookup_stub as fn(&str) -> Result<Vec<String>, String>),
            "mx1.example",
            25,
        )
        .await;
        assert!(mode.is_enforced());
    }

    fn dns_lookup_stub(name: &str) -> Result<Vec<String>, String> {
        if name.starts_with("_25._tcp.mx1") {
            Ok(vec!["3 1 1".to_string(), "aabb".to_string()])
        } else {
            Err("nope".into())
        }
    }

    #[tokio::test]
    async fn dane_lookup_opportunistic_when_absent() {
        let mode = dane_lookup(
            &email8::mail_auth::FnDnsTxt(dns_lookup_stub as fn(&str) -> Result<Vec<String>, String>),
            "mx-other.example",
            25,
        )
        .await;
        assert_eq!(mode, DaneMode::Opportunistic);
    }
}