use seekr::domain::diagnosis::{Diagnosis, DiagnosisKind};
use seekr::domain::vantage::parse_proxy;
use seekr::output::{JsonResult, JsonTarget};

fn all_kinds() -> Vec<DiagnosisKind> {
    vec![
        DiagnosisKind::Healthy,
        DiagnosisKind::GeoRestriction,
        DiagnosisKind::IpRestriction,
        DiagnosisKind::RateLimit,
        DiagnosisKind::WafChallenge,
        DiagnosisKind::ProxyFailure,
        DiagnosisKind::ServerError,
        DiagnosisKind::NetworkFailure,
        DiagnosisKind::DnsFailure,
        DiagnosisKind::TlsFailure,
        DiagnosisKind::Unknown,
    ]
}

#[test]
fn exit_code_mapping_is_total() {
    let table = [
        (DiagnosisKind::Healthy, 0),
        (DiagnosisKind::GeoRestriction, 1),
        (DiagnosisKind::IpRestriction, 1),
        (DiagnosisKind::RateLimit, 1),
        (DiagnosisKind::WafChallenge, 1),
        (DiagnosisKind::ProxyFailure, 4),
        (DiagnosisKind::ServerError, 3),
        (DiagnosisKind::NetworkFailure, 3),
        (DiagnosisKind::DnsFailure, 3),
        (DiagnosisKind::TlsFailure, 3),
        (DiagnosisKind::Unknown, 7),
    ];
    for (kind, code) in table {
        assert_eq!(kind.exit_code(), code, "exit for {}", kind.as_str());
    }
}

#[test]
fn qualifier_thresholds() {
    let mk = |conf| Diagnosis {
        kind: DiagnosisKind::GeoRestriction,
        confidence: conf,
        evidence_ids: vec![],
        interpretation: String::new(),
        next_step: None,
    };
    assert_eq!(mk(0.95).qualifier(), "confirmed");
    assert_eq!(mk(0.80).qualifier(), "confirmed");
    assert_eq!(mk(0.79).qualifier(), "likely");
    assert_eq!(mk(0.50).qualifier(), "likely");
    assert_eq!(mk(0.49).qualifier(), "unknown");
}

#[test]
fn json_shape_schema_version_is_string_one() {
    let r = JsonResult {
        schema_version: "1".to_string(),
        target: JsonTarget {
            url: "https://example.com/".to_string(),
        },
        duration_ms: 1,
        vantages: vec![],
        evidence: vec![],
        signals: vec![],
        diagnosis: None,
        diffs: None,
        skipped_proxies: 0,
        probes_used: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    assert_eq!(v["schema_version"], serde_json::Value::String("1".to_string()));
    assert!(v["target"]["url"].is_string());
}

#[test]
fn proxy_credentials_never_serialize() {
    let v = parse_proxy("http://user:sup3rsecret@proxy.example:8080").unwrap();
    let label = v.redacted_label();
    assert!(!label.contains("sup3rsecret"));
    assert!(!label.contains("user"));
    // Serialized proxy config must not carry the secret either.
    if let seekr::domain::vantage::VantagePoint::HttpProxy(c) = &v {
        let raw = serde_json::to_string(c).unwrap();
        assert!(!raw.contains("sup3rsecret"));
        assert!(raw.contains("auth_present"));
    } else {
        panic!("wrong variant");
    }
}

#[test]
fn target_sanitizer_strips_userinfo_and_query_secrets() {
    let t = seekr::domain::target::Target::parse(
        "https://user:pw@example.com/path?token=abc&n=1",
    )
    .unwrap();
    assert!(!t.url.contains("pw"));
    assert!(!t.url.contains("abc"));
    assert!(t.url.contains("n=1"));
}

#[test]
fn interpretations_name_no_vendor() {
    // Deny-list: core output must describe capability, never promote.
    let deny = [
        "cloudflare", "akamai", "fastly", "imperva", "datadome", "sucuri", "incapsula",
        "blazing", "stackpath",
    ];
    for kind in all_kinds() {
        let d = seekr::diagnosis::resolve(
            &[],
            &[seekr::domain::signal::Signal {
                kind: match kind {
                    DiagnosisKind::Healthy => continue,
                    DiagnosisKind::GeoRestriction => seekr::domain::signal::SignalKind::GeoRestriction,
                    DiagnosisKind::IpRestriction => seekr::domain::signal::SignalKind::IpRestriction,
                    DiagnosisKind::RateLimit => seekr::domain::signal::SignalKind::RateLimit,
                    DiagnosisKind::WafChallenge => seekr::domain::signal::SignalKind::WafChallenge,
                    DiagnosisKind::ProxyFailure => seekr::domain::signal::SignalKind::ProxyFailure,
                    DiagnosisKind::ServerError => seekr::domain::signal::SignalKind::ServerError,
                    DiagnosisKind::NetworkFailure => {
                        seekr::domain::signal::SignalKind::NetworkFailure
                    }
                    DiagnosisKind::DnsFailure => seekr::domain::signal::SignalKind::DnsFailure,
                    DiagnosisKind::TlsFailure => seekr::domain::signal::SignalKind::TlsFailure,
                    DiagnosisKind::Unknown => continue,
                },
                confidence: 0.9,
                evidence: vec![],
            }],
        );
        let text = format!("{} {}", d.interpretation, d.next_step.unwrap_or_default())
            .to_lowercase();
        for vendor in deny {
            assert!(
                !text.contains(vendor),
                "vendor {vendor} leaked in {kind:?}"
            );
        }
    }
}
