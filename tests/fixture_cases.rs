use seekr::comparison::compare_all;
use seekr::detectors::detect_all;
use seekr::diagnosis::resolve;
use seekr::domain::diagnosis::DiagnosisKind;
use seekr::domain::evidence::{
    ContentEvidence, Evidence, NetworkEvidence, RequestEvidence, ResponseEvidence, TimingEvidence,
};
use seekr::domain::signal::SignalKind;

fn base(vantage: &str, kind: &str, prefix: &str) -> Evidence {
    Evidence {
        id_prefix: prefix.to_string(),
        vantage: vantage.to_string(),
        vantage_kind: kind.to_string(),
        request: RequestEvidence::default(),
        response: ResponseEvidence::default(),
        network: NetworkEvidence::default(),
        timing: TimingEvidence::default(),
        content: ContentEvidence::default(),
        error: None,
    }
}

fn ok(vantage: &str, kind: &str, prefix: &str, status: u16, hash: &str) -> Evidence {
    let mut e = base(vantage, kind, prefix);
    e.response.status = Some(status);
    e.response.final_url = Some("https://example.com/".to_string());
    e.response.content_type = Some("text/html".to_string());
    e.content.sha256 = Some(hash.to_string());
    e.network.tcp_ok = Some(true);
    e.network.dns_ok = Some(true);
    e.network.tls_ok = Some(true);
    e
}

#[test]
fn proxy_auth_failure_with_direct_ok_is_proxy_failure() {
    let direct = ok("direct", "direct", "direct", 200, "a");
    let mut proxy = base("http://p.example:8080", "http_proxy", "proxy");
    proxy.error = Some("proxy_auth_failure".to_string());
    proxy.network.failure = Some("proxy_failure".to_string());
    let e = vec![direct, proxy];
    let diffs = compare_all(&e);
    let signals = detect_all(&e, &diffs);
    assert!(signals.iter().any(|s| s.kind == SignalKind::ProxyFailure));
    let d = resolve(&e, &signals);
    assert_eq!(d.kind, DiagnosisKind::ProxyFailure);
    assert_eq!(d.kind.exit_code(), 4);
}

#[test]
fn tls_failure_resolves_tls() {
    let mut e = base("direct", "direct", "direct");
    e.error = Some("tls_failure".to_string());
    e.network.tls_ok = Some(false);
    e.network.failure = Some("tls_failure".to_string());
    let ev = vec![e];
    let diffs = compare_all(&ev);
    let signals = detect_all(&ev, &diffs);
    assert!(signals.iter().any(|s| s.kind == SignalKind::TlsFailure));
    let d = resolve(&ev, &signals);
    assert_eq!(d.kind, DiagnosisKind::TlsFailure);
    assert_eq!(d.kind.exit_code(), 3);
}

#[test]
fn truncated_body_never_confirms_content_change() {
    let full = ok("a", "direct", "direct", 200, "aaa");
    let mut part = ok("b", "http_proxy", "proxy", 200, "bbb");
    part.content.partial = true;
    let e = vec![full, part];
    let diffs = compare_all(&e);
    assert!(!diffs.contains(&"content_changed".to_string()));
    let signals = detect_all(&e, &diffs);
    assert!(!signals.iter().any(|s| s.kind == SignalKind::GeoRestriction));
}

#[test]
fn rate_limit_with_retry_after_scores_high() {
    let mut e = ok("direct", "direct", "direct", 429, "a");
    e.response.retry_after = Some("60".to_string());
    let ev = vec![e];
    let diffs = compare_all(&ev);
    let signals = detect_all(&ev, &diffs);
    let s = signals.iter().find(|s| s.kind == SignalKind::RateLimit).unwrap();
    assert!((s.confidence - 0.85).abs() < f32::EPSILON);
    let d = resolve(&ev, &signals);
    assert_eq!(d.kind, DiagnosisKind::RateLimit);
}

#[test]
fn waf_needs_markers_even_across_vantages() {
    let mut blocked = ok("direct", "direct", "direct", 403, "a");
    blocked.content.challenge_markers = vec!["js_challenge".to_string()];
    let clean = ok("b", "http_proxy", "proxy", 200, "b");
    let e = vec![blocked, clean];
    let diffs = compare_all(&e);
    let signals = detect_all(&e, &diffs);
    assert!(signals.iter().any(|s| s.kind == SignalKind::WafChallenge));
}

#[test]
fn all_healthy_stays_healthy() {
    let e = vec![
        ok("direct", "direct", "direct", 200, "a"),
        ok("b", "http_proxy", "proxy", 200, "a"),
    ];
    let diffs = compare_all(&e);
    assert!(diffs.is_empty());
    let signals = detect_all(&e, &diffs);
    let d = resolve(&e, &signals);
    assert_eq!(d.kind, DiagnosisKind::Healthy);
    assert_eq!(d.kind.exit_code(), 0);
}

#[test]
fn redirect_loop_without_status_is_unknown() {
    let mut e = base("direct", "direct", "direct");
    e.error = Some("redirect_loop".to_string());
    let ev = vec![e];
    let diffs = compare_all(&ev);
    let signals = detect_all(&ev, &diffs);
    let d = resolve(&ev, &signals);
    assert_eq!(d.kind, DiagnosisKind::Unknown);
    assert_eq!(d.kind.exit_code(), 7);
}

fn geo_pair() -> Vec<Evidence> {
    let mut blocked = ok("direct", "direct", "direct", 200, "aaa");
    blocked.response.final_url = Some("https://www.fubo.tv/unavailable/".to_string());
    blocked.network.country = Some("ID".to_string());
    let mut full = ok("p", "http_proxy", "proxy", 200, "bbb");
    full.response.final_url = Some("https://www.fubo.tv/welcome".to_string());
    full.network.country = Some("US".to_string());
    full.network.public_ip = Some("203.0.113.7".to_string());
    vec![blocked, full]
}

#[test]
fn same_status_block_page_is_geo_likely_not_confirmed() {
    let e = geo_pair();
    let diffs = compare_all(&e);
    assert!(!diffs.contains(&"status_changed".to_string()));
    assert!(diffs.contains(&"redirect_changed".to_string()));
    assert!(diffs.contains(&"country_changed".to_string()));
    assert!(diffs.contains(&"content_changed".to_string()));
    let signals = detect_all(&e, &diffs);
    let s = signals
        .iter()
        .find(|s| s.kind == SignalKind::GeoRestriction)
        .expect("geo signal");
    assert!((s.confidence - 0.60).abs() < 1e-6, "got {}", s.confidence);
    assert!(s.evidence.contains(&"block_page".to_string()));
    let d = resolve(&e, &signals);
    assert_eq!(d.kind, DiagnosisKind::GeoRestriction);
    assert!(d.confidence < 0.80, "must cap below confirmed");
    assert_eq!(d.qualifier(), "likely");
    assert_eq!(d.kind.exit_code(), 1);
}

#[test]
fn same_status_same_country_is_not_geo() {
    // A/B-test shape: content differs, country identical, no block URL.
    let mut a = ok("direct", "direct", "direct", 200, "aaa");
    a.response.final_url = Some("https://example.com/".to_string());
    a.network.country = Some("ID".to_string());
    let mut b = ok("p", "http_proxy", "proxy", 200, "bbb");
    b.response.final_url = Some("https://example.com/".to_string());
    b.network.country = Some("ID".to_string());
    let e = vec![a, b];
    let diffs = compare_all(&e);
    let signals = detect_all(&e, &diffs);
    assert!(!signals.iter().any(|s| s.kind == SignalKind::GeoRestriction));
}

#[test]
fn same_status_country_differs_but_content_same_is_not_geo() {
    let mut a = ok("direct", "direct", "direct", 200, "aaa");
    a.response.final_url = Some("https://example.com/".to_string());
    a.network.country = Some("ID".to_string());
    let mut b = ok("p", "http_proxy", "proxy", 200, "aaa");
    b.response.final_url = Some("https://example.com/".to_string());
    b.network.country = Some("US".to_string());
    let e = vec![a, b];
    let diffs = compare_all(&e);
    let signals = detect_all(&e, &diffs);
    assert!(!signals.iter().any(|s| s.kind == SignalKind::GeoRestriction));
}
