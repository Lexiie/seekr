use crate::domain::evidence::Evidence;
use crate::domain::signal::{Signal, SignalKind};

pub trait Detector: Send + Sync {
    fn detect(&self, evidence: &[Evidence], diffs: &[String]) -> Vec<Signal>;
}

fn has(diffs: &[String], id: &str) -> bool {
    diffs.iter().any(|d| d == id)
}

/// True when the final URL path looks like a block/unavailable page
/// (e.g. /unavailable/, /access-denied). Matched on path segments only.
fn is_block_url(final_url: &Option<String>) -> bool {
    const BLOCK_SEGMENTS: &[&str] = &[
        "unavailable",
        "geoblock",
        "geo-block",
        "not-available",
        "access-denied",
        "forbidden",
        "blocked",
    ];
    let Some(u) = final_url else {
        return false;
    };
    let path = u.split('?').next().unwrap_or(u).to_lowercase();
    path.split('/').any(|seg| BLOCK_SEGMENTS.contains(&seg))
}

/// True when any vantage contributed more than one sample
/// (i.e. a confirmation round actually ran).
fn repeated_vantage(evidence: &[Evidence]) -> bool {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    evidence.iter().any(|e| !seen.insert(e.vantage.clone()))
}

/// Runs all detectors. Pure function over evidence; no network.
pub fn detect_all(evidence: &[Evidence], diffs: &[String]) -> Vec<Signal> {
    let mut signals = Vec::new();

    // DNS / TLS / network / proxy failures from per-vantage errors.
    if evidence.iter().any(|e| e.error.as_deref() == Some("dns_failure")) {
        signals.push(Signal {
            kind: SignalKind::DnsFailure,
            confidence: 0.95,
            evidence: vec!["dns_failure".to_string()],
        });
    }
    if evidence.iter().any(|e| e.error.as_deref() == Some("tls_failure")) {
        signals.push(Signal {
            kind: SignalKind::TlsFailure,
            confidence: 0.90,
            evidence: vec!["tls_failure".to_string()],
        });
    }
    let proxy_failed = evidence.iter().any(|e| {
        matches!(
            e.error.as_deref(),
            Some("proxy_timeout") | Some("proxy_refused") | Some("proxy_auth_failure")
        )
    });
    let direct_ok = evidence.iter().any(|e| {
        e.vantage_kind == "direct" && matches!(e.response.status, Some(200..=399))
    });
    if proxy_failed {
        let conf = if direct_ok { 0.85 } else { 0.60 };
        signals.push(Signal {
            kind: SignalKind::ProxyFailure,
            confidence: conf,
            evidence: vec!["proxy_timeout".to_string()],
        });
    }
    if evidence.iter().any(|e| {
        matches!(
            e.error.as_deref(),
            Some("timeout") | Some("tcp_timeout") | Some("tcp_refused")
        )
    }) {
        signals.push(Signal {
            kind: SignalKind::NetworkFailure,
            confidence: 0.80,
            evidence: vec!["network_failure".to_string()],
        });
    }

    // Rate limit: 429 (+Retry-After raises confidence).
    let rate_evs: Vec<&Evidence> = evidence
        .iter()
        .filter(|e| e.response.status == Some(429))
        .collect();
    if !rate_evs.is_empty() {
        let with_retry = rate_evs.iter().any(|e| e.response.retry_after.is_some());
        let mut ids = vec!["rate_429".to_string()];
        if with_retry {
            ids.push("retry_after".to_string());
        }
        if has(diffs, "unstable") {
            ids.push("unstable".to_string());
        }
        signals.push(Signal {
            kind: SignalKind::RateLimit,
            confidence: if with_retry { 0.85 } else { 0.65 },
            evidence: ids,
        });
    }

    // WAF: 403 + challenge markers.
    let waf_evs: Vec<&Evidence> = evidence
        .iter()
        .filter(|e| e.response.status == Some(403) && !e.content.challenge_markers.is_empty())
        .collect();
    if !waf_evs.is_empty() {
        signals.push(Signal {
            kind: SignalKind::WafChallenge,
            confidence: 0.75,
            evidence: vec![
                "waf_403".to_string(),
                "challenge_markers".to_string(),
            ],
        });
    }

    // Server error: majority 5xx.
    let total = evidence.iter().filter(|e| e.response.status.is_some()).count();
    let errs = evidence
        .iter()
        .filter(|e| matches!(e.response.status, Some(500..=599)))
        .count();
    if total > 0 && errs * 2 >= total {
        signals.push(Signal {
            kind: SignalKind::ServerError,
            confidence: 0.70,
            evidence: vec!["server_5xx".to_string()],
        });
    }

    // Geo: status + country + content all diverge.
    if has(diffs, "status_changed") && has(diffs, "country_changed") && has(diffs, "content_changed")
    {
        let mut ids = vec![
            "status_changed".to_string(),
            "country_changed".to_string(),
            "content_changed".to_string(),
        ];
        if has(diffs, "unstable") {
            ids.push("unstable".to_string());
        } else if repeated_vantage(evidence) {
            ids.push("repeated_result".to_string());
        }
        let confidence = 0.35 + 0.30 + 0.15
            + if ids.iter().any(|i| i == "repeated_result") {
                0.10
            } else {
                0.0
            };
        signals.push(Signal {
            kind: SignalKind::GeoRestriction,
            confidence,
            evidence: ids,
        });
    }

    // IP: status + content diverge, country same, errors none.
    if has(diffs, "status_changed")
        && has(diffs, "content_changed")
        && !has(diffs, "country_changed")
        && has(diffs, "ip_changed")
    {
        signals.push(Signal {
            kind: SignalKind::IpRestriction,
            confidence: 0.35 + 0.15 + 0.10,
            evidence: vec![
                "status_changed".to_string(),
                "ip_changed".to_string(),
                "content_changed".to_string(),
            ],
        });
    }

    // Geo without status divergence: same-status block pages
    // (e.g. 200 + /unavailable/ vs 200 + full page).
    // Conservative gate: needs country + content divergence AND a
    // block-page URL or an explicit geo marker. Capped below
    // "confirmed": status divergence stays required for that.
    if !has(diffs, "status_changed")
        && has(diffs, "country_changed")
        && has(diffs, "content_changed")
    {
        let all_ok = !evidence.is_empty()
            && evidence
                .iter()
                .all(|e| matches!(e.response.status, Some(200..=299)));
        if all_ok {
            let block_redirect =
                has(diffs, "redirect_changed") && evidence.iter().any(|e| is_block_url(&e.response.final_url));
            let marker = evidence.iter().any(|e| {
                e.content.semantic_markers.iter().any(|m| m == "geo_notice")
            });
            if block_redirect {
                signals.push(Signal {
                    kind: SignalKind::GeoRestriction,
                    confidence: (0.30_f32 + 0.15 + 0.15).min(0.79),
                    evidence: vec![
                        "country_changed".to_string(),
                        "content_changed".to_string(),
                        "redirect_changed".to_string(),
                        "block_page".to_string(),
                    ],
                });
            } else if marker {
                signals.push(Signal {
                    kind: SignalKind::GeoRestriction,
                    confidence: (0.30_f32 + 0.15 + 0.10).min(0.79),
                    evidence: vec![
                        "country_changed".to_string(),
                        "content_changed".to_string(),
                        "geo_notice".to_string(),
                    ],
                });
            }
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::evidence::*;

    fn ev(status: Option<u16>, err: Option<&str>, markers: Vec<&str>) -> Evidence {
        Evidence {
            id_prefix: "direct".to_string(),
            vantage: "direct".to_string(),
            vantage_kind: "direct".to_string(),
            request: RequestEvidence::default(),
            response: ResponseEvidence {
                status,
                retry_after: None,
                ..Default::default()
            },
            network: NetworkEvidence::default(),
            timing: TimingEvidence::default(),
            content: ContentEvidence {
                challenge_markers: markers.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            error: err.map(|s| s.to_string()),
        }
    }

    #[test]
    fn dns_signal() {
        let e = vec![ev(None, Some("dns_failure"), vec![])];
        let s = detect_all(&e, &[]);
        assert!(s.iter().any(|x| x.kind == SignalKind::DnsFailure));
    }

    #[test]
    fn waf_needs_markers() {
        let e = vec![ev(Some(403), None, vec![])];
        let s = detect_all(&e, &[]);
        assert!(!s.iter().any(|x| x.kind == SignalKind::WafChallenge));
        let e2 = vec![ev(Some(403), None, vec!["js_challenge"])];
        let s2 = detect_all(&e2, &[]);
        assert!(s2.iter().any(|x| x.kind == SignalKind::WafChallenge));
    }

    #[test]
    fn single_403_yields_no_geo() {
        let e = vec![ev(Some(403), None, vec![])];
        let s = detect_all(&e, &[]);
        assert!(!s.iter().any(|x| x.kind == SignalKind::GeoRestriction));
    }

    #[test]
    fn geo_path_needs_triple_divergence() {
        use crate::comparison::compare_all;
        let mut a = ev(Some(403), None, vec![]);
        a.id_prefix = "direct".to_string();
        a.vantage = "direct".to_string();
        a.network.country = Some("ID".to_string());
        a.content.sha256 = Some("aaa".to_string());
        let mut b = ev(Some(200), None, vec![]);
        b.id_prefix = "proxy".to_string();
        b.vantage = "http://sg.example:8080".to_string();
        b.vantage_kind = "http_proxy".to_string();
        b.network.country = Some("SG".to_string());
        b.network.public_ip = Some("203.0.113.7".to_string());
        b.content.sha256 = Some("bbb".to_string());
        let e = vec![a, b];
        let diffs = compare_all(&e);
        assert!(diffs.contains(&"status_changed".to_string()));
        assert!(diffs.contains(&"country_changed".to_string()));
        assert!(diffs.contains(&"content_changed".to_string()));
        let s = detect_all(&e, &diffs);
        assert!(s.iter().any(|x| x.kind == SignalKind::GeoRestriction));
    }
}
