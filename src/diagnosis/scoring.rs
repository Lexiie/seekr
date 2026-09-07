use crate::domain::diagnosis::{Diagnosis, DiagnosisKind};
use crate::domain::evidence::Evidence;
use crate::domain::signal::{Signal, SignalKind};

fn priority(kind: &SignalKind) -> u8 {
    match kind {
        SignalKind::DnsFailure | SignalKind::TlsFailure | SignalKind::NetworkFailure => 0,
        SignalKind::ProxyFailure => 1,
        SignalKind::WafChallenge => 2,
        SignalKind::RateLimit => 3,
        SignalKind::IpRestriction => 4,
        SignalKind::GeoRestriction => 5,
        SignalKind::ServerError => 6,
        SignalKind::Unknown => 7,
    }
}

fn to_kind(kind: SignalKind) -> DiagnosisKind {
    match kind {
        SignalKind::DnsFailure => DiagnosisKind::DnsFailure,
        SignalKind::TlsFailure => DiagnosisKind::TlsFailure,
        SignalKind::NetworkFailure => DiagnosisKind::NetworkFailure,
        SignalKind::ProxyFailure => DiagnosisKind::ProxyFailure,
        SignalKind::WafChallenge => DiagnosisKind::WafChallenge,
        SignalKind::RateLimit => DiagnosisKind::RateLimit,
        SignalKind::IpRestriction => DiagnosisKind::IpRestriction,
        SignalKind::GeoRestriction => DiagnosisKind::GeoRestriction,
        SignalKind::ServerError => DiagnosisKind::ServerError,
        SignalKind::Unknown => DiagnosisKind::Unknown,
    }
}

fn interpretation(kind: DiagnosisKind, qualifier: &str) -> String {
    match kind {
        DiagnosisKind::Healthy => "Target responds normally from all vantages.".to_string(),
        DiagnosisKind::GeoRestriction => format!(
            "{qualifier} geographic access difference: status and content change with country."
        ),
        DiagnosisKind::IpRestriction => format!(
            "{qualifier} address-based access difference: status changes with IP while country is stable."
        ),
        DiagnosisKind::RateLimit => "Request rate exceeded: server asks the client to slow down.".to_string(),
        DiagnosisKind::WafChallenge => "Protective challenge presented instead of content.".to_string(),
        DiagnosisKind::ProxyFailure => {
            "Configured vantage failed while direct path works: vantage issue, not target blocking."
                .to_string()
        }
        DiagnosisKind::ServerError => "Target returns server errors.".to_string(),
        DiagnosisKind::NetworkFailure => "Network path failed before a response.".to_string(),
        DiagnosisKind::DnsFailure => "Name resolution failed.".to_string(),
        DiagnosisKind::TlsFailure => "Secure session could not be established.".to_string(),
        DiagnosisKind::Unknown => "Not enough evidence to determine a cause.".to_string(),
    }
}

fn next_step(kind: DiagnosisKind) -> Option<String> {
    match kind {
        DiagnosisKind::GeoRestriction => {
            Some("Retry from a vantage in the required region.".to_string())
        }
        DiagnosisKind::IpRestriction => {
            Some("Retry from a different egress address.".to_string())
        }
        DiagnosisKind::RateLimit => {
            Some("Back off for the indicated delay, then retry once.".to_string())
        }
        DiagnosisKind::WafChallenge => {
            Some("Verify with an interactive browser session.".to_string())
        }
        DiagnosisKind::ProxyFailure => {
            Some("Check the configured vantage before blaming the target.".to_string())
        }
        DiagnosisKind::Unknown => {
            Some("Add a second vantage to allow comparison.".to_string())
        }
        _ => None,
    }
}

/// Resolves signals into a diagnosis. Never invents a cause from a lone
/// status code; falls back to Unknown with insufficient_evidence.
pub fn resolve(evidence: &[Evidence], signals: &[Signal]) -> Diagnosis {
    if signals.is_empty() {
        // All-healthy shortcut: every vantage returned 2xx-3xx.
        let all_ok = !evidence.is_empty()
            && evidence
                .iter()
                .all(|e| matches!(e.response.status, Some(200..=399)));
        if all_ok {
            return Diagnosis {
                kind: DiagnosisKind::Healthy,
                confidence: 0.90,
                evidence_ids: vec![],
                interpretation: interpretation(DiagnosisKind::Healthy, ""),
                next_step: None,
            };
        }
        return Diagnosis {
            kind: DiagnosisKind::Unknown,
            confidence: 0.0,
            evidence_ids: vec!["insufficient_evidence".to_string()],
            interpretation: interpretation(DiagnosisKind::Unknown, ""),
            next_step: next_step(DiagnosisKind::Unknown),
        };
    }
    let mut best = &signals[0];
    for s in signals.iter().skip(1) {
        let clearly_better = s.confidence > best.confidence + 0.10;
        let tied = (s.confidence - best.confidence).abs() <= 0.10;
        if clearly_better || (tied && priority(&s.kind) < priority(&best.kind)) {
            best = s;
        }
    }
    let kind = to_kind(best.kind);
    // Round to 2dp so binary float sums (e.g. 0.35+0.30+0.15) land on
    // the intended threshold instead of just below it.
    let confidence = (best.confidence.min(1.0) * 100.0).round() / 100.0;
    let q = if confidence >= 0.80 {
        "confirmed"
    } else if confidence >= 0.50 {
        "likely"
    } else {
        "unknown"
    };
    if q == "unknown" {
        return Diagnosis {
            kind: DiagnosisKind::Unknown,
            confidence,
            evidence_ids: vec!["insufficient_evidence".to_string()],
            interpretation: interpretation(DiagnosisKind::Unknown, ""),
            next_step: next_step(DiagnosisKind::Unknown),
        };
    }
    Diagnosis {
        kind,
        confidence,
        evidence_ids: best.evidence.clone(),
        interpretation: interpretation(kind, q),
        next_step: next_step(kind),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lone_signal_below_threshold_is_unknown() {
        let d = resolve(
            &[],
            &[Signal {
                kind: SignalKind::GeoRestriction,
                confidence: 0.35,
                evidence: vec![],
            }],
        );
        assert_eq!(d.kind, DiagnosisKind::Unknown);
    }

    #[test]
    fn priority_breaks_ties() {
        let d = resolve(
            &[],
            &[
                Signal {
                    kind: SignalKind::GeoRestriction,
                    confidence: 0.75,
                    evidence: vec![],
                },
                Signal {
                    kind: SignalKind::RateLimit,
                    confidence: 0.78,
                    evidence: vec![],
                },
            ],
        );
        assert_eq!(d.kind, DiagnosisKind::RateLimit);
    }
}
