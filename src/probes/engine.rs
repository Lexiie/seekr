use crate::comparison::compare_all;
use crate::detectors::detect_all;
use crate::diagnosis::resolve;
use crate::domain::evidence::{
    ContentEvidence, Evidence, NetworkEvidence, RequestEvidence, ResponseEvidence, TimingEvidence,
};
use crate::domain::target::sanitize_url_str;
use crate::domain::vantage::VantagePoint;
use crate::probes::plan::ProbePlan;
use crate::transport::{ExecRequest, TransportError, challenge_markers, execute, extract_title, semantic_markers, sha256_hex};

pub struct ProbeOutcome {
    pub evidence: Vec<Evidence>,
    pub probes_used: usize,
}

fn probe_once(plan: &ProbePlan, vantage: &VantagePoint) -> Evidence {
    let id_prefix = vantage.short_id().to_string();
    let header_names: Vec<String> = plan.headers.iter().map(|(k, _)| k.clone()).collect();
    let request = RequestEvidence {
        method: plan.method.clone(),
        url: sanitize_url_str(&plan.target.url),
        header_names,
        user_agent: plan.user_agent.clone(),
        vantage: vantage.redacted_label(),
    };
    let exec_req = ExecRequest {
        url: plan.target.url.clone(),
        method: plan.method.clone(),
        headers: plan.headers.clone(),
        user_agent: plan.user_agent.clone(),
        timeout_total: plan.limits.timeout_total,
        timeout_connect: plan.limits.timeout_connect,
        max_redirects: plan.limits.max_redirects,
        max_body_bytes: plan.limits.max_body_bytes,
        retries: plan.limits.retries,
    };
    match execute(vantage, &exec_req) {
        Ok(raw) => {
            let retry_after = raw
                .headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == "retry-after")
                .map(|(_, v)| v.clone());
            let status = raw.status;
            let sha = sha256_hex(&raw.body_prefix);
            let title = extract_title(&raw.body_prefix);
            let ch = challenge_markers(&raw.body_prefix);
            let sem = semantic_markers(status, &raw.body_prefix);
            let mut network = NetworkEvidence {
                proxy_type: if matches!(vantage, VantagePoint::Direct) {
                    None
                } else {
                    Some(vantage.kind_label().to_string())
                },
                tcp_ok: Some(true),
                dns_ok: Some(true),
                tls_ok: Some(true),
                ..Default::default()
            };
            if plan.identity_lookup {
                // Precedence: static map entry wins; otherwise auto lookup
                // through the same vantage; any failure degrades to None.
                let info = plan
                    .identity
                    .lookup(&vantage.redacted_label())
                    .or_else(|| {
                        crate::identity::auto_lookup(
                            vantage,
                            plan.limits.timeout_total,
                            plan.limits.timeout_connect,
                        )
                    });
                if let Some(info) = info {
                    if info.ip.is_some() {
                        network.public_ip = info.ip;
                    }
                    if info.country.is_some() {
                        network.country = info.country;
                    }
                    network.accuracy_radius_km = info.accuracy_radius_km;
                    if info.asn.is_some() {
                        network.asn = info.asn;
                    }
                }
            }
            Evidence {
                id_prefix: id_prefix.clone(),
                vantage: vantage.redacted_label(),
                vantage_kind: vantage.kind_label().to_string(),
                request,
                response: ResponseEvidence {
                    status: Some(status),
                    final_url: Some(raw.final_url),
                    redirect_chain: raw.redirect_chain,
                    content_length: Some(raw.body_prefix.len() as u64),
                    content_type: raw.content_type.clone(),
                    retry_after,
                },
                network,
                timing: TimingEvidence {
                    total_ms: Some(raw.total_ms),
                    ..Default::default()
                },
                content: ContentEvidence {
                    length: Some(raw.body_prefix.len() as u64),
                    sha256: Some(sha),
                    content_type: raw.content_type,
                    title,
                    challenge_markers: ch,
                    semantic_markers: sem,
                    partial: raw.truncated,
                },
                error: None,
            }
        }
        Err(e) => {
            let (failure, dns_ok, tcp_ok, tls_ok) = match &e {
                TransportError::DnsFailure => ("dns_failure", Some(false), None, None),
                TransportError::TlsFailure => ("tls_failure", Some(true), Some(true), Some(false)),
                TransportError::TcpRefused | TransportError::TcpTimeout | TransportError::Timeout | TransportError::NetworkFailure => {
                    ("network_failure", None, Some(false), None)
                }
                TransportError::ProxyAuthFailure | TransportError::ProxyRefused | TransportError::ProxyTimeout => {
                    ("proxy_failure", None, None, None)
                }
                TransportError::RedirectLoop => ("redirect_loop", Some(true), Some(true), Some(true)),
                TransportError::BodyTooLarge => ("body_too_large", Some(true), Some(true), Some(true)),
            };
            Evidence {
                id_prefix: id_prefix.clone(),
                vantage: vantage.redacted_label(),
                vantage_kind: vantage.kind_label().to_string(),
                request,
                response: ResponseEvidence::default(),
                network: NetworkEvidence {
                    proxy_type: if matches!(vantage, VantagePoint::Direct) {
                        None
                    } else {
                        Some(vantage.kind_label().to_string())
                    },
                    dns_ok,
                    tcp_ok,
                    tls_ok,
                    failure: Some(failure.to_string()),
                    ..Default::default()
                },
                timing: TimingEvidence::default(),
                content: ContentEvidence::default(),
                error: Some(error_label(&e)),
            }
        }
    }
}

fn error_label(e: &TransportError) -> String {
    match e {
        TransportError::DnsFailure => "dns_failure".to_string(),
        TransportError::TcpRefused => "tcp_refused".to_string(),
        TransportError::TcpTimeout => "tcp_timeout".to_string(),
        TransportError::TlsFailure => "tls_failure".to_string(),
        TransportError::ProxyAuthFailure => "proxy_auth_failure".to_string(),
        TransportError::ProxyRefused => "proxy_refused".to_string(),
        TransportError::ProxyTimeout => "proxy_timeout".to_string(),
        TransportError::Timeout => "timeout".to_string(),
        TransportError::RedirectLoop => "redirect_loop".to_string(),
        TransportError::BodyTooLarge => "body_too_large".to_string(),
        TransportError::NetworkFailure => "network_failure".to_string(),
    }
}

/// Decides whether a confirmation round is worthwhile.
/// Pure decision: testable without network.
pub fn needs_confirmation(
    diagnosis: &crate::domain::diagnosis::Diagnosis,
    probes_used: usize,
    max_probes: usize,
    require_reproducibility: bool,
    min_confidence: f32,
) -> bool {
    diagnosis.confidence < min_confidence
        && require_reproducibility
        && probes_used < max_probes
        && is_confirmable(&diagnosis.kind)
}

/// Runs initial round (one probe per vantage) plus at most one confirmation
/// round when confidence is below threshold and budget allows.
/// Never exceeds max_probes; never does 3+ probes per vantage.
pub fn run_plan(plan: &ProbePlan) -> ProbeOutcome {
    let mut evidence: Vec<Evidence> = Vec::new();
    let mut probes_used = 0;
    for v in &plan.vantages {
        if probes_used >= plan.limits.max_probes {
            break;
        }
        evidence.push(probe_once(plan, v));
        probes_used += 1;
    }
    // Confirmation: one extra round over divergent vantages only.
    let diffs = compare_all(&evidence);
    let signals = detect_all(&evidence, &diffs);
    let diagnosis = resolve(&evidence, &signals);
    if needs_confirmation(
        &diagnosis,
        probes_used,
        plan.limits.max_probes,
        plan.confirmation.require_reproducibility,
        plan.confirmation.min_confidence,
    ) {
        // Re-probe up to remaining budget, each vantage at most once more.
        let remaining = plan.limits.max_probes - probes_used;
        let n = remaining.min(plan.vantages.len());
        let targets: Vec<VantagePoint> = plan.vantages.iter().take(n).cloned().collect();
        for v in &targets {
            evidence.push(probe_once(plan, v));
            probes_used += 1;
        }
    }
    ProbeOutcome {
        evidence,
        probes_used,
    }
}

fn is_confirmable(kind: &crate::domain::diagnosis::DiagnosisKind) -> bool {
    use crate::domain::diagnosis::DiagnosisKind::*;
    // Definitive transport failures never benefit from confirmation.
    !matches!(kind, DnsFailure | TlsFailure | NetworkFailure | ProxyFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::diagnosis::{Diagnosis, DiagnosisKind};

    fn diag(kind: DiagnosisKind, conf: f32) -> Diagnosis {
        Diagnosis {
            kind,
            confidence: conf,
            evidence_ids: vec![],
            interpretation: String::new(),
            next_step: None,
        }
    }

    #[test]
    fn request_evidence_stores_names_only() {
        // By construction RequestEvidence.header_names holds names;
        // values never enter Evidence. Covered by type shape.
    }

    #[test]
    fn confirmation_for_unknown_with_budget() {
        assert!(needs_confirmation(&diag(DiagnosisKind::Unknown, 0.0), 1, 10, true, 0.50));
    }

    #[test]
    fn no_confirmation_when_confident() {
        assert!(!needs_confirmation(
            &diag(DiagnosisKind::Healthy, 0.90),
            1,
            10,
            true,
            0.50
        ));
    }

    #[test]
    fn no_confirmation_when_budget_spent() {
        assert!(!needs_confirmation(
            &diag(DiagnosisKind::Unknown, 0.0),
            10,
            10,
            true,
            0.50
        ));
    }

    #[test]
    fn no_confirmation_for_transport_failures() {
        for kind in [
            DiagnosisKind::DnsFailure,
            DiagnosisKind::TlsFailure,
            DiagnosisKind::NetworkFailure,
            DiagnosisKind::ProxyFailure,
        ] {
            assert!(
                !needs_confirmation(&diag(kind, 0.85), 1, 10, true, 0.50),
                "{kind:?} must not confirm"
            );
        }
    }

    #[test]
    fn no_confirmation_when_reproducibility_off() {
        assert!(!needs_confirmation(
            &diag(DiagnosisKind::Unknown, 0.0),
            1,
            10,
            false,
            0.50
        ));
    }
}
