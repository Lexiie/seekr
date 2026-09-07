use std::collections::BTreeSet;

use crate::domain::evidence::Evidence;

/// Difference ids across vantages. Never emits a diagnosis kind.
pub fn compare_all(evidence: &[Evidence]) -> Vec<String> {
    let mut diffs = Vec::new();
    if evidence.len() < 2 {
        return diffs;
    }
    let statuses: BTreeSet<Option<u16>> = evidence.iter().map(|e| e.response.status).collect();
    if statuses.len() > 1 {
        diffs.push("status_changed".to_string());
    }
    let urls: BTreeSet<Option<String>> =
        evidence.iter().map(|e| e.response.final_url.clone()).collect();
    if urls.len() > 1 {
        diffs.push("redirect_changed".to_string());
    }
    let cts: BTreeSet<Option<String>> =
        evidence.iter().map(|e| e.response.content_type.clone()).collect();
    if cts.len() > 1 {
        diffs.push("headers_changed".to_string());
    }
    let countries: BTreeSet<Option<String>> =
        evidence.iter().map(|e| e.network.country.clone()).collect();
    if countries.len() > 1 {
        diffs.push("country_changed".to_string());
    }
    let ips: BTreeSet<Option<String>> =
        evidence.iter().map(|e| e.network.public_ip.clone()).collect();
    if ips.len() > 1 {
        diffs.push("ip_changed".to_string());
    }
    let asns: BTreeSet<Option<String>> = evidence.iter().map(|e| e.network.asn.clone()).collect();
    if asns.len() > 1 {
        diffs.push("asn_changed".to_string());
    }
    // Content: only full-vs-full hashes are comparable.
    let full_hashes: Vec<&String> = evidence
        .iter()
        .filter(|e| !e.content.partial)
        .filter_map(|e| e.content.sha256.as_ref())
        .collect();
    let uniq: BTreeSet<&String> = full_hashes.iter().copied().collect();
    if uniq.len() > 1 {
        diffs.push("content_changed".to_string());
    } else if evidence.iter().any(|e| e.content.partial) && uniq.len() <= 1 {
        // Check full-vs-partial mismatch conservatively: unknown, not changed.
        let partials = evidence.iter().filter(|e| e.content.partial).count();
        if partials > 0 && !full_hashes.is_empty() {
            diffs.push("content_unknown".to_string());
        }
    }
    // Instability: same vantage label produced different statuses.
    if has_instability(evidence) {
        diffs.push("unstable".to_string());
    }
    diffs
}

fn has_instability(evidence: &[Evidence]) -> bool {
    use std::collections::HashMap;
    let mut by_vantage: HashMap<&str, BTreeSet<Option<u16>>> = HashMap::new();
    for e in evidence {
        by_vantage
            .entry(e.vantage.as_str())
            .or_default()
            .insert(e.response.status);
    }
    by_vantage.values().any(|s| s.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::evidence::*;

    fn ev(vantage: &str, status: Option<u16>, hash: Option<&str>, partial: bool) -> Evidence {
        Evidence {
            id_prefix: "direct".to_string(),
            vantage: vantage.to_string(),
            vantage_kind: "direct".to_string(),
            request: RequestEvidence::default(),
            response: ResponseEvidence {
                status,
                ..Default::default()
            },
            network: NetworkEvidence::default(),
            timing: TimingEvidence::default(),
            content: ContentEvidence {
                sha256: hash.map(|s| s.to_string()),
                partial,
                ..Default::default()
            },
            error: None,
        }
    }

    #[test]
    fn detects_status_change() {
        let e = vec![ev("a", Some(403), None, false), ev("b", Some(200), None, false)];
        assert!(compare_all(&e).contains(&"status_changed".to_string()));
    }

    #[test]
    fn partial_never_yields_content_changed() {
        let e = vec![
            ev("a", Some(200), Some("aaa"), false),
            ev("b", Some(200), Some("bbb"), true),
        ];
        let d = compare_all(&e);
        assert!(!d.contains(&"content_changed".to_string()));
        assert!(d.contains(&"content_unknown".to_string()));
    }
}
