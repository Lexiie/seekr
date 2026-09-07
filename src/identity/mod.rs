use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::domain::vantage::VantagePoint;
use crate::transport::{ExecRequest, execute};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub ip: Option<String>,
    pub country: Option<String>,
    pub accuracy_radius_km: Option<u32>,
    pub asn: Option<String>,
}

pub trait IdentityProvider: Send + Sync {
    /// Returns identity for a vantage label, or None when unavailable.
    /// Never fails: failure degrades to None.
    fn lookup(&self, vantage_label: &str) -> Option<IdentityInfo>;
}

#[derive(Debug, Default)]
pub struct NullProvider;

impl IdentityProvider for NullProvider {
    fn lookup(&self, _vantage_label: &str) -> Option<IdentityInfo> {
        None
    }
}

/// Matches vantage labels by substring (e.g. proxy host) to static identity.
/// File format: JSON object mapping substring -> info.
///
/// ```json
/// { "sg-proxy": { "ip": "203.0.113.7", "country": "SG",
///   "accuracy_radius_km": 50, "asn": "AS12345" } }
/// ```
#[derive(Debug, Default)]
pub struct StaticProvider {
    entries: Vec<(String, IdentityInfo)>,
}

impl StaticProvider {
    pub fn from_map(map: HashMap<String, IdentityInfo>) -> Self {
        Self {
            entries: map.into_iter().collect(),
        }
    }

    pub fn load_file(path: &str) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|_| format!("cannot read file: {path}"))?;
        let map: HashMap<String, IdentityInfo> =
            serde_json::from_str(&text).map_err(|_| "invalid JSON map".to_string())?;
        Ok(Self::from_map(map))
    }
}

impl IdentityProvider for StaticProvider {
    fn lookup(&self, vantage_label: &str) -> Option<IdentityInfo> {
        let label = vantage_label.to_lowercase();
        for (key, info) in &self.entries {
            if label.contains(&key.to_lowercase()) {
                return Some(info.clone());
            }
        }
        None
    }
}

pub type SharedProvider = Arc<dyn IdentityProvider>;

pub fn null_provider() -> SharedProvider {
    Arc::new(NullProvider)
}

/// Extracts `AS12345` from org strings like `AS15169 Google LLC`.
pub fn asn_from_org(org: &str) -> Option<String> {
    let first = org.split_whitespace().next()?;
    if first.len() > 2
        && first.starts_with("AS")
        && first[2..].chars().all(|c| c.is_ascii_digit())
    {
        Some(first.to_string())
    } else {
        None
    }
}

const IDENTITY_ENDPOINT: &str = "https://ipinfo.io/json";

/// Learns egress identity by querying a fixed endpoint *through* the vantage,
/// so the observed IP is the one the web actually sees from that path.
/// Any failure (DNS, timeout, rate limit, bad JSON) degrades to None.
pub fn auto_lookup(
    vantage: &VantagePoint,
    timeout_total: Duration,
    timeout_connect: Duration,
) -> Option<IdentityInfo> {
    auto_lookup_with(vantage, IDENTITY_ENDPOINT, timeout_total, timeout_connect)
}

fn auto_lookup_with(
    vantage: &VantagePoint,
    endpoint: &str,
    timeout_total: Duration,
    timeout_connect: Duration,
) -> Option<IdentityInfo> {
    if matches!(vantage, VantagePoint::RemoteProbe(_)) {
        return None;
    }
    let req = ExecRequest {
        url: endpoint.to_string(),
        method: "GET".to_string(),
        headers: vec![],
        user_agent: "seekr/0.1".to_string(),
        timeout_total,
        timeout_connect,
        max_redirects: 3,
        max_body_bytes: 64 * 1024,
        retries: 0,
    };
    let raw = execute(vantage, &req).ok()?;
    if raw.status != 200 || raw.truncated {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&raw.body_prefix).ok()?;
    let country = v.get("country").and_then(|c| c.as_str()).map(|s| s.to_string());
    let ip = v.get("ip").and_then(|c| c.as_str()).map(|s| s.to_string());
    let asn = v
        .get("org")
        .and_then(|c| c.as_str())
        .and_then(asn_from_org);
    if country.is_none() && ip.is_none() {
        return None;
    }
    Some(IdentityInfo {
        ip,
        country,
        accuracy_radius_km: None,
        asn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_yields_none() {
        assert!(NullProvider.lookup("direct").is_none());
    }

    #[test]
    fn static_matches_substring_case_insensitive() {        let mut map = HashMap::new();
        map.insert(
            "sg-proxy".to_string(),
            IdentityInfo {
                country: Some("SG".to_string()),
                ..Default::default()
            },
        );
        let p = StaticProvider::from_map(map);
        assert_eq!(
            p.lookup("http://SG-PROXY.example:8080")
                .unwrap()
                .country
                .as_deref(),
            Some("SG")
        );
        assert!(p.lookup("direct").is_none());
    }
}

#[cfg(test)]
mod auto_tests {
    use super::*;
    use crate::domain::vantage::VantagePoint;

    #[test]
    fn asn_parses_org_prefix() {
        assert_eq!(
            asn_from_org("AS15169 Google LLC").as_deref(),
            Some("AS15169")
        );
        assert_eq!(asn_from_org("Google LLC"), None);
        assert_eq!(asn_from_org(""), None);
        assert_eq!(asn_from_org("ASX Google"), None);
    }

    #[test]
    fn auto_degrades_on_unreachable_endpoint() {
        let v = VantagePoint::Direct;
        let r = auto_lookup_with(
            &v,
            "http://127.0.0.1:9/json",
            Duration::from_secs(3),
            Duration::from_secs(2),
        );
        assert!(r.is_none());
    }
}
