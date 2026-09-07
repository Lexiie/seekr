use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    IpRestriction,
    GeoRestriction,
    RateLimit,
    WafChallenge,
    NetworkFailure,
    ProxyFailure,
    ServerError,
    TlsFailure,
    DnsFailure,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    #[serde(rename = "kind")]
    pub kind: SignalKind,
    pub confidence: f32,
    pub evidence: Vec<String>,
}
