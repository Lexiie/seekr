use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisKind {
    Healthy,
    GeoRestriction,
    IpRestriction,
    RateLimit,
    WafChallenge,
    ProxyFailure,
    ServerError,
    NetworkFailure,
    DnsFailure,
    TlsFailure,
    Unknown,
}

impl DiagnosisKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiagnosisKind::Healthy => "healthy",
            DiagnosisKind::GeoRestriction => "geo_restriction",
            DiagnosisKind::IpRestriction => "ip_restriction",
            DiagnosisKind::RateLimit => "rate_limit",
            DiagnosisKind::WafChallenge => "waf_challenge",
            DiagnosisKind::ProxyFailure => "proxy_failure",
            DiagnosisKind::ServerError => "server_error",
            DiagnosisKind::NetworkFailure => "network_failure",
            DiagnosisKind::DnsFailure => "dns_failure",
            DiagnosisKind::TlsFailure => "tls_failure",
            DiagnosisKind::Unknown => "unknown",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            DiagnosisKind::Healthy => 0,
            DiagnosisKind::GeoRestriction
            | DiagnosisKind::IpRestriction
            | DiagnosisKind::RateLimit
            | DiagnosisKind::WafChallenge => 1,
            DiagnosisKind::ServerError
            | DiagnosisKind::NetworkFailure
            | DiagnosisKind::DnsFailure
            | DiagnosisKind::TlsFailure => 3,
            DiagnosisKind::ProxyFailure => 4,
            DiagnosisKind::Unknown => 7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    #[serde(rename = "kind")]
    pub kind: DiagnosisKind,
    pub confidence: f32,
    pub evidence_ids: Vec<String>,
    pub interpretation: String,
    pub next_step: Option<String>,
}

impl Diagnosis {
    pub fn qualifier(&self) -> &'static str {
        if self.confidence >= 0.80 {
            "confirmed"
        } else if self.confidence >= 0.50 {
            "likely"
        } else {
            "unknown"
        }
    }
}
