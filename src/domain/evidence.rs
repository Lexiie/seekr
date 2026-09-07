use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestEvidence {
    pub method: String,
    pub url: String,
    /// Header names only; values are never stored.
    pub header_names: Vec<String>,
    pub user_agent: String,
    pub vantage: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseEvidence {
    pub status: Option<u16>,
    pub final_url: Option<String>,
    pub redirect_chain: Vec<String>,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub retry_after: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkEvidence {
    pub public_ip: Option<String>,
    pub country: Option<String>,
    pub accuracy_radius_km: Option<u32>,
    pub asn: Option<String>,
    pub proxy_type: Option<String>,
    pub dns_ok: Option<bool>,
    pub tcp_ok: Option<bool>,
    pub tls_ok: Option<bool>,
    pub tls_sni: Option<String>,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingEvidence {
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub request_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub total_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentEvidence {
    pub length: Option<u64>,
    pub sha256: Option<String>,
    pub content_type: Option<String>,
    pub title: Option<String>,
    pub challenge_markers: Vec<String>,
    pub semantic_markers: Vec<String>,
    pub partial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id_prefix: String,
    pub vantage: String,
    pub vantage_kind: String,
    pub request: RequestEvidence,
    pub response: ResponseEvidence,
    pub network: NetworkEvidence,
    pub timing: TimingEvidence,
    pub content: ContentEvidence,
    pub error: Option<String>,
}
