use std::time::Instant;

use serde::Serialize;

use crate::application::{RunOptions, prepare};
use crate::error::SeekrError;
use crate::probes::run_plan;

#[derive(Debug, Clone, Serialize)]
pub struct StageView {
    pub vantage: String,
    pub vantage_kind: String,
    pub dns: StageState,
    pub tcp: StageState,
    pub tls: StageState,
    pub http: HttpStage,
    pub identity: IdentityStage,
    pub content: ContentStage,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageState {
    pub ok: Option<bool>,
    pub duration_ms: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpStage {
    pub status: Option<u16>,
    pub final_url: Option<String>,
    pub redirects_followed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityStage {
    pub ip: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentStage {
    pub sha256: Option<String>,
    pub length: Option<u64>,
    pub partial: bool,
}

#[derive(Debug, Serialize)]
pub struct TraceReport {
    pub schema_version: String,
    pub target: String,
    pub duration_ms: u64,
    pub stages: Vec<StageView>,
    pub skipped_proxies: usize,
    pub exit_code: i32,
}

fn state(ok: Option<bool>, ms: Option<u64>, detail: Option<String>) -> StageState {
    StageState {
        ok,
        duration_ms: ms,
        detail,
    }
}

pub fn run(url: &str, opts: &RunOptions) -> Result<TraceReport, SeekrError> {
    let start = Instant::now();
    let prepared = prepare(url, opts)?;
    let outcome = run_plan(&prepared.plan);
    let mut stages = Vec::new();
    let mut exit_code = 0;
    for e in &outcome.evidence {
        let failed = e.error.is_some();
        if failed && exit_code == 0 {
            exit_code = 3;
        }
        stages.push(StageView {
            vantage: e.vantage.clone(),
            vantage_kind: e.vantage_kind.clone(),
            dns: state(e.network.dns_ok, e.timing.dns_ms, None),
            tcp: state(e.network.tcp_ok, e.timing.tcp_ms, None),
            tls: state(e.network.tls_ok, e.timing.tls_ms, None),
            http: HttpStage {
                status: e.response.status,
                final_url: e.response.final_url.clone(),
                redirects_followed: e.response.redirect_chain.len(),
            },
            identity: IdentityStage {
                ip: e.network.public_ip.clone(),
                country: e.network.country.clone(),
                asn: e.network.asn.clone(),
            },
            content: ContentStage {
                sha256: e.content.sha256.clone(),
                length: e.content.length,
                partial: e.content.partial,
            },
        });
    }
    Ok(TraceReport {
        schema_version: "1".to_string(),
        target: prepared.plan.target.url.clone(),
        duration_ms: start.elapsed().as_millis() as u64,
        stages,
        skipped_proxies: prepared.skipped_proxies,
        exit_code,
    })
}
