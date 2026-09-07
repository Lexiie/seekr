use std::time::Instant;

use crate::application::{RunOptions, prepare};
use crate::error::SeekrError;
use crate::output::{JsonResult, JsonTarget};
use crate::probes::run_plan;

pub struct ProbeReport {
    pub result: JsonResult,
    pub exit_code: i32,
}

pub fn run(url: &str, opts: &RunOptions) -> Result<ProbeReport, SeekrError> {
    let start = Instant::now();
    let prepared = prepare(url, opts)?;
    let outcome = run_plan(&prepared.plan);
    let duration_ms = start.elapsed().as_millis() as u64;
    let result = JsonResult {
        schema_version: "1".to_string(),
        target: JsonTarget {
            url: prepared.plan.target.url.clone(),
        },
        duration_ms,
        vantages: outcome.evidence.clone(),
        evidence: outcome.evidence,
        signals: vec![],
        diagnosis: None,
        diffs: None,
        skipped_proxies: prepared.skipped_proxies,
        probes_used: outcome.probes_used,
    };
    Ok(ProbeReport {
        result,
        exit_code: 0,
    })
}
