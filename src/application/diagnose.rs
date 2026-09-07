use std::time::Instant;

use crate::application::{RunOptions, prepare};
use crate::comparison::compare_all;
use crate::detectors::detect_all;
use crate::diagnosis::resolve;
use crate::error::SeekrError;
use crate::output::{JsonResult, JsonTarget};
use crate::probes::run_plan;

pub struct DiagnoseReport {
    pub result: JsonResult,
    pub exit_code: i32,
}

pub fn run(url: &str, opts: &RunOptions) -> Result<DiagnoseReport, SeekrError> {
    let start = Instant::now();
    let prepared = prepare(url, opts)?;
    let outcome = run_plan(&prepared.plan);
    let diffs = compare_all(&outcome.evidence);
    let signals = detect_all(&outcome.evidence, &diffs);
    let diagnosis = resolve(&outcome.evidence, &signals);
    let exit_code = diagnosis.kind.exit_code();
    let duration_ms = start.elapsed().as_millis() as u64;
    let result = JsonResult {
        schema_version: "1".to_string(),
        target: JsonTarget {
            url: prepared.plan.target.url.clone(),
        },
        duration_ms,
        vantages: outcome.evidence.clone(),
        evidence: outcome.evidence,
        signals,
        diagnosis: Some(diagnosis),
        diffs: Some(diffs),
        skipped_proxies: prepared.skipped_proxies,
        probes_used: outcome.probes_used,
    };
    Ok(DiagnoseReport { result, exit_code })
}
