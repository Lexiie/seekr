use serde::Serialize;

use crate::domain::diagnosis::Diagnosis;
use crate::domain::evidence::Evidence;
use crate::domain::signal::Signal;

#[derive(Debug, Serialize)]
pub struct JsonResult {
    pub schema_version: String,
    pub target: JsonTarget,
    pub duration_ms: u64,
    pub vantages: Vec<Evidence>,
    pub evidence: Vec<Evidence>,
    pub signals: Vec<Signal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnosis: Option<Diagnosis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diffs: Option<Vec<String>>,
    pub skipped_proxies: usize,
    pub probes_used: usize,
}

#[derive(Debug, Serialize)]
pub struct JsonTarget {
    pub url: String,
}

pub fn print_json(result: &JsonResult) {
    println!(
        "{}",
        serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
    );
}
