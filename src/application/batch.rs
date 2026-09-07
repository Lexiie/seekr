use std::fs;
use std::sync::mpsc;
use std::thread;

use serde::Serialize;

use crate::application::{RunOptions, diagnose};
use crate::error::SeekrError;
use crate::output::JsonResult;

#[derive(Debug, Serialize)]
pub struct BatchReport {
    pub schema_version: String,
    pub results: Vec<BatchItem>,
    pub summary: BatchSummary,
    pub exit_code: i32,
}

#[derive(Debug, Serialize)]
pub struct BatchItem {
    pub target: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JsonResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub exit_code: i32,
}

#[derive(Debug, Default, Serialize)]
pub struct BatchSummary {
    pub total: usize,
    pub healthy: usize,
    pub restricted: usize,
    pub failed: usize,
    pub partial: usize,
    pub skipped_lines: usize,
}

/// Reads one URL per line; `#` comments and blanks ignored.
/// Returns (targets, skipped_invalid).
pub fn read_targets_file(path: &str) -> Result<(Vec<String>, usize), SeekrError> {
    let text = fs::read_to_string(path)
        .map_err(|_| SeekrError::InvalidTarget(format!("cannot read file: {path}")))?;
    let mut targets = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Validate early so one bad line never kills the batch.
        match crate::domain::target::Target::parse(line) {
            Ok(_) => targets.push(line.to_string()),
            Err(e) => {
                eprintln!("warning: skipping target: {e}");
                skipped += 1;
            }
        }
    }
    Ok((targets, skipped))
}

fn run_one(target: String, opts: RunOptions) -> BatchItem {
    match diagnose::run(&target, &opts) {
        Ok(rep) => {
            let kind = rep
                .result
                .diagnosis
                .as_ref()
                .map(|d| d.kind.as_str().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            BatchItem {
                target,
                status: kind,
                result: Some(rep.result),
                error: None,
                exit_code: rep.exit_code,
            }
        }
        Err(e) => {
            let code = e.exit_code();
            BatchItem {
                target,
                status: "error".to_string(),
                result: None,
                error: Some(e.to_string()),
                exit_code: code,
            }
        }
    }
}

fn aggregate(items: &[BatchItem]) -> i32 {
    let mut has6 = false;
    let mut has5 = false;
    let mut has4 = false;
    let mut has3 = false;
    let mut has1 = false;
    let mut has7 = false;
    for i in items {
        match i.exit_code {
            6 => has6 = true,
            5 => has5 = true,
            4 => has4 = true,
            3 => has3 = true,
            1 => has1 = true,
            7 => has7 = true,
            _ => {}
        }
    }
    if has6 {
        6
    } else if has5 {
        5
    } else if has4 {
        4
    } else if has3 {
        3
    } else if has1 {
        1
    } else if has7 {
        7
    } else {
        0
    }
}

pub fn run(file: &str, opts: &RunOptions, concurrency: usize) -> Result<BatchReport, SeekrError> {
    let (targets, skipped_lines) = read_targets_file(file)?;
    if targets.is_empty() {
        return Err(SeekrError::InvalidTarget("no valid targets in file".to_string()));
    }
    let limit = concurrency.max(1);
    // Bounded worker pool over a shared queue; results collected in order.
    let total = targets.len();
    let (tx, rx) = mpsc::channel::<(usize, BatchItem)>();
    let queue: Vec<(usize, String)> = targets.into_iter().enumerate().collect();
    let queue = std::sync::Arc::new(std::sync::Mutex::new(queue.into_iter()));
    let workers = limit.min(total).max(1);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let q = queue.clone();
        let tx = tx.clone();
        let opts = opts.clone();
        handles.push(thread::spawn(move || loop {
            let next = q.lock().unwrap().next();
            match next {
                Some((idx, target)) => {
                    let item = run_one(target, opts.clone());
                    let _ = tx.send((idx, item));
                }
                None => break,
            }
        }));
    }
    drop(tx);
    let mut items: Vec<Option<BatchItem>> = Vec::new();
    items.resize_with(total, || None);
    for (idx, item) in rx {
        if idx < items.len() {
            items[idx] = Some(item);
        }
    }
    for h in handles {
        let _ = h.join();
    }
    let results: Vec<BatchItem> = items.into_iter().flatten().collect();
    let mut summary = BatchSummary {
        total: results.len(),
        skipped_lines,
        ..Default::default()
    };
    for r in &results {
        match r.exit_code {
            0 => summary.healthy += 1,
            1 => summary.restricted += 1,
            7 => summary.partial += 1,
            _ => summary.failed += 1,
        }
    }
    let exit_code = aggregate(&results);
    Ok(BatchReport {
        schema_version: "1".to_string(),
        results,
        summary,
        exit_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn skips_bad_lines() {
        let mut p = std::env::temp_dir();
        p.push("seekr_batch_test.txt");
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "https://example.com/").unwrap();
        writeln!(f, "not a url").unwrap();
        let (targets, skipped) = read_targets_file(p.to_str().unwrap()).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(skipped, 1);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn aggregate_priority() {
        let mk = |code| BatchItem {
            target: "x".to_string(),
            status: "s".to_string(),
            result: None,
            error: None,
            exit_code: code,
        };
        assert_eq!(aggregate(&[mk(0), mk(1), mk(7)]), 1);
        assert_eq!(aggregate(&[mk(0), mk(7)]), 7);
        assert_eq!(aggregate(&[mk(4), mk(1)]), 4);
        assert_eq!(aggregate(&[mk(0)]), 0);
    }
}
