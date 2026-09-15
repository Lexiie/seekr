use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::application::{RunOptions, diagnose};
use crate::domain::diagnosis::Diagnosis;
use crate::error::SeekrError;
use crate::output::JsonResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertMode {
    Change,
    Restriction,
}

impl AlertMode {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "change" => Ok(AlertMode::Change),
            "restriction" => Ok(AlertMode::Restriction),
            other => Err(format!("bad alert mode: {other} (want change|restriction)")),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WatchEvent {
    pub run_index: u64,
    pub changed: bool,
    pub prev_kind: Option<String>,
    #[serde(flatten)]
    pub result: JsonResult,
}

/// True when an alert should fire for this transition, plus the previous kind.
pub fn should_alert(
    mode: &AlertMode,
    prev: Option<&Diagnosis>,
    curr: &Option<Diagnosis>,
) -> (bool, Option<String>) {
    let prev_kind = prev.map(|d| d.kind.as_str().to_string());
    let curr_kind = curr.as_ref().map(|d| d.kind.as_str().to_string());
    match mode {
        // No alert on the very first run (nothing changed *from* yet).
        AlertMode::Change => (prev.is_some() && prev_kind != curr_kind, prev_kind),
        AlertMode::Restriction => {
            let bad = matches!(
                curr_kind.as_deref(),
                Some("geo_restriction")
                    | Some("ip_restriction")
                    | Some("rate_limit")
                    | Some("waf_challenge")
            );
            (bad, prev_kind)
        }
    }
}

pub struct WatchConfig {
    pub interval: Duration,
    pub times: Option<u64>,
    pub mode: AlertMode,
}

/// Runs diagnose repeatedly. Sleeps between runs, never before the first.
/// `on_event` receives each run. Returns completed run count.
/// Ctrl-C terminates the process (documented; no partial state kept).
pub fn run(
    url: &str,
    opts: &RunOptions,
    cfg: &WatchConfig,
    mut on_event: impl FnMut(WatchEvent),
) -> Result<u64, SeekrError> {
    let mut prev: Option<Diagnosis> = None;
    let mut runs = 0u64;
    loop {
        if let Some(n) = cfg.times {
            if runs >= n {
                break;
            }
        }
        if runs > 0 {
            thread::sleep(cfg.interval);
        }
        let rep = diagnose::run(url, opts)?;
        let (changed, prev_kind) = should_alert(&cfg.mode, prev.as_ref(), &rep.result.diagnosis);
        runs += 1;
        prev = rep.result.diagnosis.clone();
        on_event(WatchEvent {
            run_index: runs,
            changed,
            prev_kind,
            result: rep.result,
        });
    }
    Ok(runs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::diagnosis::DiagnosisKind;

    fn diag(kind: DiagnosisKind) -> Diagnosis {
        Diagnosis {
            kind,
            confidence: 0.9,
            evidence_ids: vec![],
            interpretation: String::new(),
            next_step: None,
        }
    }

    #[test]
    fn change_fires_only_on_transition() {
        let h = diag(DiagnosisKind::Healthy);
        let g = diag(DiagnosisKind::GeoRestriction);
        // First run never alerts.
        assert!(!should_alert(&AlertMode::Change, None, &Some(h.clone())).0);
        // Same kind: silent.
        assert!(!should_alert(&AlertMode::Change, Some(&h), &Some(h.clone())).0);
        // Transition: alert + prev reported.
        let (fire, prev) = should_alert(&AlertMode::Change, Some(&h), &Some(g));
        assert!(fire);
        assert_eq!(prev.as_deref(), Some("healthy"));
    }

    #[test]
    fn restriction_fires_on_bad_kind_every_run() {
        let g = diag(DiagnosisKind::GeoRestriction);
        let h = diag(DiagnosisKind::Healthy);
        assert!(should_alert(&AlertMode::Restriction, None, &Some(g.clone())).0);
        assert!(!should_alert(&AlertMode::Restriction, None, &Some(h.clone())).0);
        assert!(!should_alert(&AlertMode::Restriction, None, &None).0);
    }

    #[test]
    fn bad_mode_rejected() {
        assert!(AlertMode::parse("sometimes").is_err());
        assert_eq!(AlertMode::parse("CHANGE"), Ok(AlertMode::Change));
    }
}
