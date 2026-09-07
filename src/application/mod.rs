pub mod batch;
pub mod compare;
pub mod diagnose;
pub mod probe;
pub mod trace;

use std::fs;
use std::time::Duration;

use crate::domain::target::Target;
use crate::domain::vantage::{VantagePoint, parse_proxy};
use crate::error::SeekrError;
use crate::identity::{SharedProvider, StaticProvider, null_provider};
use crate::planner::select_vantages;
use crate::probes::plan::{ConfirmationPolicy, ProbeLimits, ProbePlan};

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub proxy: Option<String>,
    pub proxy_file: Option<String>,
    pub no_direct: bool,
    pub timeout_secs: u64,
    pub retries: u32,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub user_agent: String,
    pub max_probes: usize,
    pub identity_lookup: bool,
    pub geo_map: Option<String>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            proxy: None,
            proxy_file: None,
            no_direct: false,
            timeout_secs: 15,
            retries: 1,
            method: "GET".to_string(),
            headers: vec![],
            user_agent: "seekr/0.1".to_string(),
            max_probes: 10,
            identity_lookup: true,
            geo_map: None,
        }
    }
}

pub struct Prepared {
    pub plan: ProbePlan,
    pub skipped_proxies: usize,
}

pub fn read_proxy_file(path: &str) -> Result<Vec<VantagePoint>, SeekrError> {
    let text = fs::read_to_string(path)
        .map_err(|_| SeekrError::InvalidProxy(format!("cannot read proxy file: {path}")))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_proxy(line) {
            Ok(v) => out.push(v),
            Err(e) => eprintln!("warning: skipping proxy entry: {e}"),
        }
    }
    Ok(out)
}

pub fn prepare(url: &str, opts: &RunOptions) -> Result<Prepared, SeekrError> {
    let target = Target::parse(url).map_err(SeekrError::InvalidTarget)?;
    let mut proxies = Vec::new();
    if let Some(p) = &opts.proxy {
        proxies.push(parse_proxy(p).map_err(SeekrError::InvalidProxy)?);
    }
    if let Some(f) = &opts.proxy_file {
        proxies.extend(read_proxy_file(f)?);
    }
    let include_direct = !opts.no_direct;
    if !include_direct && proxies.is_empty() {
        return Err(SeekrError::NoVantage);
    }
    let max = opts.max_probes.max(1);
    let sel = select_vantages(include_direct, proxies, max);
    if sel.selected.is_empty() {
        return Err(SeekrError::NoVantage);
    }
    // Non-safe methods never get automatic retries.
    let retries = match opts.method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "TRACE" => opts.retries,
        _ => 0,
    };
    let identity: SharedProvider = match &opts.geo_map {
        Some(path) if opts.identity_lookup => match StaticProvider::load_file(path) {
            Ok(p) => std::sync::Arc::new(p),
            Err(e) => {
                // Provider failure degrades identity evidence, never the run.
                eprintln!("warning: identity map ignored: {e}");
                null_provider()
            }
        },
        _ => null_provider(),
    };
    Ok(Prepared {
        plan: ProbePlan {
            target,
            vantages: sel.selected,
            method: opts.method.clone(),
            headers: opts.headers.clone(),
            user_agent: opts.user_agent.clone(),
            confirmation: ConfirmationPolicy::default(),
            limits: ProbeLimits {
                max_probes: max,
                timeout_total: Duration::from_secs(opts.timeout_secs),
                timeout_connect: Duration::from_secs(5),
                retries,
                max_redirects: 10,
                max_body_bytes: 2 * 1024 * 1024,
            },
            identity_lookup: opts.identity_lookup,
            identity,
        },
        skipped_proxies: sel.skipped,
    })
}
