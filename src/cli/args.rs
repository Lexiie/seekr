use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "seekr", version, about = "See what the web sees.")]
pub struct Cli {
    #[arg(long, global = true)]
    pub proxy: Option<String>,
    #[arg(long = "proxy-file", global = true)]
    pub proxy_file: Option<String>,
    #[arg(long = "no-direct", global = true)]
    pub no_direct: bool,
    #[arg(long, global = true, default_value_t = 15)]
    pub timeout: u64,
    #[arg(long, global = true, default_value_t = 1)]
    pub retries: u32,
    #[arg(long, global = true, default_value = "GET")]
    pub method: String,
    #[arg(long = "header", global = true)]
    pub header: Vec<String>,
    #[arg(long = "user-agent", global = true, default_value = "seekr/0.1")]
    pub user_agent: String,
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub quiet: bool,
    #[arg(long, global = true)]
    pub verbose: bool,
    #[arg(long = "max-probes", global = true, default_value_t = 10)]
    pub max_probes: usize,
    #[arg(long = "concurrency", global = true, default_value_t = 4)]
    pub concurrency: usize,
    #[arg(long = "no-identity-lookup", global = true)]
    pub no_identity_lookup: bool,
    #[arg(long = "geo-map", global = true)]
    pub geo_map: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Diagnose { url: String },
    Compare { url: String },
    Probe { url: String },
    Trace { url: String },
    Batch { file: String },
    Completions { shell: String },
}

/// Parses repeated `--header "Name: value"` flags.
pub fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for h in raw {
        let (k, v) = h
            .split_once(':')
            .ok_or_else(|| format!("bad header (want 'Name: value'): {h}"))?;
        let k = k.trim().to_string();
        let v = v.trim().to_string();
        if k.is_empty() || v.is_empty() {
            return Err(format!("bad header (want 'Name: value'): {h}"));
        }
        out.push((k, v));
    }
    Ok(out)
}
