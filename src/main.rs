use std::process::ExitCode;

use clap::{CommandFactory, Parser};
use seekr::application::RunOptions;
use seekr::cli::{Cli, Command, parse_headers};
use seekr::output::{print_human, print_json, print_trace};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let headers = match parse_headers(&cli.header) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let opts = RunOptions {
        proxy: cli.proxy,
        proxy_file: cli.proxy_file,
        no_direct: cli.no_direct,
        timeout_secs: cli.timeout,
        retries: cli.retries,
        method: cli.method.to_uppercase(),
        headers,
        user_agent: cli.user_agent,
        max_probes: cli.max_probes,
        identity_lookup: !cli.no_identity_lookup,
        geo_map: cli.geo_map,
    };
    if cli.verbose {
        eprintln!("seekr: starting run");
    }
    match cli.command {
        Command::Diagnose { url } => match seekr::application::diagnose::run(&url, &opts) {
            Ok(rep) => {
                emit(&rep.result, rep.exit_code, cli.json, cli.quiet);
                ExitCode::from(rep.exit_code as u8)
            }
            Err(e) => fail(e),
        },
        Command::Compare { url } => match seekr::application::compare::run(&url, &opts) {
            Ok(rep) => {
                emit(&rep.result, rep.exit_code, cli.json, cli.quiet);
                ExitCode::from(rep.exit_code as u8)
            }
            Err(e) => fail(e),
        },
        Command::Probe { url } => match seekr::application::probe::run(&url, &opts) {
            Ok(rep) => {
                emit(&rep.result, rep.exit_code, cli.json, cli.quiet);
                ExitCode::from(rep.exit_code as u8)
            }
            Err(e) => fail(e),
        },
        Command::Completions { shell } => {
            let gen = match shell.to_lowercase().as_str() {
                "bash" => clap_complete::Shell::Bash,
                "zsh" => clap_complete::Shell::Zsh,
                "fish" => clap_complete::Shell::Fish,
                "powershell" | "power-shell" => clap_complete::Shell::PowerShell,
                "elvish" => clap_complete::Shell::Elvish,
                other => {
                    eprintln!("error: unknown shell: {other}");
                    return ExitCode::from(2);
                }
            };
            let mut cmd = Cli::command();
            clap_complete::generate(gen, &mut cmd, "seekr", &mut std::io::stdout());
            ExitCode::from(0)
        }
        Command::Watch {
            url,
            interval_secs,
            times,
            alert_on,
        } => {
            use std::time::Duration;
            let mode = match seekr::application::watch::AlertMode::parse(&alert_on) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            if interval_secs == 0 {
                eprintln!("error: --interval must be at least 1");
                return ExitCode::from(2);
            }
            if matches!(times, Some(0)) {
                eprintln!("error: --times must be at least 1");
                return ExitCode::from(2);
            }
            let cfg = seekr::application::watch::WatchConfig {
                interval: Duration::from_secs(interval_secs),
                times,
                mode,
            };
            let json = cli.json;
            let quiet = cli.quiet;
            let mut last_code = 0;
            match seekr::application::watch::run(&url, &opts, &cfg, |ev| {
                last_code = ev.result.diagnosis.as_ref().map(|d| d.kind.exit_code()).unwrap_or(0);
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&ev)
                            .unwrap_or_else(|_| "{}".to_string())
                    );
                } else if quiet {
                    if let Some(d) = &ev.result.diagnosis {
                        println!("#{} {}", ev.run_index, d.kind.as_str());
                    }
                } else {
                    print_human(
                        &ev.result.target.url,
                        &ev.result.evidence,
                        ev.result.diagnosis.as_ref(),
                        ev.result.duration_ms,
                    );
                }
                if ev.changed {
                    eprintln!(
                        "ALERT run #{}: {} -> {}",
                        ev.run_index,
                        ev.prev_kind.as_deref().unwrap_or("-"),
                        ev.result
                            .diagnosis
                            .as_ref()
                            .map(|d| d.kind.as_str())
                            .unwrap_or("unknown")
                    );
                }
            }) {
                Ok(_) => ExitCode::from(last_code as u8),
                Err(e) => fail(e),
            }
        }
        Command::Batch { file } => {
            if cli.concurrency == 0 {
                eprintln!("error: --concurrency must be at least 1");
                return ExitCode::from(2);
            }
            match seekr::application::batch::run(&file, &opts, cli.concurrency) {
                Ok(rep) => {
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&rep)
                                .unwrap_or_else(|_| "{}".to_string())
                        );
                    } else if cli.quiet {
                        println!("batch: {}", rep.summary.restricted);
                    } else {
                        for item in &rep.results {
                            match &item.result {
                                Some(r) => print_human(
                                    &r.target.url,
                                    &r.evidence,
                                    r.diagnosis.as_ref(),
                                    r.duration_ms,
                                ),
                                None => println!(
                                    "target: {} error: {}",
                                    item.target,
                                    item.error.as_deref().unwrap_or("failed")
                                ),
                            }
                        }
                        println!(
                            "summary: total={} healthy={} restricted={} partial={} failed={} skipped_lines={}",
                            rep.summary.total,
                            rep.summary.healthy,
                            rep.summary.restricted,
                            rep.summary.partial,
                            rep.summary.failed,
                            rep.summary.skipped_lines,
                        );
                    }
                    ExitCode::from(rep.exit_code as u8)
                }
                Err(e) => fail(e),
            }
        }
        Command::Trace { url } => match seekr::application::trace::run(&url, &opts) {
            Ok(rep) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&rep)
                            .unwrap_or_else(|_| "{}".to_string())
                    );
                } else if cli.quiet {
                    println!("trace");
                } else {
                    print_trace(&rep);
                }
                ExitCode::from(rep.exit_code as u8)
            }
            Err(e) => fail(e),
        },
    }
}

fn emit(result: &seekr::output::JsonResult, code: i32, json: bool, quiet: bool) -> i32 {
    if quiet && !json {
        if let Some(d) = &result.diagnosis {
            println!("{}", d.kind.as_str());
        } else if result.diffs.as_ref().map(|d| !d.is_empty()).unwrap_or(false) {
            println!("difference");
        } else {
            println!("healthy");
        }
        return code;
    }
    if json {
        print_json(result);
    } else {
        print_human(
            &result.target.url,
            &result.evidence,
            result.diagnosis.as_ref(),
            result.duration_ms,
        );
        if result.skipped_proxies > 0 {
            println!("skipped proxies: {}", result.skipped_proxies);
        }
    }
    code
}

fn fail(e: seekr::error::SeekrError) -> ExitCode {
    eprintln!("error: {e}");
    ExitCode::from(e.exit_code() as u8)
}
