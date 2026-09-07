use crate::application::trace::TraceReport;
use crate::domain::diagnosis::Diagnosis;
use crate::domain::evidence::Evidence;

fn fmt_stage(ok: Option<bool>, ms: Option<u64>) -> String {
    let s = match ok {
        Some(true) => "ok",
        Some(false) => "fail",
        None => "-",
    };
    match ms {
        Some(m) => format!("{s} ({m} ms)"),
        None => s.to_string(),
    }
}

pub fn print_trace(report: &TraceReport) {
    println!("target: {} ({} ms)", report.target, report.duration_ms);
    for st in &report.stages {
        println!("  [{}] {}", st.vantage, st.vantage_kind);
        println!("    dns:  {}", fmt_stage(st.dns.ok, st.dns.duration_ms));
        println!("    tcp:  {}", fmt_stage(st.tcp.ok, st.tcp.duration_ms));
        println!("    tls:  {}", fmt_stage(st.tls.ok, st.tls.duration_ms));
        println!(
            "    http: {}",
            st.http
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        if let Some(u) = &st.http.final_url {
            println!("    final: {u}");
        }
        println!(
            "    identity: ip={} country={} asn={}",
            st.identity.ip.as_deref().unwrap_or("-"),
            st.identity.country.as_deref().unwrap_or("-"),
            st.identity.asn.as_deref().unwrap_or("-"),
        );
        println!(
            "    content: {} bytes{}",
            st.content.length.map(|l| l.to_string()).unwrap_or_else(|| "-".to_string()),
            if st.content.partial { " (partial)" } else { "" }
        );
    }
    if report.skipped_proxies > 0 {
        println!("skipped proxies: {}", report.skipped_proxies);
    }
}

pub fn print_human(
    target: &str,
    evidence: &[Evidence],
    diagnosis: Option<&Diagnosis>,
    duration_ms: u64,
) {
    println!("target: {target} ({duration_ms} ms)");
    for e in evidence {
        let status = e
            .response
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| e.error.clone().unwrap_or_else(|| "no response".to_string()));
        let country = e.network.country.as_deref().unwrap_or("-");
        let total = e
            .timing
            .total_ms
            .map(|m| format!("{m} ms"))
            .unwrap_or_else(|| "-".to_string());
        let partial = if e.content.partial { " partial" } else { "" };
        println!(
            "  [{}] {} country={country} latency={total}{partial}",
            e.vantage, status
        );
    }
    match diagnosis {
        Some(d) => {
            println!(
                "diagnosis: {} ({:.2}, {})",
                d.kind.as_str(),
                d.confidence,
                d.qualifier()
            );
            println!("evidence: {}", d.evidence_ids.join(", "));
            println!("interpretation: {}", d.interpretation);
            if let Some(next) = &d.next_step {
                println!("next: {next}");
            }
        }
        None => println!("diagnosis: (not computed for this command)"),
    }
}
