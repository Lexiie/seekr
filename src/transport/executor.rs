use std::io::Read;
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, ClientBuilder};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::domain::target::sanitize_url_str;
use crate::domain::vantage::VantagePoint;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    #[error("dns failure")]
    DnsFailure,
    #[error("tcp refused")]
    TcpRefused,
    #[error("tcp timeout")]
    TcpTimeout,
    #[error("tls failure")]
    TlsFailure,
    #[error("proxy auth failure")]
    ProxyAuthFailure,
    #[error("proxy refused")]
    ProxyRefused,
    #[error("proxy timeout")]
    ProxyTimeout,
    #[error("timeout")]
    Timeout,
    #[error("redirect loop")]
    RedirectLoop,
    #[error("body too large")]
    BodyTooLarge,
    #[error("network failure")]
    NetworkFailure,
}

#[derive(Clone)]
pub struct ExecRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub user_agent: String,
    pub timeout_total: Duration,
    pub timeout_connect: Duration,
    pub max_redirects: usize,
    pub max_body_bytes: u64,
    pub retries: u32,
}

impl std::fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header values never appear in debug output; names only.
        let names: Vec<&String> = self.headers.iter().map(|(k, _)| k).collect();
        f.debug_struct("ExecRequest")
            .field("url", &crate::domain::target::sanitize_url_str(&self.url))
            .field("method", &self.method)
            .field("header_names", &names)
            .field("timeout_total", &self.timeout_total)
            .field("max_redirects", &self.max_redirects)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub final_url: String,
    pub redirect_chain: Vec<String>,
    pub body_prefix: Vec<u8>,
    pub truncated: bool,
    pub content_type: Option<String>,
    pub total_ms: u64,
}

fn classify(reqwest_err: &reqwest::Error, via_proxy: bool) -> TransportError {
    let msg = reqwest_err.to_string().to_lowercase();
    if via_proxy
        && (msg.contains("407") || msg.contains("proxy authentication") || msg.contains("proxy auth"))
    {
        return TransportError::ProxyAuthFailure;
    }
    if reqwest_err.is_timeout() {
        return if via_proxy {
            TransportError::ProxyTimeout
        } else {
            TransportError::Timeout
        };
    }
    if reqwest_err.is_redirect() {
        return TransportError::RedirectLoop;
    }
    if reqwest_err.is_connect() {
        let s = reqwest_err.to_string().to_lowercase();
        if s.contains("dns") || s.contains("resolve") || s.contains("name") {
            return TransportError::DnsFailure;
        }
        if s.contains("tls") || s.contains("ssl") || s.contains("certificate") {
            return TransportError::TlsFailure;
        }
        if via_proxy {
            return TransportError::ProxyRefused;
        }
        return TransportError::TcpRefused;
    }
    if reqwest_err.is_decode() {
        return TransportError::NetworkFailure;
    }
    let s = reqwest_err.to_string().to_lowercase();
    if s.contains("tls") || s.contains("certificate") {
        return TransportError::TlsFailure;
    }
    if via_proxy {
        TransportError::ProxyRefused
    } else {
        TransportError::NetworkFailure
    }
}

fn build_client(
    vantage: &VantagePoint,
    timeout_total: Duration,
    timeout_connect: Duration,
    max_redirects: usize,
) -> Result<Client, TransportError> {
    let policy = Policy::limited(max_redirects);
    let mut builder = ClientBuilder::new()
        .timeout(timeout_total)
        .connect_timeout(timeout_connect)
        .redirect(policy);
    match vantage {
        VantagePoint::Direct => {}
        VantagePoint::HttpProxy(c) | VantagePoint::HttpsProxy(c) => {
            let proxy = reqwest::Proxy::all(&c.url_with_auth)
                .map_err(|_| TransportError::ProxyRefused)?;
            builder = builder.proxy(proxy);
        }
        VantagePoint::Socks5(c) => {
            let proxy = reqwest::Proxy::all(&c.url_with_auth)
                .map_err(|_| TransportError::ProxyRefused)?;
            builder = builder.proxy(proxy);
        }
        VantagePoint::RemoteProbe(_) => return Err(TransportError::NetworkFailure),
    }
    builder.build().map_err(|_| TransportError::NetworkFailure)
}

fn is_safe_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

pub fn execute(
    vantage: &VantagePoint,
    req: &ExecRequest,
) -> Result<RawResponse, TransportError> {
    if matches!(vantage, VantagePoint::RemoteProbe(_)) {
        return Err(TransportError::NetworkFailure);
    }
    let via_proxy = !matches!(vantage, VantagePoint::Direct);
    let client = build_client(vantage, req.timeout_total, req.timeout_connect, req.max_redirects)?;
    let attempts = if is_safe_method(req.method.as_str()) {
        req.retries + 1
    } else {
        1
    };
    let mut last_err = TransportError::NetworkFailure;
    for _ in 0..attempts {
        match attempt(&client, req, via_proxy) {
            Ok(r) => return Ok(r),
            Err(e) => {
                last_err = e.clone();
                let retryable = matches!(
                    e,
                    TransportError::Timeout | TransportError::TcpTimeout
                );
                if !retryable {
                    return Err(e);
                }
            }
        }
    }
    Err(last_err)
}

fn attempt(client: &Client, req: &ExecRequest, via_proxy: bool) -> Result<RawResponse, TransportError> {
    let method: reqwest::Method = req
        .method
        .parse()
        .map_err(|_| TransportError::NetworkFailure)?;
    let mut rb = client
        .request(method, &req.url)
        .header("User-Agent", req.user_agent.clone())
        .header("Accept", "*/*");
    for (k, v) in &req.headers {
        rb = rb.header(k.clone(), v.clone());
    }
    let start = Instant::now();
    let resp = rb.send().map_err(|e| classify(&e, via_proxy))?;
    let status = resp.status().as_u16();
    let final_url = sanitize_url_str(resp.url().as_str());
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("[UNREADABLE]").to_string(),
            )
        })
        .collect();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Stream with cap: read at most max+1 to detect truncation.
    let limit = req.max_body_bytes.saturating_add(1) as usize;
    let mut body: Vec<u8> = Vec::new();
    let mut limited = resp.take(limit as u64);
    limited
        .read_to_end(&mut body)
        .map_err(|_| TransportError::NetworkFailure)?;
    let truncated = (body.len() as u64) > req.max_body_bytes;
    if truncated {
        body.truncate(req.max_body_bytes as usize);
    }
    let total_ms = start.elapsed().as_millis() as u64;
    Ok(RawResponse {
        status,
        headers,
        final_url,
        redirect_chain: vec![],
        body_prefix: body,
        truncated,
        content_type,
        total_ms,
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(h.finalize().as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    const C: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(C[(b >> 4) as usize] as char);
        s.push(C[(b & 0xf) as usize] as char);
    }
    s
}

pub fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&body[..body.len().min(65536)]).to_lowercase();
    let start = text.find("<title")?;
    let after = text[start..].find('>')?;
    let rest = &text[start + after + 1..];
    let end = rest.find("</title>")?;
    let title = rest[..end].trim();
    if title.is_empty() {
        return None;
    }
    let clean: String = title.chars().take(500).collect();
    Some(clean)
}

pub fn challenge_markers(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(&body[..body.len().min(131072)]).to_lowercase();
    let mut out = Vec::new();
    let rules = [
        ("cf-challenge", "cf_challenge"),
        ("challenge-platform", "cf_challenge"),
        ("just a moment", "js_challenge"),
        ("checking your browser", "js_challenge"),
        ("datadome", "dd_challenge"),
        ("recaptcha", "captcha_wall"),
        ("captcha", "captcha_wall"),
        ("meta http-equiv=\"refresh\"", "meta_refresh"),
    ];
    for (needle, marker) in rules {
        if text.contains(needle) && !out.iter().any(|m| m == marker) {
            out.push(marker.to_string());
        }
    }
    out
}

pub fn semantic_markers(status: u16, body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(&body[..body.len().min(131072)]).to_lowercase();
    let mut out = Vec::new();
    if text.contains("not available in your country")
        || text.contains("not available in your location")
        || text.contains("not available where you are")
        || text.contains("available in your region")
        || text.contains("only available in the us")
        || text.contains("only available in the united states")
        || text.contains("geo-block")
        || text.contains("geoblocked")
    {
        out.push("geo_notice".to_string());
    }
    if text.contains("access denied") || text.contains("forbidden") || status == 403 {
        out.push("block_notice".to_string());
    }
    if status == 429 || text.contains("too many requests") || text.contains("rate limit") {
        out.push("rate_notice".to_string());
    }
    if body.is_empty() {
        out.push("empty_body".to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_methods() {
        assert!(is_safe_method("GET"));
        assert!(!is_safe_method("POST"));
    }

    #[test]
    fn error_display_has_no_secrets() {
        let e = TransportError::ProxyAuthFailure;
        assert!(!format!("{e}").contains("pass"));
    }

    #[test]
    fn debug_hides_header_values_and_url_secrets() {
        let r = ExecRequest {
            url: "https://user:pw@example.com/?token=abc".to_string(),
            method: "GET".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer s3cr3t".to_string())],
            user_agent: "t".to_string(),
            timeout_total: Duration::from_secs(15),
            timeout_connect: Duration::from_secs(5),
            max_redirects: 10,
            max_body_bytes: 1024,
            retries: 1,
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("s3cr3t"));
        assert!(!dbg.contains("pw"));
        assert!(!dbg.contains("abc"));
        assert!(dbg.contains("Authorization"));
    }
}
