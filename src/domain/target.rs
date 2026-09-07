use serde::{Deserialize, Serialize};
use url::Url;

const SENSITIVE_QUERY_KEYS: &[&str] = &["token", "code", "session", "secret", "key", "auth"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub url: String,
    pub host: String,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self, String> {
        let url = Url::parse(input).map_err(|_| format!("cannot parse URL: {input}"))?;
        match url.scheme() {
            "http" | "https" => {}
            other => return Err(format!("unsupported scheme: {other}")),
        }
        if url.host_str().is_none() {
            return Err("URL has no host".to_string());
        }
        let host = url.host_str().unwrap_or("").to_string();
        Ok(Self {
            url: sanitize_url(&url),
            host,
        })
    }

    pub fn raw_url(&self) -> &str {
        &self.url
    }
}

pub fn sanitize_url(url: &Url) -> String {
    let mut out = url.clone();
    // Strip userinfo entirely.
    let _ = out.set_username("");
    let _ = out.set_password(None);
    // Redact sensitive query values, keep keys and order.
    let pairs: Vec<(String, String)> = out
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if !pairs.is_empty() {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            let kl = k.to_lowercase();
            if SENSITIVE_QUERY_KEYS.iter().any(|s| kl.contains(s)) {
                ser.append_pair(&k, "[REDACTED]");
            } else {
                ser.append_pair(&k, &v);
            }
        }
        out.set_query(Some(&ser.finish()));
    }
    out.to_string()
}

pub fn sanitize_url_str(input: &str) -> String {
    match Url::parse(input) {
        Ok(u) => sanitize_url(&u),
        Err(_) => "[INVALID_URL]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_userinfo() {
        let t = Target::parse("http://user:password@proxy.example:8080/x").unwrap();
        assert!(!t.url.contains("password"));
        assert!(!t.url.contains("user@"));
        assert!(t.url.contains("proxy.example"));
    }

    #[test]
    fn redacts_sensitive_query() {
        let t = Target::parse("https://example.com/?token=abc&page=2").unwrap();
        assert!(t.url.contains("token=%5BREDACTED%5D") || t.url.contains("token=[REDACTED]"));
        assert!(t.url.contains("page=2"));
    }

    #[test]
    fn rejects_non_http() {
        assert!(Target::parse("ftp://example.com/").is_err());
    }
}
