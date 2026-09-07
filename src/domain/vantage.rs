use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub auth_present: bool,
    /// Full proxy URL including credentials. Never serialized to output.
    #[serde(skip)]
    pub url_with_auth: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProbeConfig {
    pub endpoint: String,
    pub region: Option<String>,
}

#[derive(Debug, Clone)]
pub enum VantagePoint {
    Direct,
    HttpProxy(ProxyConfig),
    HttpsProxy(ProxyConfig),
    Socks5(ProxyConfig),
    RemoteProbe(RemoteProbeConfig),
}

impl VantagePoint {
    /// Short stable id used in evidence ids: "direct" or "proxy".
    pub fn short_id(&self) -> &'static str {
        match self {
            VantagePoint::Direct => "direct",
            _ => "proxy",
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            VantagePoint::Direct => "direct",
            VantagePoint::HttpProxy(_) => "http_proxy",
            VantagePoint::HttpsProxy(_) => "https_proxy",
            VantagePoint::Socks5(_) => "socks5",
            VantagePoint::RemoteProbe(_) => "remote_probe",
        }
    }

    /// Redacted human label. Never includes credentials.
    pub fn redacted_label(&self) -> String {
        match self {
            VantagePoint::Direct => "direct".to_string(),
            VantagePoint::HttpProxy(c) => format!("http://{}:{}", c.host, c.port),
            VantagePoint::HttpsProxy(c) => format!("https://{}:{}", c.host, c.port),
            VantagePoint::Socks5(c) => format!("socks5://{}:{}", c.host, c.port),
            VantagePoint::RemoteProbe(c) => format!("remote:{}", c.endpoint),
        }
    }
}

pub fn parse_proxy(input: &str) -> Result<VantagePoint, String> {
    let url = Url::parse(input).map_err(|_| "cannot parse proxy URL".to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "proxy URL has no host".to_string())?
        .to_string();
    let port = url.port_or_known_default().ok_or_else(|| {
        "proxy URL has no port and scheme has no known default".to_string()
    })?;
    let auth_present = !url.username().is_empty() || url.password().is_some();
    let cfg = ProxyConfig {
        scheme: ProxyScheme::Http,
        host,
        port,
        auth_present,
        url_with_auth: input.to_string(),
    };
    match url.scheme() {
        "http" => Ok(VantagePoint::HttpProxy(ProxyConfig {
            scheme: ProxyScheme::Http,
            ..cfg
        })),
        "https" => Ok(VantagePoint::HttpsProxy(ProxyConfig {
            scheme: ProxyScheme::Https,
            ..cfg
        })),
        "socks5" | "socks5h" => Ok(VantagePoint::Socks5(ProxyConfig {
            scheme: ProxyScheme::Socks5,
            ..cfg
        })),
        other => Err(format!("unsupported proxy scheme: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_credentials() {
        let v = parse_proxy("http://user:password@proxy.example:8080").unwrap();
        let label = v.redacted_label();
        assert!(!label.contains("password"));
        assert!(!label.contains("user"));
        assert!(label.contains("proxy.example"));
        match v {
            VantagePoint::HttpProxy(c) => assert!(c.auth_present),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_proxy("ftp://proxy.example:21").is_err());
    }
}
