use thiserror::Error;

use crate::transport::TransportError;

#[derive(Debug, Error)]
pub enum SeekrError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("no vantage selected")]
    NoVantage,
    #[error("proxy error: {0}")]
    InvalidProxy(String),
    #[error("transport error on {vantage}: {kind}")]
    Transport { vantage: String, kind: TransportError },
    #[error("probe budget exceeded")]
    BudgetExceeded,
    #[error("remote probe is not available in this build")]
    RemoteNotAvailable,
    #[error("internal error")]
    Internal,
}

impl SeekrError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SeekrError::InvalidTarget(_) | SeekrError::NoVantage | SeekrError::InvalidProxy(_) => 2,
            SeekrError::Transport { kind, .. } => match kind {
                TransportError::ProxyAuthFailure
                | TransportError::ProxyRefused
                | TransportError::ProxyTimeout => 4,
                TransportError::Timeout | TransportError::TcpTimeout => 5,
                _ => 3,
            },
            SeekrError::BudgetExceeded => 7,
            SeekrError::RemoteNotAvailable | SeekrError::Internal => 6,
        }
    }
}
