use std::time::Duration;

use crate::domain::target::Target;
use crate::domain::vantage::VantagePoint;
use crate::identity::SharedProvider;

#[derive(Debug, Clone)]
pub struct ConfirmationPolicy {
    pub min_confidence: f32,
    pub require_reproducibility: bool,
}

impl Default for ConfirmationPolicy {
    fn default() -> Self {
        Self {
            min_confidence: 0.50,
            require_reproducibility: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeLimits {
    pub max_probes: usize,
    pub timeout_total: Duration,
    pub timeout_connect: Duration,
    pub retries: u32,
    pub max_redirects: usize,
    pub max_body_bytes: u64,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            max_probes: 10,
            timeout_total: Duration::from_secs(15),
            timeout_connect: Duration::from_secs(5),
            retries: 1,
            max_redirects: 10,
            max_body_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
pub struct ProbePlan {
    pub target: Target,
    pub vantages: Vec<VantagePoint>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub user_agent: String,
    pub confirmation: ConfirmationPolicy,
    pub limits: ProbeLimits,
    pub identity_lookup: bool,
    pub identity: SharedProvider,
}

impl std::fmt::Debug for ProbePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbePlan")
            .field("target", &self.target)
            .field("vantages", &self.vantages.len())
            .field("method", &self.method)
            .field("confirmation", &self.confirmation)
            .field("limits", &self.limits)
            .field("identity_lookup", &self.identity_lookup)
            .finish()
    }
}
