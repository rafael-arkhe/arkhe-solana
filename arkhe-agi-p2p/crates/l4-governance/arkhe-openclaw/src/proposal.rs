//! Self-improvement proposals for autonomous agent swarms.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelfImprovementProposal {
    pub proposal_id: Digest32,
    pub proposer_id: String,
    pub title: String,
    pub target_component: String,
    pub diff_digest: Digest32,
    pub benchmark_target: String,
    pub created_at: u64,
}

impl SelfImprovementProposal {
    pub fn new(
        proposer_id: String,
        title: String,
        target_component: String,
        diff_digest: Digest32,
        benchmark_target: String,
        created_at: u64,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"OPENCLAW:PROPOSAL:v1\0");
        hasher.update(proposer_id.as_bytes());
        hasher.update(title.as_bytes());
        hasher.update(target_component.as_bytes());
        hasher.update(diff_digest.as_bytes());
        let id = Digest32(*hasher.finalize().as_bytes());
        Self {
            proposal_id: id,
            proposer_id,
            title,
            target_component,
            diff_digest,
            benchmark_target,
            created_at,
        }
    }
}
