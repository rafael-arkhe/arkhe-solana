use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimStatus {
    #[default]
    Verified,
    Partial,
    Conjecture,
    Falsified,
    Compromised,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    #[serde(default)]
    pub status: ClaimStatus,
    #[serde(default = "default_verification_source")]
    pub verification_source: String,
    #[serde(default)]
    pub falsifier: Option<String>,
    #[serde(default)]
    pub source_files: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub last_run: Option<String>,
}

fn default_verification_source() -> String {
    "none".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualHash {
    pub sha256: String,
    pub blake3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Freshness {
    pub checked_at: String,
    pub match_: bool,
    pub reason: String,
    pub sha_match: bool,
    pub blake3_match: bool,
    pub report_hash: Option<String>,
    pub current_hash: String,
    pub report_blake3: Option<String>,
    pub current_blake3: Option<String>,
    pub diff: Diff,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diff {
    pub changed: Vec<String>,
    pub missing: Vec<String>,
    pub added: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDecision {
    pub allowed: bool,
    pub reason: String,
    pub severity: Severity,
    pub affected: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Propagated {
    pub id: String,
    pub upstream: String,
    pub depth: u32,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationGraph {
    pub generated_at: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub cycles: Vec<Vec<String>>,
    pub propagated_compromised: Vec<Propagated>,
    pub max_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub status: ClaimStatus,
    pub verification_source: String,
    pub falsifier: Option<String>,
    pub source_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
}
