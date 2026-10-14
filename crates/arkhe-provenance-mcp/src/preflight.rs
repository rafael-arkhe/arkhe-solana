use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreflightRequest {
    pub report: serde_json::Value,
    pub mode: String,
    pub online: bool,
    pub c2pa_a: Option<String>,
    pub c2pa_b: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreflightEvidence {
    pub result: String,
    pub mode: String,
    pub verifier_version: String,
    pub verifier_sha256: String,
    pub content_hash: String,
    pub envelope_hash: Option<String>,
    pub hard_failures: u32,
    pub checks: Vec<PreflightCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreflightCheck {
    pub id: String,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPreflight {
    pub evidence: PreflightEvidence,
    pub raw_response: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PreflightError {
    #[error("preflight transport failure: {0}")]
    Transport(String),
    #[error("preflight returned malformed evidence: {0}")]
    Malformed(String),
    #[error("preflight evidence failed validation: {0}")]
    InvalidEvidence(String),
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PreflightPort: Send + Sync {
    async fn verify(&self, request: PreflightRequest) -> Result<VerifiedPreflight, PreflightError>;
}

#[derive(Clone)]
pub struct HttpPreflightClient {
    client: Client,
    base_url: String,
}

impl HttpPreflightClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, PreflightError> {
        let client = Client::builder()
            .build()
            .map_err(|e| PreflightError::Transport(e.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        })
    }
}

#[async_trait]
impl PreflightPort for HttpPreflightClient {
    async fn verify(&self, request: PreflightRequest) -> Result<VerifiedPreflight, PreflightError> {
        let response = self
            .client
            .post(format!("{}/internal/verify", self.base_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| PreflightError::Transport(e.to_string()))?;

        if !response.status().is_success() {
            return Err(PreflightError::Transport(format!(
                "HTTP status {}",
                response.status()
            )));
        }

        let raw_response = response
            .bytes()
            .await
            .map_err(|e| PreflightError::Transport(e.to_string()))?
            .to_vec();

        let evidence: PreflightEvidence = serde_json::from_slice(&raw_response)
            .map_err(|e| PreflightError::Malformed(e.to_string()))?;

        validate_evidence(&request, &evidence)?;

        Ok(VerifiedPreflight {
            evidence,
            raw_response,
        })
    }
}

pub fn validate_evidence(
    request: &PreflightRequest,
    evidence: &PreflightEvidence,
) -> Result<(), PreflightError> {
    if evidence.mode != request.mode {
        return Err(PreflightError::InvalidEvidence("mode mismatch".into()));
    }

    if evidence.result != "PASS" && evidence.result != "FAIL" {
        return Err(PreflightError::InvalidEvidence("unknown result".into()));
    }

    if evidence.checks.is_empty() {
        return Err(PreflightError::InvalidEvidence("empty checks".into()));
    }

    let mut ids = std::collections::HashSet::new();
    for check in &evidence.checks {
        if !ids.insert(check.id.as_str()) {
            return Err(PreflightError::InvalidEvidence(format!(
                "duplicate check id: {}",
                check.id
            )));
        }
    }

    if evidence.result == "PASS" && evidence.hard_failures != 0 {
        return Err(PreflightError::InvalidEvidence(
            "PASS with non-zero hard_failures".into(),
        ));
    }

    if request.mode == "release" && evidence.result == "PASS" && evidence.envelope_hash.is_none() {
        return Err(PreflightError::InvalidEvidence(
            "release PASS without envelope_hash".into(),
        ));
    }

    Ok(())
}
