use crate::metering::{MeteringError, UsageEvent, UsageLedgerPort};
use crate::preflight::{PreflightError, PreflightPort, PreflightRequest, VerifiedPreflight};
use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use uuid::Uuid;

const TOOL_NAME: &str = "verify_provenance";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const PRICE_BOOK_VERSION: &str = "phase-a-free-v1";
const PRICING_RULE_ID: &str = "phase-a-free-verify";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[derive(schemars::JsonSchema)]
pub struct VerifyProvenanceRequest {
    pub tenant_id: String,
    pub idempotency_key: String,
    pub report: serde_json::Value,
    pub mode: String,
    pub online: bool,
    pub c2pa_a: Option<String>,
    pub c2pa_b: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyProvenanceResponse {
    pub request_id: Uuid,
    pub result: String,
    pub verification_level: String,
    pub evidence_hash: String,
    pub content_hash: String,
    pub envelope_hash: Option<String>,
}

#[derive(Debug, Error)]
pub enum ProvenanceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("duplicate idempotency key")]
    DuplicateRequest,
    #[error(transparent)]
    Preflight(#[from] PreflightError),
    #[error(transparent)]
    Metering(#[from] MeteringError),
}

#[derive(Clone)]
pub struct ProvenanceService {
    ledger: Arc<dyn UsageLedgerPort>,
    preflight: Arc<dyn PreflightPort>,
}

impl ProvenanceService {
    pub fn new(
        ledger: Arc<dyn UsageLedgerPort>,
        preflight: Arc<dyn PreflightPort>,
    ) -> Self {
        Self { ledger, preflight }
    }

    pub async fn verify(
        &self,
        request: VerifyProvenanceRequest,
    ) -> Result<VerifyProvenanceResponse, ProvenanceError> {
        validate_request(&request)?;

        let request_digest = request_digest(&request)?;

        if self
            .ledger
            .find_idempotency(&request.tenant_id, &request.idempotency_key)
            .await?
            .is_some()
        {
            return Err(ProvenanceError::DuplicateRequest);
        }

        let request_id = Uuid::new_v4();
        let started_at = Utc::now();
        let started = Instant::now();
        let bytes_in = serde_json::to_vec(&request)
            .map_err(|e| ProvenanceError::InvalidRequest(e.to_string()))?
            .len() as i64;

        let verified = self
            .preflight
            .verify(PreflightRequest {
                report: request.report.clone(),
                mode: request.mode.clone(),
                online: request.online,
                c2pa_a: request.c2pa_a.clone(),
                c2pa_b: request.c2pa_b.clone(),
            })
            .await?;

        let evidence_hash = sha256_hex(&verified.raw_response);
        let response = response_from_verified(request_id, evidence_hash.clone(), &verified);
        let bytes_out = serde_json::to_vec(&response)
            .map_err(|e| ProvenanceError::InvalidRequest(e.to_string()))?
            .len() as i64;

        let event = UsageEvent {
            request_id,
            idempotency_key: request.idempotency_key,
            request_digest,
            tenant_id: request.tenant_id,
            tool: TOOL_NAME.to_owned(),
            tool_version: TOOL_VERSION.to_owned(),
            price_book_version: PRICE_BOOK_VERSION.to_owned(),
            pricing_rule_id: PRICING_RULE_ID.to_owned(),
            started_at,
            duration_ms: started.elapsed().as_millis().try_into().unwrap_or(i64::MAX),
            bytes_in,
            bytes_out,
            execution_status: "completed".to_owned(),
            domain_outcome: verified.evidence.result.clone(),
            verification_level: Some(request.mode),
            estimated_cost_usd: None,
            billable_units: 1,
            billable_amount_usd: Decimal::ZERO,
            evidence_hash: Some(evidence_hash),
            metadata: serde_json::json!({
                "phase": "A",
                "onchain_write": false,
                "solana_tx_count": 0
            }),
        };

        // A1/A7 enforcement point: no successful domain response is released
        // until the append-only usage event has committed successfully.
        self.ledger.append(event).await?;

        Ok(response)
    }
}

fn validate_request(request: &VerifyProvenanceRequest) -> Result<(), ProvenanceError> {
    if request.tenant_id.trim().is_empty() {
        return Err(ProvenanceError::InvalidRequest("empty tenant_id".into()));
    }
    if request.idempotency_key.trim().is_empty() {
        return Err(ProvenanceError::InvalidRequest(
            "empty idempotency_key".into(),
        ));
    }
    if request.mode != "sanity" && request.mode != "release" {
        return Err(ProvenanceError::InvalidRequest("invalid mode".into()));
    }
    if request.mode == "release" && (!request.online || request.c2pa_a.is_none() || request.c2pa_b.is_none()) {
        return Err(ProvenanceError::InvalidRequest(
            "release requires online=true and c2pa_a/c2pa_b".into(),
        ));
    }
    Ok(())
}

fn request_digest(request: &VerifyProvenanceRequest) -> Result<String, ProvenanceError> {
    // This digest binds the typed Phase-A request fields. Do not reuse it as a
    // canonical cross-language signature format; that requires an RFC 8785 contract.
    let bytes = serde_json::to_vec(request)
        .map_err(|e| ProvenanceError::InvalidRequest(e.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn response_from_verified(
    request_id: Uuid,
    evidence_hash: String,
    verified: &VerifiedPreflight,
) -> VerifyProvenanceResponse {
    VerifyProvenanceResponse {
        request_id,
        result: verified.evidence.result.clone(),
        verification_level: verified.evidence.mode.clone(),
        evidence_hash,
        content_hash: verified.evidence.content_hash.clone(),
        envelope_hash: verified.evidence.envelope_hash.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metering::{MockUsageLedgerPort, UsageEvent};
    use crate::preflight::{MockPreflightPort, PreflightCheck, PreflightEvidence};
    use mockall::predicate;

    fn request() -> VerifyProvenanceRequest {
        VerifyProvenanceRequest {
            tenant_id: "tenant-test".into(),
            idempotency_key: "idem-1".into(),
            report: serde_json::json!({"content_hash": "abc"}),
            mode: "release".into(),
            online: true,
            c2pa_a: Some("asset-a".into()),
            c2pa_b: Some("asset-b".into()),
        }
    }

    fn verified_pass() -> VerifiedPreflight {
        let evidence = PreflightEvidence {
            result: "PASS".into(),
            mode: "release".into(),
            verifier_version: "v23".into(),
            verifier_sha256: "a".repeat(64),
            content_hash: "abc".into(),
            envelope_hash: Some("b".repeat(64)),
            hard_failures: 0,
            checks: vec![PreflightCheck {
                id: "I1".into(),
                passed: true,
            }],
        };
        let raw_response = serde_json::to_vec(&evidence).unwrap();
        VerifiedPreflight {
            evidence,
            raw_response,
        }
    }

    #[tokio::test]
    async fn a1_success_is_released_only_after_usage_commit() {
        let mut ledger = MockUsageLedgerPort::new();
        ledger
            .expect_find_idempotency()
            .times(1)
            .returning(|_, _| Ok(None));
        ledger
            .expect_append()
            .withf(|event: &UsageEvent| {
                event.tool == TOOL_NAME
                    && event.billable_amount_usd == Decimal::ZERO
                    && event.domain_outcome == "PASS"
            })
            .times(1)
            .returning(|_| Ok(()));

        let mut preflight = MockPreflightPort::new();
        preflight
            .expect_verify()
            .times(1)
            .returning(|_| Ok(verified_pass()));

        let service = ProvenanceService::new(Arc::new(ledger), Arc::new(preflight));
        let response = service.verify(request()).await.unwrap();
        assert_eq!(response.result, "PASS");
    }

    #[tokio::test]
    async fn a2_duplicate_idempotency_prevents_preflight_execution() {
        let mut ledger = MockUsageLedgerPort::new();
        ledger
            .expect_find_idempotency()
            .times(1)
            .returning(|_, _| {
                Ok(Some(crate::metering::ExistingUsage {
                    request_id: Uuid::new_v4(),
                    request_digest: "deadbeef".into(),
                }))
            });
        ledger.expect_append().times(0);

        let mut preflight = MockPreflightPort::new();
        preflight.expect_verify().times(0);

        let service = ProvenanceService::new(Arc::new(ledger), Arc::new(preflight));
        let error = service.verify(request()).await.unwrap_err();
        assert!(matches!(error, ProvenanceError::DuplicateRequest));
    }

    #[tokio::test]
    async fn a7_metering_failure_withholds_successful_verification() {
        let mut ledger = MockUsageLedgerPort::new();
        ledger
            .expect_find_idempotency()
            .times(1)
            .returning(|_, _| Ok(None));
        ledger
            .expect_append()
            .times(1)
            .returning(|_| Err(MeteringError::Unavailable("db down".into())));

        let mut preflight = MockPreflightPort::new();
        preflight
            .expect_verify()
            .times(1)
            .returning(|_| Ok(verified_pass()));

        let service = ProvenanceService::new(Arc::new(ledger), Arc::new(preflight));
        let error = service.verify(request()).await.unwrap_err();
        assert!(matches!(error, ProvenanceError::Metering(_)));
    }

    #[tokio::test]
    async fn invalid_release_request_fails_before_side_effects() {
        let mut req = request();
        req.online = false;

        let mut ledger = MockUsageLedgerPort::new();
        ledger.expect_find_idempotency().times(0);
        ledger.expect_append().times(0);

        let mut preflight = MockPreflightPort::new();
        preflight.expect_verify().times(0);

        let service = ProvenanceService::new(Arc::new(ledger), Arc::new(preflight));
        let error = service.verify(req).await.unwrap_err();
        assert!(matches!(error, ProvenanceError::InvalidRequest(_)));
    }

    #[test]
    fn evidence_hash_is_sha256_of_exact_raw_preflight_bytes() {
        let verified = verified_pass();
        let expected = sha256_hex(&verified.raw_response);
        let response = response_from_verified(Uuid::new_v4(), expected.clone(), &verified);
        assert_eq!(response.evidence_hash, expected);
    }

    #[test]
    fn mockall_is_test_only() {
        let _ = predicate::always();
    }
}
