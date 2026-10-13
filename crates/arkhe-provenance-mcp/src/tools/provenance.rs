use crate::{metering::UsageEvent, preflight::VerifyProvenanceArgs, server::ArkheMcp};
use chrono::Utc;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    ErrorData as McpError,
};
use serde_json::json;
use std::time::Instant;
use uuid::Uuid;
use crate::metering::UsageLedgerPort;
use crate::preflight::PreflightPort;

use std::sync::Arc;
use crate::server::ArkheMcpConfig;

#[derive(Clone)]
pub struct ProvenanceService {
    pub ledger: Arc<dyn UsageLedgerPort>,
    pub preflight: Arc<dyn PreflightPort>,
    pub config: ArkheMcpConfig,
}

impl ProvenanceService {
    pub fn new(
        ledger: Arc<dyn UsageLedgerPort>,
        preflight: Arc<dyn PreflightPort>,
        config: ArkheMcpConfig,
    ) -> Self {
        Self {
            ledger,
            preflight,
            config,
        }
    }

    pub async fn verify(
        &self,
        args: VerifyProvenanceArgs,
    ) -> Result<CallToolResult, McpError> {
        if args.tenant_id.trim().is_empty() || args.idempotency_key.trim().is_empty() {
            return Err(McpError::invalid_params(
                "tenant_id and idempotency_key are required",
                None,
            ));
        }

        match self
            .ledger
            .seen_idempotency_key(&args.tenant_id, &args.idempotency_key)
            .await
        {
            Ok(Some(existing)) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                    "idempotency key already used; original request_id={existing}"
                ))]));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = ?e, "usage ledger lookup failed");
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    "metering unavailable; request rejected fail-closed",
                )]));
            }
        }

        let started_at = Utc::now();
        let timer = Instant::now();
        let input_bytes = serde_json::to_vec(&args).map(|v| v.len()).unwrap_or(0) as i64;
        let request_id = Uuid::new_v4();

        let outcome = self.preflight.verify(&args).await;
        let (tool_result, result_label, verification_level, evidence_hash, bytes_out, metadata) =
            match outcome {
                Ok(verified) => {
                    let evidence = verified.evidence;
                    let verification_level = if evidence.result == "PASS" {
                        Some(if evidence.mode == "release" {
                            "release_verified".to_owned()
                        } else {
                            "sanity_valid".to_owned()
                        })
                    } else {
                        Some("verification_failed".to_owned())
                    };
                    let text = serde_json::to_string_pretty(&evidence)
                        .unwrap_or_else(|_| "{\"result\":\"FAIL\"}".to_owned());
                    (
                        CallToolResult::success(vec![ContentBlock::text(text)]),
                        evidence.result.clone(),
                        verification_level,
                        Some(verified.wire_sha256),
                        verified.wire_len as i64,
                        json!({
                            "mode": evidence.mode,
                            "verifier_version": evidence.verifier_version,
                            "verifier_sha256": evidence.verifier_sha256,
                            "hard_failures": evidence.hard_failures,
                            "onchain_write": false,
                            "solana_tx_count": 0
                        }),
                    )
                }
                Err(e) => {
                    let message = format!("provenance verification failed to execute: {e}");
                    (
                        CallToolResult::error(vec![ContentBlock::text(message.clone())]),
                        "ERROR".to_owned(),
                        None,
                        None,
                        message.len() as i64,
                        json!({"error": e.to_string()}),
                    )
                }
            };

        let event = UsageEvent {
            request_id,
            idempotency_key: args.idempotency_key,
            tenant_id: args.tenant_id,
            tool: "verify_provenance".to_owned(),
            price_book_version: self.ledger.price_book_version().to_owned(),
            pricing_rule_id: "phase-a-free-verify-provenance-v1".to_owned(),
            sol_price_usd_at_event: self.config.sol_price_usd.clone(),
            started_at,
            duration_ms: timer.elapsed().as_millis().min(i64::MAX as u128) as i64,
            bytes_in: input_bytes,
            bytes_out,
            result: result_label,
            verification_level,
            estimated_cost_usd: self.config.verify_cost_usd.clone(),
            billable_units: 1,
            billable_amount_usd: "0".to_owned(),
            evidence_hash,
            metadata,
        };

        if let Err(e) = self.ledger.append(&event).await {
            tracing::error!(error = ?e, request_id = %request_id, "usage ledger append failed");
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "verification completed but metering commit failed; response withheld fail-closed",
            )]));
        }

        Ok(tool_result)
    }
}

impl ArkheMcp {
    pub(crate) async fn verify_provenance_impl(
        &self,
        Parameters(args): Parameters<VerifyProvenanceArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.provenance_service.verify(args).await
    }
}

#[cfg(test)]
mod logic_tests {
    use super::*;
    use std::sync::Arc;
    use crate::metering::{MockUsageLedgerPort, MeteringError};
    use crate::preflight::{MockPreflightPort, VerifiedPreflightResponse, PreflightEvidence, VerifyProvenanceArgs, ReleaseGate};
    use crate::server::ArkheMcpConfig;

    fn test_config() -> ArkheMcpConfig {
        ArkheMcpConfig {
            sol_price_usd: Some("150".into()),
            verify_cost_usd: Some("0".into()),
            royalty_lookup_cost_usd: Some("0".into()),
        }
    }

    fn valid_request() -> VerifyProvenanceArgs {
        serde_json::from_value(serde_json::json!({
            "tenant_id": "test_tenant",
            "idempotency_key": "test_idem",
            "report": { "content_hash": "c_hash", "script_sha256": "v_hash" },
            "audio_a": { "url": "http://a", "expected_sha256": "a_hash" },
            "audio_b": { "url": "http://b", "expected_sha256": "b_hash" },
            "mode": "sanity"
        })).unwrap()
    }

    fn valid_release_verified_report() -> VerifiedPreflightResponse {
        VerifiedPreflightResponse {
            evidence: PreflightEvidence {
                result: "PASS".to_owned(),
                mode: "sanity".to_owned(),
                verifier_version: "23".to_owned(),
                verifier_sha256: "v_hash".to_owned(),
                content_hash: Some("c_hash".to_owned()),
                envelope_hash: None,
                release_gate: ReleaseGate { applied: false, passed: None, issues: vec![] },
                hard_failures: 0,
                checks: vec![],
            },
            wire_sha256: "w_hash".to_owned(),
            wire_len: 1234,
        }
    }

    #[tokio::test]
    async fn successful_verification_is_withheld_when_metering_fails() {
        let mut preflight = MockPreflightPort::new();

        preflight
            .expect_verify()
            .times(1)
            .returning(|_| {
                Ok(valid_release_verified_report())
            });

        let mut ledger = MockUsageLedgerPort::new();

        ledger
            .expect_seen_idempotency_key()
            .returning(|_, _| Ok(None));

        ledger.expect_price_book_version().return_const("v1".to_owned());

        ledger
            .expect_append()
            .times(1)
            .returning(|_| {
                Err(MeteringError::Unavailable)
            });

        let service = ProvenanceService::new(
            Arc::new(ledger),
            Arc::new(preflight),
            test_config()
        );

        let result = service.verify(valid_request()).await;

        let result = result.unwrap();
        assert!(result.is_error.unwrap_or(false));

        let error_text = serde_json::to_string(&result.content).unwrap();
        assert!(error_text.contains("verification completed but metering commit failed; response withheld fail-closed"));
    }

    #[tokio::test]
    async fn duplicate_execution_rejected() {
        let mut preflight = MockPreflightPort::new();

        preflight.expect_verify().times(0);

        let mut ledger = MockUsageLedgerPort::new();

        ledger
            .expect_seen_idempotency_key()
            .times(1)
            .returning(|_, _| Ok(Some(uuid::Uuid::new_v4())));

        let service = ProvenanceService::new(
            Arc::new(ledger),
            Arc::new(preflight),
            test_config()
        );

        let result = service.verify(valid_request()).await;
        let result = result.unwrap();
        assert!(result.is_error.unwrap_or(false));

        let error_text = serde_json::to_string(&result.content).unwrap();
        assert!(error_text.contains("idempotency key already used"));
    }
}
