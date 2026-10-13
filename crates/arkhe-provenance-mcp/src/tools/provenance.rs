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

impl ArkheMcp {
    pub(crate) async fn verify_provenance_impl(
        &self,
        Parameters(args): Parameters<VerifyProvenanceArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.tenant_id.trim().is_empty() || args.idempotency_key.trim().is_empty() {
            return Err(McpError::invalid_params(
                "tenant_id and idempotency_key are required",
                None,
            ));
        }

        match self
            .usage
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
            price_book_version: self.usage.price_book_version().to_owned(),
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

        if let Err(e) = self.usage.append(&event).await {
            tracing::error!(error = ?e, request_id = %request_id, "usage ledger append failed");
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "verification completed but metering commit failed; response withheld fail-closed",
            )]));
        }

        Ok(tool_result)
    }
}
