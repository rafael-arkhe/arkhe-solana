use crate::{metering::UsageEvent, royalty::RoyaltyStatusArgs, server::ArkheMcp};
use chrono::Utc;
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    ErrorData as McpError,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Instant;
use uuid::Uuid;

impl ArkheMcp {
    pub(crate) async fn get_royalty_status_impl(
        &self,
        Parameters(args): Parameters<RoyaltyStatusArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.tenant_id.trim().is_empty()
            || args.idempotency_key.trim().is_empty()
            || args.work_id.trim().is_empty()
        {
            return Err(McpError::invalid_params(
                "tenant_id, idempotency_key, and work_id are required",
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

        let outcome = self.royalties.get(&args.work_id).await;
        let (tool_result, result_label, evidence_hash, bytes_out, metadata) = match outcome {
            Ok(status) => {
                let body = serde_json::to_vec(&status).unwrap_or_default();
                let evidence_hash = hex::encode(Sha256::digest(&body));
                let text = serde_json::to_string_pretty(&status).unwrap_or_else(|_| "{}".into());
                (
                    CallToolResult::success(vec![ContentBlock::text(text)]),
                    if status.found { "FOUND" } else { "NOT_FOUND" }.to_owned(),
                    Some(evidence_hash),
                    body.len() as i64,
                    json!({"found": status.found}),
                )
            }
            Err(e) => {
                let message = format!("royalty lookup failed: {e}");
                (
                    CallToolResult::error(vec![ContentBlock::text(message.clone())]),
                    "ERROR".to_owned(),
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
            tool: "get_royalty_status".to_owned(),
            price_book_version: self.usage.price_book_version().to_owned(),
            pricing_rule_id: "phase-a-free-royalty-status-v1".to_owned(),
            sol_price_usd_at_event: self.config.sol_price_usd.clone(),
            started_at,
            duration_ms: timer.elapsed().as_millis().min(i64::MAX as u128) as i64,
            bytes_in: input_bytes,
            bytes_out,
            result: result_label,
            verification_level: None,
            estimated_cost_usd: self.config.royalty_lookup_cost_usd.clone(),
            billable_units: 1,
            billable_amount_usd: "0".to_owned(),
            evidence_hash,
            metadata,
        };

        if let Err(e) = self.usage.append(&event).await {
            tracing::error!(error = ?e, request_id = %request_id, "usage ledger append failed");
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "lookup completed but metering commit failed; response withheld fail-closed",
            )]));
        }

        Ok(tool_result)
    }
}
