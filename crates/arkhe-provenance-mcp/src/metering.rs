use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageEvent {
    pub request_id: Uuid,
    pub idempotency_key: String,
    pub request_digest: String,
    pub tenant_id: String,
    pub tool: String,
    pub tool_version: String,
    pub price_book_version: String,
    pub pricing_rule_id: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub execution_status: String,
    pub domain_outcome: String,
    pub verification_level: Option<String>,
    pub estimated_cost_usd: Option<Decimal>,
    pub billable_units: i64,
    pub billable_amount_usd: Decimal,
    pub evidence_hash: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingUsage {
    pub request_id: Uuid,
    pub request_digest: String,
}

#[derive(Debug, Error)]
pub enum MeteringError {
    #[error("usage ledger unavailable: {0}")]
    Unavailable(String),
    #[error("idempotency conflict")]
    IdempotencyConflict,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait UsageLedgerPort: Send + Sync {
    async fn find_idempotency(
        &self,
        tenant_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ExistingUsage>, MeteringError>;

    async fn append(&self, event: UsageEvent) -> Result<(), MeteringError>;
}

#[derive(Clone)]
pub struct UsageLedger {
    pool: PgPool,
}

impl UsageLedger {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UsageLedgerPort for UsageLedger {
    async fn find_idempotency(
        &self,
        tenant_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<ExistingUsage>, MeteringError> {
        let row = sqlx::query(
            r#"
            SELECT request_id, request_digest
            FROM usage_events
            WHERE tenant_id = $1 AND idempotency_key = $2
            "#,
        )
        .bind(tenant_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| MeteringError::Unavailable(e.to_string()))?;

        Ok(row.map(|row| ExistingUsage {
            request_id: row.get("request_id"),
            request_digest: row.get("request_digest"),
        }))
    }

    async fn append(&self, event: UsageEvent) -> Result<(), MeteringError> {
        sqlx::query(
            r#"
            INSERT INTO usage_events (
                request_id,
                idempotency_key,
                request_digest,
                tenant_id,
                tool,
                tool_version,
                price_book_version,
                pricing_rule_id,
                started_at,
                duration_ms,
                bytes_in,
                bytes_out,
                execution_status,
                domain_outcome,
                verification_level,
                estimated_cost_usd,
                billable_units,
                billable_amount_usd,
                evidence_hash,
                metadata
            )
            VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                $11,$12,$13,$14,$15,$16,$17,$18,$19,$20
            )
            "#,
        )
        .bind(event.request_id)
        .bind(event.idempotency_key)
        .bind(event.request_digest)
        .bind(event.tenant_id)
        .bind(event.tool)
        .bind(event.tool_version)
        .bind(event.price_book_version)
        .bind(event.pricing_rule_id)
        .bind(event.started_at)
        .bind(event.duration_ms)
        .bind(event.bytes_in)
        .bind(event.bytes_out)
        .bind(event.execution_status)
        .bind(event.domain_outcome)
        .bind(event.verification_level)
        .bind(event.estimated_cost_usd)
        .bind(event.billable_units)
        .bind(event.billable_amount_usd)
        .bind(event.evidence_hash)
        .bind(event.metadata)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if let Some(db) = e.as_database_error() {
                if db.is_unique_violation() {
                    return MeteringError::IdempotencyConflict;
                }
            }
            MeteringError::Unavailable(e.to_string())
        })?;

        Ok(())
    }
}
