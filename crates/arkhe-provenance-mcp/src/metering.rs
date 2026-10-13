use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct UsageEvent {
    pub request_id: Uuid,
    pub idempotency_key: String,
    pub tenant_id: String,
    pub tool: String,
    pub price_book_version: String,
    pub pricing_rule_id: String,
    pub sol_price_usd_at_event: Option<String>,
    pub started_at: DateTime<Utc>,
    pub duration_ms: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub result: String,
    pub verification_level: Option<String>,
    pub estimated_cost_usd: Option<String>,
    pub billable_units: i64,
    pub billable_amount_usd: String,
    pub evidence_hash: Option<String>,
    pub metadata: Value,
}

#[derive(Clone)]
pub struct UsageLedger {
    pool: PgPool,
    price_book_version: String,
}

impl UsageLedger {
    pub fn new(pool: PgPool, price_book_version: impl Into<String>) -> Self {
        Self {
            pool,
            price_book_version: price_book_version.into(),
        }
    }

    pub fn price_book_version(&self) -> &str {
        &self.price_book_version
    }

    pub async fn append(&self, event: &UsageEvent) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO usage_events (
                request_id, idempotency_key, tenant_id, tool,
                price_book_version, pricing_rule_id, sol_price_usd_at_event,
                started_at, duration_ms, bytes_in, bytes_out, result,
                verification_level, estimated_cost_usd, billable_units,
                billable_amount_usd, evidence_hash, metadata
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7::numeric,
                $8, $9, $10, $11, $12,
                $13, $14::numeric, $15,
                $16::numeric, $17, $18
            )
            "#,
        )
        .bind(event.request_id)
        .bind(&event.idempotency_key)
        .bind(&event.tenant_id)
        .bind(&event.tool)
        .bind(&event.price_book_version)
        .bind(&event.pricing_rule_id)
        .bind(event.sol_price_usd_at_event.as_deref())
        .bind(event.started_at)
        .bind(event.duration_ms)
        .bind(event.bytes_in)
        .bind(event.bytes_out)
        .bind(&event.result)
        .bind(event.verification_level.as_deref())
        .bind(event.estimated_cost_usd.as_deref())
        .bind(event.billable_units)
        .bind(&event.billable_amount_usd)
        .bind(event.evidence_hash.as_deref())
        .bind(&event.metadata)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn seen_idempotency_key(
        &self,
        tenant_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT request_id FROM usage_events WHERE tenant_id = $1 AND idempotency_key = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<Uuid, _>("request_id")))
    }
}
