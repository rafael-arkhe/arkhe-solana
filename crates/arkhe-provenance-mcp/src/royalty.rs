use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoyaltyStatusArgs {
    /// Metering identity. Phase A accepts a caller-supplied tenant; OAuth replaces this later.
    pub tenant_id: String,
    /// Caller-generated idempotency key. Reuse is rejected.
    pub idempotency_key: String,
    /// Work UUID or 64-hex BLAKE3 hash.
    pub work_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoyaltyStatus {
    pub found: bool,
    pub work_uuid: Option<Uuid>,
    pub blake3_hash: Option<String>,
    pub state: Option<String>,
    pub split: Option<Value>,
    pub currency: Option<String>,
    pub source: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Clone)]
pub struct RoyaltyStore {
    pool: PgPool,
}

impl RoyaltyStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, work_id: &str) -> Result<RoyaltyStatus, sqlx::Error> {
        let row = if let Ok(id) = Uuid::parse_str(work_id) {
            sqlx::query(
                r#"
                SELECT w.uuid, w.blake3_hash, r.state, r.split, r.currency, r.source,
                       r.updated_at::text AS updated_at
                FROM works w
                LEFT JOIN royalty_status r ON r.work_uuid = w.uuid
                WHERE w.uuid = $1
                LIMIT 1
                "#,
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT w.uuid, w.blake3_hash, r.state, r.split, r.currency, r.source,
                       r.updated_at::text AS updated_at
                FROM works w
                LEFT JOIN royalty_status r ON r.work_uuid = w.uuid
                WHERE w.blake3_hash = $1
                LIMIT 1
                "#,
            )
            .bind(work_id)
            .fetch_optional(&self.pool)
            .await?
        };

        let Some(row) = row else {
            return Ok(RoyaltyStatus {
                found: false,
                work_uuid: None,
                blake3_hash: None,
                state: None,
                split: None,
                currency: None,
                source: None,
                updated_at: None,
            });
        };

        Ok(RoyaltyStatus {
            found: true,
            work_uuid: Some(row.get("uuid")),
            blake3_hash: row.try_get::<String, _>("blake3_hash").ok(),
            state: row.try_get::<Option<String>, _>("state").unwrap_or(None),
            split: row.try_get::<Option<Value>, _>("split").unwrap_or(None),
            currency: row.try_get::<Option<String>, _>("currency").unwrap_or(None),
            source: row.try_get::<Option<String>, _>("source").unwrap_or(None),
            updated_at: row.try_get::<Option<String>, _>("updated_at").unwrap_or(None),
        })
    }
}
