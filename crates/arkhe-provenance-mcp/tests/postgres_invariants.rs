use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use rust_decimal::Decimal;
use sqlx::{PgPool, Row};
use uuid::Uuid;

async fn temporary_postgres() -> anyhow::Result<(PostgreSQL, PgPool)> {
    let settings = SettingsBuilder::new()
        .host("127.0.0.1")
        .port(0)
        .username("postgres")
        .password("arkhe-test")
        .temporary(true)
        .build();

    let mut postgres = PostgreSQL::new(settings);
    postgres.setup().await?;
    postgres.start().await?;
    postgres.create_database("arkhe_test").await?;

    let database_url = postgres.settings().url("arkhe_test");
    let pool = PgPool::connect(&database_url).await?;

    sqlx::raw_sql(include_str!(
        "../../../database/migrations/003_phase_a_metering.sql"
    ))
    .execute(&pool)
    .await?;

    Ok((postgres, pool))
}

async fn insert_usage(pool: &PgPool, idempotency_key: &str) -> anyhow::Result<Uuid> {
    let request_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO usage_events (
            request_id, idempotency_key, request_digest, tenant_id,
            tool, tool_version, price_book_version, pricing_rule_id,
            started_at, duration_ms, bytes_in, bytes_out,
            execution_status, domain_outcome, verification_level,
            estimated_cost_usd, billable_units, billable_amount_usd,
            evidence_hash, metadata
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,
            NOW(),10,100,200,$9,$10,$11,
            NULL,1,$12,$13,$14
        )
        "#,
    )
    .bind(request_id)
    .bind(idempotency_key)
    .bind("a".repeat(64))
    .bind("tenant-a")
    .bind("verify_provenance")
    .bind("0.2.1")
    .bind("phase-a-free-v1")
    .bind("phase-a-free-verify")
    .bind("completed")
    .bind("PASS")
    .bind("release")
    .bind(Decimal::ZERO)
    .bind("b".repeat(64))
    .bind(serde_json::json!({"phase":"A"}))
    .execute(pool)
    .await?;
    Ok(request_id)
}

#[tokio::test]
async fn usage_events_are_append_only_and_idempotent() -> anyhow::Result<()> {
    let (postgres, pool) = temporary_postgres().await?;

    let request_id = insert_usage(&pool, "idem-001").await?;

    let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM usage_events WHERE request_id = $1")
        .bind(request_id)
        .fetch_one(&pool)
        .await?
        .get("count");
    assert_eq!(count, 1);

    let update = sqlx::query("UPDATE usage_events SET duration_ms = 999 WHERE request_id = $1")
        .bind(request_id)
        .execute(&pool)
        .await;
    assert!(update.is_err(), "UPDATE unexpectedly succeeded");

    let delete = sqlx::query("DELETE FROM usage_events WHERE request_id = $1")
        .bind(request_id)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "DELETE unexpectedly succeeded");

    let duplicate = insert_usage(&pool, "idem-001").await;
    assert!(duplicate.is_err(), "duplicate idempotency unexpectedly succeeded");

    pool.close().await;
    postgres.stop().await?;
    Ok(())
}
