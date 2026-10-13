use sqlx::PgPool;
use postgresql_embedded::PostgreSQL;

#[tokio::test]
async fn test_idempotency_constraint() {
    let mut postgresql = PostgreSQL::default();
    // increase timeout to give it enough time to setup on slow runners
    postgresql.setup().await.expect("setup failed");
    postgresql.start().await.expect("start failed");

    let uri = postgresql.settings().url("postgres");

    let pool = PgPool::connect(&uri).await.unwrap();

    let migration = std::fs::read_to_string("../../crates/arkhe-core/migrations/003_phase_a_metering.sql").unwrap();

    // Create missing 'works' table since migration 003 relies on it
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS works (
            uuid UUID PRIMARY KEY
        );
        "#
    ).execute(&pool).await.unwrap();

    // Split the migration on semicolons to execute commands individually
    let mut statements = Vec::new();
    let mut current_statement = String::new();
    let mut in_dollar_quote = false;

    for line in migration.lines() {
        if line.contains("$$") {
            in_dollar_quote = !in_dollar_quote;
        }
        current_statement.push_str(line);
        current_statement.push('\n');

        if line.trim().ends_with(';') && !in_dollar_quote {
            statements.push(current_statement.clone());
            current_statement.clear();
        }
    }

    for stmt in statements {
        let stmt = stmt.trim();
        if !stmt.is_empty() {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
    }

    // Insert first event
    sqlx::query(
        "INSERT INTO usage_events (request_id, tenant_id, idempotency_key, tool, price_book_version, pricing_rule_id, started_at, duration_ms, bytes_in, bytes_out, result, billable_units, billable_amount_usd)
         VALUES (gen_random_uuid(), 't1', 'k1', 'verify_provenance', 'v1', 'r1', NOW(), 1, 1, 1, 'success', 1, 0)"
    ).execute(&pool).await.unwrap();

    // Second insert with same (tenant_id, idempotency_key) must fail
    let result = sqlx::query(
        "INSERT INTO usage_events (request_id, tenant_id, idempotency_key, tool, price_book_version, pricing_rule_id, started_at, duration_ms, bytes_in, bytes_out, result, billable_units, billable_amount_usd)
         VALUES (gen_random_uuid(), 't1', 'k1', 'verify_provenance', 'v1', 'r1', NOW(), 1, 1, 1, 'success', 1, 0)"
    ).execute(&pool).await;

    assert!(result.is_err(), "duplicate idempotency key must be rejected");
}

#[tokio::test]
async fn test_append_only_ledger() {
    let mut postgresql = PostgreSQL::default();
    // increase timeout to give it enough time to setup on slow runners
    postgresql.setup().await.expect("setup failed");
    postgresql.start().await.expect("start failed");

    let uri = postgresql.settings().url("postgres");

    let pool = PgPool::connect(&uri).await.unwrap();

    let migration = std::fs::read_to_string("../../crates/arkhe-core/migrations/003_phase_a_metering.sql").unwrap();

    // Create missing 'works' table since migration 003 relies on it
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS works (
            uuid UUID PRIMARY KEY
        );
        "#
    ).execute(&pool).await.unwrap();

    let mut statements = Vec::new();
    let mut current_statement = String::new();
    let mut in_dollar_quote = false;

    for line in migration.lines() {
        if line.contains("$$") {
            in_dollar_quote = !in_dollar_quote;
        }
        current_statement.push_str(line);
        current_statement.push('\n');

        if line.trim().ends_with(';') && !in_dollar_quote {
            statements.push(current_statement.clone());
            current_statement.clear();
        }
    }

    for stmt in statements {
        let stmt = stmt.trim();
        if !stmt.is_empty() {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
    }

    // Insert an event to mutate
    sqlx::query(
        "INSERT INTO usage_events (request_id, tenant_id, idempotency_key, tool, price_book_version, pricing_rule_id, started_at, duration_ms, bytes_in, bytes_out, result, billable_units, billable_amount_usd)
         VALUES (gen_random_uuid(), 't1', 'k1', 'verify_provenance', 'v1', 'r1', NOW(), 1, 1, 1, 'success', 1, 0)"
    ).execute(&pool).await.unwrap();

    // UPDATE must fail
    let update = sqlx::query("UPDATE usage_events SET tool = 'x'")
        .execute(&pool).await;
    assert!(update.is_err(), "UPDATE on usage_events must be rejected");

    // DELETE must fail
    let delete = sqlx::query("DELETE FROM usage_events")
        .execute(&pool).await;
    assert!(delete.is_err(), "DELETE on usage_events must be rejected");
}
