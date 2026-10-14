BEGIN;

CREATE TABLE IF NOT EXISTS usage_events (
    request_id UUID PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    request_digest CHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    price_book_version TEXT NOT NULL,
    pricing_rule_id TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    bytes_in BIGINT NOT NULL CHECK (bytes_in >= 0),
    bytes_out BIGINT NOT NULL CHECK (bytes_out >= 0),
    execution_status TEXT NOT NULL,
    domain_outcome TEXT NOT NULL,
    verification_level TEXT,
    estimated_cost_usd NUMERIC(20,10),
    billable_units BIGINT NOT NULL CHECK (billable_units >= 0),
    billable_amount_usd NUMERIC(20,10) NOT NULL CHECK (billable_amount_usd >= 0),
    evidence_hash CHAR(64) CHECK (evidence_hash IS NULL OR evidence_hash ~ '^[0-9a-f]{64}$'),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT usage_events_tenant_idempotency_unique UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS usage_events_tenant_started_at_idx
    ON usage_events (tenant_id, started_at DESC);

CREATE OR REPLACE FUNCTION reject_usage_event_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'usage_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS usage_events_reject_update ON usage_events;
CREATE TRIGGER usage_events_reject_update
BEFORE UPDATE ON usage_events
FOR EACH ROW EXECUTE FUNCTION reject_usage_event_mutation();

DROP TRIGGER IF EXISTS usage_events_reject_delete ON usage_events;
CREATE TRIGGER usage_events_reject_delete
BEFORE DELETE ON usage_events
FOR EACH ROW EXECUTE FUNCTION reject_usage_event_mutation();

COMMIT;
