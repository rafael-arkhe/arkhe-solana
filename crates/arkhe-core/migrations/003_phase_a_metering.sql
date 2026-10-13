-- Phase A: append-only usage ledger + read-only royalty status projection.
-- No billing or payment mutation is introduced in this migration.

CREATE TABLE IF NOT EXISTS usage_events (
    request_id UUID PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    price_book_version TEXT NOT NULL,
    pricing_rule_id TEXT NOT NULL,
    sol_price_usd_at_event NUMERIC(20, 8),
    started_at TIMESTAMPTZ NOT NULL,
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    bytes_in BIGINT NOT NULL CHECK (bytes_in >= 0),
    bytes_out BIGINT NOT NULL CHECK (bytes_out >= 0),
    result TEXT NOT NULL,
    verification_level TEXT,
    estimated_cost_usd NUMERIC(20, 10) CHECK (estimated_cost_usd IS NULL OR estimated_cost_usd >= 0),
    billable_units BIGINT NOT NULL CHECK (billable_units >= 0),
    billable_amount_usd NUMERIC(20, 10) NOT NULL CHECK (billable_amount_usd >= 0),
    evidence_hash TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT usage_events_idempotency UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT usage_events_evidence_hash_format CHECK (
        evidence_hash IS NULL OR evidence_hash ~ '^[0-9a-f]{64}$'
    )
);

CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_started
    ON usage_events (tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_tool_started
    ON usage_events (tool, started_at DESC);

CREATE OR REPLACE FUNCTION arkhe_reject_usage_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'usage_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS usage_events_no_update ON usage_events;
CREATE TRIGGER usage_events_no_update
BEFORE UPDATE ON usage_events
FOR EACH ROW EXECUTE FUNCTION arkhe_reject_usage_event_mutation();

DROP TRIGGER IF EXISTS usage_events_no_delete ON usage_events;
CREATE TRIGGER usage_events_no_delete
BEFORE DELETE ON usage_events
FOR EACH ROW EXECUTE FUNCTION arkhe_reject_usage_event_mutation();

-- Projection populated by the existing/future indexer. The MCP tool is read-only.
CREATE TABLE IF NOT EXISTS royalty_status (
    work_uuid UUID PRIMARY KEY REFERENCES works(uuid) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (state IN ('unknown', 'registered', 'claimable', 'settled', 'disputed', 'frozen')),
    split JSONB,
    currency TEXT,
    source TEXT NOT NULL DEFAULT 'indexer',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
