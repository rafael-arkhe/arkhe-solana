# Arkhe Phase A — invariant test architecture

This bundle implements the test architecture agreed for Phase A:

- `mockall` is a **dev-dependency only**;
- generated Mockall types exist only under `#[cfg(test)]` unit-test compilation;
- external integration tests define **manual local fakes** and never require exported mocks;
- PostgreSQL persistence invariants are verified against an ephemeral real PostgreSQL server via `postgresql_embedded`;
- successful provenance results are withheld if append-only metering cannot commit;
- Phase A records zero billable amount and no Solana write.

## Files

- `crates/arkhe-provenance-mcp/src/metering.rs` — `UsageLedgerPort` + PostgreSQL adapter.
- `crates/arkhe-provenance-mcp/src/preflight.rs` — `PreflightPort` + HTTP adapter + structured evidence validation.
- `crates/arkhe-provenance-mcp/src/tools/provenance.rs` — `ProvenanceService`, DI, inline Mockall unit tests.
- `crates/arkhe-provenance-mcp/tests/integration_invariants.rs` — local manual fakes only.
- `crates/arkhe-provenance-mcp/tests/postgres_invariants.rs` — ephemeral real PostgreSQL tests.
- `database/migrations/003_phase_a_metering.sql` — append-only usage ledger.
- `.cargo/audit.toml` — no permanent RUSTSEC ignore by default.
- `docs/security/RUSTSEC-2023-0071.md` — dependency-removal policy.

## Important integration note

This is a coherent reference implementation for the invariant architecture. If the local branch already contains richer MCP/RMCP handlers, keep those handlers and route them through `ProvenanceService`; do not replace working transport code merely to adopt these tests.

## Required gates

```bash
cargo check --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo tree --locked -p arkhe-provenance-mcp -i rsa
cargo audit
```

Then run the system E2E only after the real structured preflight HTTP wrapper is available:

MCP -> POST /internal/verify -> structured v23 evidence -> UsageEvent commit -> MCP response.

## Security boundaries still not solved by these files

These files do **not** solve the public URL SSRF/TOCTOU boundary, caller-controlled tenant identity, raw duplicate-JSON-key preservation, production C2PA verification, or public-edge rate limiting. Those remain independent gates before internet exposure.
