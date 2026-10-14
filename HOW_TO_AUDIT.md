# How to audit this code

1. Verify `mockall` appears only under `[dev-dependencies]`.
2. Verify no `MockUsageLedgerPort` or `MockPreflightPort` is exported by the non-test crate API.
3. Run `cargo test --locked --workspace` and confirm both inline unit tests and `tests/` integration tests pass.
4. Run `cargo clippy --locked --workspace --all-targets -- -D warnings`.
5. Run the PostgreSQL invariant test and confirm UPDATE, DELETE, and duplicate `(tenant_id,idempotency_key)` all fail.
6. Mutate `UsageLedgerPort::append` to return an error and confirm a successful preflight result is not returned to the caller.
7. Mutate idempotency lookup to return an existing record and confirm preflight is never invoked.
8. Change one byte of raw preflight response bytes and confirm `evidence_hash` changes.
9. Verify Phase A records `billable_amount_usd = 0`, `onchain_write = false`, and `solana_tx_count = 0`.
10. Run `cargo tree --locked -p arkhe-provenance-mcp -i rsa` and remove any unnecessary dependency path rather than adding a permanent audit ignore.
11. Run `cargo audit` and require new advisories to fail closed by default.
12. Treat this as application/persistence validation only; Phase A is not E2E verified until the structured preflight HTTP service and MCP transport are exercised together.
