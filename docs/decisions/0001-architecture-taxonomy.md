# ADR 0001: Architecture Taxonomy and Priorities

## Status
Accepted

## Context
Arkhe requires a clear technology taxonomy to avoid over-engineering and prioritize auditability and security from the start. The architecture must align with a hybrid blockchain model (Solana for settlement, Ethereum for liquidity) and support our core MVP requirements on devnet.

## Decision
We adopt the following updated taxonomy, which prioritizes tools and practices recommended for 2026, focusing on fail-closed security and clear testing (falsifiers).

### Core
*   **Domain & Business Logic:** Rust crates (`arkhe-core`, `arkhe-royalty-verify`). Separate pure logic in independent crates, testable without I/O.
*   **API Gateway:** Axum 0.8 as single gateway. Use `tower` for middleware (TraceLayer, CompressionLayer, TimeoutLayer).
*   **Service Layer:** Rust backend `app/` modules. Clean Architecture (domain, app, infra separation).
*   **Event-Driven Architecture:** WormGraph on-chain events + Yellowstone gRPC (with Yellowstone Vixen for modular pipelines).
*   **Background Jobs:** `tokio::spawn` for light jobs; `apalis` or `tokio-cron-scheduler` for durable jobs (indexer, reconciliation, EU AI Act reports).

### APIs
*   **REST:** Primary backend API (Axum) with `utoipa` for OpenAPI 3.1.
*   **GraphQL:** Not needed (resource-oriented domain).
*   **gRPC:** Internal communication (indexer ↔ API) - deferred until multiple services exist.
*   **WebSockets:** Real-time dashboard via `axum::extract::ws` - deferred.
*   **API Versioning:** `/v1/` adopted from the start to prevent breaking changes.

### Identity
*   **Authentication:** Wallet-based using Sign-In With Solana (SIWS). No passwords.
*   **Authorization:** Wallet + roles (RBAC: `creator`, `auditor`, `admin`).
*   **RBAC / ABAC:** Simple RBAC now. ABAC (via `oso` or `casbin-rs`) later for compliance.
*   **OAuth2 / OIDC:** SSO (Enter AI, offices) via `openidconnect-rs` - deferred.
*   **Service-to-Service Identity:** mTLS (indexer ↔ API) via `rustls` - deferred.

### Data
*   **PostgreSQL:** Schema with `works`, `royalty_events`, `wormgraph_leaves`. SQLx for compile-time verified queries. Pool sizing: ~2-4x CPU cores.
*   **NoSQL:** Not needed (PostgreSQL JSONB is sufficient).
*   **Redis:** Cache for MMR proofs, rate limiting, sessions - deferred.
*   **Read Replicas & Data Partitioning:** Deferred. (Future: TimescaleDB for `wormgraph_events`).

### Messaging
*   **Kafka:** Overkill.
*   **RabbitMQ:** Lighter alternative via `lapin` - deferred.
*   **Event Streaming:** Yellowstone gRPC.
*   **Queues:** `apalis` or `tokio::mpsc` for internal jobs.
*   **Dead Letter Queues:** For failed indexing events - deferred.

### Security
*   **Secrets Management:** Doppler, Infisical or Vault. No `.env` in production. Use `secrecy` crate.
*   **Encryption:** TLS 1.3 (`rustls`); HSM keys (`yubihsm-rs`).
*   **Rate Limiting:** `tower-governor` by IP and wallet.
*   **WAF:** Cloudflare - deferred until public traffic.
*   **Audit Logging:** `audit_log` table + export to SIEM. **Fail-closed**: blocks operation if logging fails.

### Reliability
*   **Retries & Timeouts:** `tower::retry` + explicit timeouts. Retries only for idempotent operations.
*   **Circuit Breakers:** For RPCs. **Fail-closed**: if RPC fails, return error, never `Verified`.
*   **Idempotency:** Key by `record_hash` + `tx_signature`.
*   **Health Checks:** `/health` and `/ready`.

### Observability
*   **Centralized Logging:** `tracing` + Loki/Grafana Cloud (OpenTelemetry).
*   **Metrics:** Prometheus (`metrics-rs`) + Grafana (`ro11y` for OTLP).
*   **Distributed Tracing / Alerting:** Deferred.

### Infrastructure & DevOps
*   **Infrastructure:** Docker for dev; Railway/Fly.io + Vercel for MVP. K8s/Terraform deferred.
*   **CI/CD:** GitHub Actions (`cargo test`, `clippy`, `anchor build`, `npm test`).
*   **Automated Testing:** Invariant tests + integration with `solana-test-validator`. **Falsifiers are mandatory**.
*   **Security Scanning:** `cargo-audit`, `cargo-deny`, Dependabot in CI with `--locked`.

### Performance & Scaling
*   **CDN:** Vercel Edge for frontend/WASM.
*   **Database Optimization:** Indexes on `record_hash`, `work_id`. SQLx.
*   **Async Processing:** Tokio + `apalis`.
*   **Failover Strategy:** Primary RPC + fallback (Helius → QuickNode → Triton).

## Consequences
*   We commit to a simple, highly-auditable stack avoiding over-engineering.
*   Every component added must have a clear falsifier. If there is no test proving it fails when it should, it does not go to production.
