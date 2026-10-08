# ADR 0002: Backend Framework - Axum and Clean Architecture

## Status
Accepted

## Context
Arkhe requires a reliable, performant, and type-safe HTTP API gateway for its Rust backend. The framework must support modular architecture, robust middleware, and easily integrate with standard API specification tools.

## Decision
We will use **Axum 0.8** as our primary API gateway framework.

*   **Framework:** Axum is mature, highly performant, and deeply integrated with the `tokio` ecosystem.
*   **Architecture:** We adopt **Clean Architecture** patterns, logically separating our code into `domain`, `app` (service layer), and `infra` (infrastructure) modules to ensure high testability and dependency isolation.
*   **Middleware:** We will leverage the `tower` ecosystem for middlewares such as `TraceLayer`, `CompressionLayer`, and `TimeoutLayer`.
*   **API Standard:** We will expose a REST API. We will use `utoipa` to automatically generate **OpenAPI 3.1** documentation from our Axum routes.
*   **Versioning:** All API endpoints will be versioned from the start (e.g., `/v1/`) to avoid future breaking changes.

## Consequences
*   Strong type safety and performance from the Rust ecosystem.
*   Easy generation of standardized API documentation (OpenAPI 3.1).
*   Enforced separation of concerns through Clean Architecture, enabling pure logic (domain) to be tested without I/O dependencies.
