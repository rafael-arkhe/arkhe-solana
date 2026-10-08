# ADR 0003: Database - PostgreSQL and SQLx

## Status
Accepted

## Context
Arkhe needs a robust, transactional datastore for managing relational entities such as `works`, `royalty_events`, `wormgraph_leaves`, and audit logs. We need strong typing and compile-time verification to prevent runtime SQL errors.

## Decision
We will use **PostgreSQL** as our primary database and **SQLx** as our database connectivity layer in Rust.

*   **PostgreSQL:** Provides strong ACID guarantees and handles unstructured data via JSONB, removing the need for a separate NoSQL database.
*   **SQLx:** We will use SQLx for compile-time verified SQL queries. This aligns with our focus on safety and audibility.
*   **Connection Pooling:** We will configure the database connection pool size appropriately (e.g., `max_connections` ≈ 2-4× CPU cores) for optimal performance.
*   **Optimization:** Critical fields like `record_hash` and `work_id` must be indexed from the start.

## Consequences
*   Compile-time checking of SQL queries reduces production bugs.
*   We rely on a single, proven database technology, keeping operations simple for the MVP.
*   Read replicas, partitioning (e.g., TimescaleDB), and caching (Redis) are deferred until specific scale or latency requirements demand them.
