# ADR 0005: Fail-Closed Verification

## Status
Accepted

## Context
Arkhe's core value proposition is the cryptographic provenance and conditioned settlement of royalties. If the system cannot definitively prove inclusion or verify state due to infrastructure failure (e.g., RPC node downtime, network partition, database unavailability), it must not default to a permissive state.

## Decision
Arkhe operates under a strict **fail-closed** paradigm.

*   **RPC Failures:** If an RPC call (Solana, Ethereum, etc.) fails, times out, or returns an ambiguous result during a verification process, the process MUST return an error. It MUST NEVER default to a `Verified` or successful state by omission.
*   **Audit Logging:** If writing an audit log fails, the associated operation MUST be blocked.
*   **Circuit Breakers:** We will use `tower::limit` or `failsafe-rs` for RPC circuit breaking. When the circuit is open, requests must fail fast with an error, preserving the fail-closed invariant.
*   **Falsifiers:** Every component and invariant, especially this fail-closed behavior, MUST have a corresponding automated test (falsifier) that proves the system fails when it should.

## Consequences
*   Strong security guarantees regarding state verification.
*   System availability might be temporarily reduced during infrastructure outages, but integrity is strictly preserved.
*   Significant effort must be dedicated to writing falsifier tests for all critical paths.
