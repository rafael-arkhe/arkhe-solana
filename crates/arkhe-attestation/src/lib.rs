//! arkhe-attestation — grafo de atestação, freshness check e gate fail-closed.
//!
//! Portado dos scripts Python originais (attestation_graph.py,
//! verify_freshness.py, evaluateAttestation.ts, junit_to_report.py)
//! para o ecossistema Rust do arkhe-solana.
//!
//! Invariantes:
//!   - BFS de propagação de compromised com depth correcto (não hardcoded).
//!   - Dual-hash SHA-256 + BLAKE3 verificado em AMBAS as direcções.
//!   - Fail-closed: sem freshness.json, claims de código ficam compromised.

pub mod graph;
pub mod hash;
pub mod junit;
pub mod types;

pub use graph::{build_graph, detect_cycles, propagate_compromised};
pub use hash::{aggregate_hash, compute_source_hashes};
pub use types::{Claim, ClaimStatus, DualHash, Freshness, GateDecision};
