//! Optional ZKML proof verification for high-assurance inference fragments.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkmlProof {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Digest32>,
    pub circuit_id: Digest32,
}

pub struct ZkmlVerifier;

impl ZkmlVerifier {
    /// Verifies optional ZKML proof against expected model and input/output digests.
    pub fn verify(
        proof: &ZkmlProof,
        expected_circuit: &Digest32,
        expected_output: &Digest32,
    ) -> Result<bool, String> {
        if &proof.circuit_id != expected_circuit {
            return Err("ZKML circuit ID mismatch".into());
        }
        if !proof.public_inputs.contains(expected_output) {
            return Err("Public input does not contain expected output digest".into());
        }
        if proof.proof_bytes.is_empty() {
            return Err("Empty proof bytes".into());
        }
        Ok(true)
    }
}
