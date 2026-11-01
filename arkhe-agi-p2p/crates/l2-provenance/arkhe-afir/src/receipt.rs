//! 384-byte AFiR post-quantum receipt representation.
//!
//! Profile specifications:
//! - 0.785 ms overhead per fragment
//! - 384 bytes post-quantum ML-DSA-65 signed receipt
//! - TEE-free, compatible with SPICE Merkle tree

use arkhe_core::{Digest32, DOMAIN_AFIR_RECEIPT};
use arkhe_crypto::MlDsa65Signature;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AfirReceipt {
    pub version: u8,
    pub session_id: Digest32,
    pub step_index: u32,
    pub input_digest: Digest32,
    pub output_digest: Digest32,
    pub model_cid: String,
    pub execution_timestamp: u64,
    pub signature: MlDsa65Signature, // 384 bytes
}

impl AfirReceipt {
    pub fn compute_signing_payload(&self) -> Digest32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_AFIR_RECEIPT);
        hasher.update(&[self.version]);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&self.step_index.to_be_bytes());
        hasher.update(self.input_digest.as_bytes());
        hasher.update(self.output_digest.as_bytes());
        hasher.update(self.model_cid.as_bytes());
        hasher.update(&self.execution_timestamp.to_be_bytes());
        Digest32(*hasher.finalize().as_bytes())
    }
}
