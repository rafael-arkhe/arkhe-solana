//! IETF SPICE Append-Only Inference Chain.
//! Manages computational provenance entries in a Merkle tree structure.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InferenceHopEntry {
    pub step: usize,
    pub model_id: String,
    pub input_digest: Digest32,
    pub intermediate_digest: Digest32,
    pub output_digest: Digest32,
    pub leaf_hash: Digest32,
}

impl InferenceHopEntry {
    pub fn new(
        step: usize,
        model_id: String,
        input_digest: Digest32,
        intermediate_digest: Digest32,
        output_digest: Digest32,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SPICE:INFERENCE:LEAF\0");
        hasher.update(&step.to_be_bytes());
        hasher.update(model_id.as_bytes());
        hasher.update(input_digest.as_bytes());
        hasher.update(intermediate_digest.as_bytes());
        hasher.update(output_digest.as_bytes());
        let leaf_hash = Digest32(*hasher.finalize().as_bytes());

        Self {
            step,
            model_id,
            input_digest,
            intermediate_digest,
            output_digest,
            leaf_hash,
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct InferenceChain {
    pub hops: Vec<InferenceHopEntry>,
}

impl InferenceChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_hop(&mut self, entry: InferenceHopEntry) {
        self.hops.push(entry);
    }

    /// Computes the overall inference_root Merkle digest over all execution hops.
    pub fn compute_inference_root(&self) -> Digest32 {
        if self.hops.is_empty() {
            return Digest32::ZERO;
        }
        let mut current_hashes: Vec<Digest32> = self.hops.iter().map(|h| h.leaf_hash).collect();
        while current_hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in current_hashes.chunks(2) {
                if chunk.len() == 2 {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(b"SPICE:INFERENCE:NODE\0");
                    hasher.update(chunk[0].as_bytes());
                    hasher.update(chunk[1].as_bytes());
                    next.push(Digest32(*hasher.finalize().as_bytes()));
                } else {
                    next.push(chunk[0]);
                }
            }
            current_hashes = next;
        }
        current_hashes[0]
    }
}
