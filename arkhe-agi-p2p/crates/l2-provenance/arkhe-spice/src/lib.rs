pub mod inference_chain;
pub mod tee;
pub mod zkml;

pub use inference_chain::{InferenceChain, InferenceHopEntry};
pub use tee::{TeeQuote, TeeVerifier};
pub use zkml::{ZkmlProof, ZkmlVerifier};

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_core::Digest32;

    #[test]
    fn test_inference_chain_merkle_root() {
        let mut chain = InferenceChain::new();
        let hop1 = InferenceHopEntry::new(
            0,
            "llama3-8b-chunk0".into(),
            Digest32::blake3_hash(b"token_input"),
            Digest32::blake3_hash(b"hidden_states_1"),
            Digest32::blake3_hash(b"hidden_states_2"),
        );
        let hop2 = InferenceHopEntry::new(
            1,
            "llama3-8b-chunk1".into(),
            Digest32::blake3_hash(b"hidden_states_2"),
            Digest32::blake3_hash(b"hidden_states_3"),
            Digest32::blake3_hash(b"logits_final"),
        );
        chain.append_hop(hop1);
        chain.append_hop(hop2);

        let root = chain.compute_inference_root();
        assert_ne!(root, Digest32::ZERO);
    }
}
