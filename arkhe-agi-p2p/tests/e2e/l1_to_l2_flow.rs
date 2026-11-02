#[test]
fn test_l1_to_l2_flow() {
    use arkhe_afir::{AfirSigner, AfirVerifier};
    use arkhe_core::Digest32;
    use arkhe_crypto::MlDsa65Keypair;
    use arkhe_omninode_client::WeightChunker;
    use arkhe_spice::{InferenceChain, InferenceHopEntry};
    // 1. L1: Chunker processes transformer weights and obtains CIDv1
    let weight_bytes = b"sample_transformer_layer_0_weights".to_vec();
    let chunks = WeightChunker::chunk_tensor_blocks(vec![
        ("layer.0.attn".into(), 0, weight_bytes.clone()),
    ]);
    let chunk = &chunks[0];
    let model_cid = chunk.cid.0.clone();

    // 2. L2: Execute inference and build SPICE inference_chain
    let prompt_digest = Digest32::blake3_hash(b"hello world prompt");
    let output_digest = Digest32::blake3_hash(b"generated token response");
    let mut chain = InferenceChain::new();
    chain.append_hop(InferenceHopEntry::new(
        0,
        model_cid.clone(),
        prompt_digest,
        Digest32::blake3_hash(b"hidden_states"),
        output_digest,
    ));
    let inference_root = chain.compute_inference_root();

    // 3. L2: Issue AFiR receipt signed by ML-DSA-65
    let afir_keys = MlDsa65Keypair::generate_deterministic(b"e2e-afir-seed");
    let signer = AfirSigner::new(&afir_keys);
    let session_id = Digest32::blake3_hash(b"session_flow_123");
    let receipt = signer.issue_receipt(
        session_id,
        0,
        prompt_digest,
        output_digest,
        model_cid,
        1712000000,
    );

    // Verify AFiR receipt offline
    assert!(AfirVerifier::verify_offline(&receipt, &afir_keys.public_key).is_ok());
    assert_ne!(inference_root, Digest32::ZERO);
}
