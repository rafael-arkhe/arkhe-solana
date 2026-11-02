#[test]
fn test_l2_to_l3_binding() {
    use arkhe_afir::AfirSigner;
    use arkhe_core::Digest32;
    use arkhe_crypto::MlDsa65Keypair;
    use arkhe_mobile_wer::{MobileAction, MobileWER, TitanM2Binding};
    // 1. L2 produces an AFiR receipt
    let afir_keys = MlDsa65Keypair::generate_deterministic(b"l2-l3-afir-seed");
    let signer = AfirSigner::new(&afir_keys);
    let prompt_d = Digest32::blake3_hash(b"agent prompt");
    let output_d = Digest32::blake3_hash(b"agent output decision");
    let receipt = signer.issue_receipt(
        Digest32::blake3_hash(b"session"),
        0,
        prompt_d,
        output_d,
        "bafk01551e20weights".into(),
        1712000000,
    );

    // 2. L3 hardware attestation
    let raw_quote = b"titan_m2_hardware_measured_boot_quote";
    let nonce = [12u8; 32];
    let app_measurement = [55u8; 32];
    let device_hash = TitanM2Binding::compute_device_attestation_hash(
        raw_quote,
        &nonce,
        &app_measurement,
    );

    // 3. Anchor into MobileWER
    let receipt_digest = receipt.compute_signing_payload();
    let wer = MobileWER {
        version: 1,
        device_attestation_hash: device_hash,
        app_id: Digest32::blake3_hash(b"space.arkhe.mobile"),
        action: MobileAction::InferenceExecution {
            model_name: "llama3-8b".into(),
            tokens_in: 32,
            tokens_out: 16,
        },
        input_digest: prompt_d,
        output_digest: output_d,
        policy_digest: Digest32::blake3_hash(b"safety_policy_v1"),
        performed_at: 1712000005,
        evidence_refs: vec![receipt_digest],
    };

    assert_eq!(wer.output_digest, receipt.output_digest);
    assert!(TitanM2Binding::verify_binding(
        &wer.device_attestation_hash,
        raw_quote,
        &nonce,
        &app_measurement
    ));
}
