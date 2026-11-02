#[test]
fn test_complete_offline_verification_and_falsifiers() {
    use arkhe_afir::AfirSigner;
    use arkhe_core::Digest32;
    use arkhe_crypto::MlDsa65Keypair;
    use arkhe_mobile_mmr::{HardwareStrongBox, LocalMmr, SignedCheckpoint};
    use arkhe_mobile_verify::{OfflineVerificationBundle, OfflineVerifier};
    use arkhe_mobile_wer::{MobileAction, MobileWER, TitanM2Binding};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let quote = b"titan_m2_hardware_measured_boot_quote";
    let nonce = [101u8; 32];
    let app_measurement = [77u8; 32];
    let device_hash = TitanM2Binding::compute_device_attestation_hash(
        quote,
        &nonce,
        &app_measurement,
    );

    let in_d = Digest32::blake3_hash(b"sample_query");
    let out_d = Digest32::blake3_hash(b"sample_response");

    let wer = MobileWER {
        version: 1,
        device_attestation_hash: device_hash,
        app_id: Digest32::blake3_hash(b"space.arkhe.mobile"),
        action: MobileAction::InferenceExecution {
            model_name: "llama3-8b".into(),
            tokens_in: 50,
            tokens_out: 25,
        },
        input_digest: in_d,
        output_digest: out_d,
        policy_digest: Digest32::blake3_hash(b"policy_01"),
        performed_at: 1712000000,
        evidence_refs: vec![],
    };

    let mut mmr = LocalMmr::new();
    let wer_d = wer.compute_wer_digest().unwrap();
    mmr.append(wer_d);

    let strongbox = HardwareStrongBox::init_isolated(b"strongbox_seed_e2e");
    let mut rng = OsRng;
    let ed_key = SigningKey::generate(&mut rng);

    let checkpoint = SignedCheckpoint::create(
        &mmr,
        device_hash,
        1712000050,
        &strongbox,
        &ed_key,
    )
    .unwrap();

    let afir_keys = MlDsa65Keypair::generate_deterministic(b"afir_seed_e2e");
    let signer = AfirSigner::new(&afir_keys);
    let receipt = signer.issue_receipt(
        Digest32::blake3_hash(b"session"),
        0,
        in_d,
        out_d,
        "bafk01551e20deadbeef".into(),
        1712000020,
    );

    let bundle = OfflineVerificationBundle {
        wer,
        wer_index: 0,
        mmr_proof: vec![],
        checkpoint,
        afir_receipts: vec![receipt],
        afir_signer_pubkey: afir_keys.public_key,
        raw_attestation_blob: quote.to_vec(),
        first_wer_nonce: nonce,
        app_measurement,
    };

    // 1. Honest verification passes offline
    assert!(OfflineVerifier::verify_bundle(&bundle).is_ok());

    // 2. FALSIFIER 1: History rewrite (tampered output digest)
    let mut falsified_wer = bundle.clone();
    falsified_wer.wer.output_digest = Digest32::blake3_hash(b"tampered_response_tokens");
    assert!(
        OfflineVerifier::verify_bundle(&falsified_wer).is_err(),
        "Falsifier failed: history tampering went undetected!"
    );

    // 3. FALSIFIER 2: Tampered Titan M2 attestation quote
    let mut falsified_device = bundle.clone();
    falsified_device.raw_attestation_blob = b"tampered_attacker_quote".to_vec();
    assert!(
        OfflineVerifier::verify_bundle(&falsified_device).is_err(),
        "Falsifier failed: unauthentic hardware quote went undetected!"
    );
}
