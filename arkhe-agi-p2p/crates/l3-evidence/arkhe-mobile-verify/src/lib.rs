pub mod bundle;
pub mod wasm;

pub use bundle::{OfflineVerificationBundle, OfflineVerifier};
pub use wasm::verify_bundle_json;

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_afir::AfirSigner;
    use arkhe_core::Digest32;
    use arkhe_crypto::MlDsa65Keypair;
    use arkhe_mobile_mmr::{HardwareStrongBox, LocalMmr, SignedCheckpoint};
    use arkhe_mobile_wer::{MobileAction, MobileWER, TitanM2Binding};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_offline_bundle_verification() {
        let attestation_blob = b"titan_m2_secure_element_p384_quote";
        let nonce = [11u8; 32];
        let app_measurement = [99u8; 32];

        let device_hash = TitanM2Binding::compute_device_attestation_hash(
            attestation_blob,
            &nonce,
            &app_measurement,
        );

        let input_d = Digest32::blake3_hash(b"test_query");
        let output_d = Digest32::blake3_hash(b"test_response");

        let wer = MobileWER {
            version: 1,
            device_attestation_hash: device_hash,
            app_id: Digest32::blake3_hash(b"space.arkhe.mobile"),
            action: MobileAction::InferenceExecution {
                model_name: "llama3-8b".into(),
                tokens_in: 10,
                tokens_out: 20,
            },
            input_digest: input_d,
            output_digest: output_d,
            policy_digest: Digest32::blake3_hash(b"policy"),
            performed_at: 1712000000,
            evidence_refs: vec![],
        };

        let mut mmr = LocalMmr::new();
        let wer_digest = wer.compute_wer_digest().unwrap();
        mmr.append(wer_digest);

        let strongbox = HardwareStrongBox::init_isolated(b"strongbox_seed_1");
        let mut rng = OsRng;
        let ed_key = SigningKey::generate(&mut rng);

        let checkpoint = SignedCheckpoint::create(
            &mmr,
            device_hash,
            1712000100,
            &strongbox,
            &ed_key,
        )
        .unwrap();

        let afir_keypair = MlDsa65Keypair::generate_deterministic(b"afir_signer_seed");
        let afir_signer = AfirSigner::new(&afir_keypair);
        let receipt = afir_signer.issue_receipt(
            Digest32::blake3_hash(b"session"),
            0,
            input_d,
            output_d,
            "bafk01551e20deadbeef".into(),
            1712000050,
        );

        let bundle = OfflineVerificationBundle {
            wer: wer.clone(),
            wer_index: 0,
            mmr_proof: vec![],
            checkpoint,
            afir_receipts: vec![receipt],
            afir_signer_pubkey: afir_keypair.public_key,
            raw_attestation_blob: attestation_blob.to_vec(),
            first_wer_nonce: nonce,
            app_measurement,
        };

        assert!(OfflineVerifier::verify_bundle(&bundle).is_ok());

        // Falsifier: History Rewrite / Tampered output digest
        let mut tampered_bundle = bundle.clone();
        tampered_bundle.wer.output_digest = Digest32::blake3_hash(b"tampered_output");
        assert!(OfflineVerifier::verify_bundle(&tampered_bundle).is_err());
    }
}
