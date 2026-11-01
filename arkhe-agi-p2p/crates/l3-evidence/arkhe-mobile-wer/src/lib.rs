pub mod action;
pub mod attestation;
pub mod wer;

pub use action::MobileAction;
pub use attestation::TitanM2Binding;
pub use wer::MobileWER;

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_core::Digest32;

    #[test]
    fn test_mobile_wer_binding_and_digest() {
        let attestation_blob = b"titan_m2_raw_x509_cert_quote";
        let nonce = [7u8; 32];
        let app_measurement = [42u8; 32];

        let device_hash = TitanM2Binding::compute_device_attestation_hash(
            attestation_blob,
            &nonce,
            &app_measurement,
        );

        assert!(TitanM2Binding::verify_binding(
            &device_hash,
            attestation_blob,
            &nonce,
            &app_measurement
        ));

        let wer = MobileWER {
            version: 1,
            device_attestation_hash: device_hash,
            app_id: Digest32::blake3_hash(b"space.arkhe.mobile"),
            action: MobileAction::InferenceExecution {
                model_name: "llama3-8b-q4".into(),
                tokens_in: 128,
                tokens_out: 64,
            },
            input_digest: Digest32::blake3_hash(b"query"),
            output_digest: Digest32::blake3_hash(b"response"),
            policy_digest: Digest32::blake3_hash(b"policy_baseline"),
            performed_at: 1712000000,
            evidence_refs: vec![Digest32::blake3_hash(b"afir_receipt_ref")],
        };

        let digest = wer.compute_wer_digest().unwrap();
        assert_ne!(digest, Digest32::ZERO);
    }
}
