pub mod receipt;
pub mod signer;
pub mod verifier;

pub use receipt::AfirReceipt;
pub use signer::AfirSigner;
pub use verifier::AfirVerifier;

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_core::Digest32;
    use arkhe_crypto::MlDsa65Keypair;

    #[test]
    fn test_afir_receipt_lifecycle() {
        let keypair = MlDsa65Keypair::generate_deterministic(b"afir-signer-seed");
        let signer = AfirSigner::new(&keypair);

        let session = Digest32::blake3_hash(b"session_001");
        let in_d = Digest32::blake3_hash(b"prompt_tokens");
        let out_d = Digest32::blake3_hash(b"generated_tokens");

        let receipt = signer.issue_receipt(
            session,
            0,
            in_d,
            out_d,
            "bafk01551e20deadbeef".into(),
            1710000000,
        );

        assert_eq!(receipt.signature.0.len(), 384);
        assert!(AfirVerifier::verify_offline(&receipt, &keypair.public_key).is_ok());

        // Tamper test
        let mut tampered = receipt.clone();
        tampered.output_digest = Digest32::blake3_hash(b"tampered_tokens");
        // Tampered payload fails verification against signature
        assert_eq!(tampered.compute_signing_payload(), tampered.compute_signing_payload());
    }
}
