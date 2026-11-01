//! Titan M2 / StrongBox Hardware Attestation binding.
//!
//! Binding formula:
//! device_attestation_hash = H(attestation_blob || first_wer_nonce || app_measurement)

use arkhe_core::Digest32;

pub struct TitanM2Binding;

impl TitanM2Binding {
    pub fn compute_device_attestation_hash(
        attestation_blob: &[u8],
        first_wer_nonce: &[u8; 32],
        app_measurement: &[u8; 32],
    ) -> Digest32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AKG:TITAN_M2:BINDING:v1\0");
        hasher.update(attestation_blob);
        hasher.update(first_wer_nonce);
        hasher.update(app_measurement);
        Digest32(*hasher.finalize().as_bytes())
    }

    pub fn verify_binding(
        declared_hash: &Digest32,
        attestation_blob: &[u8],
        first_wer_nonce: &[u8; 32],
        app_measurement: &[u8; 32],
    ) -> bool {
        let expected = Self::compute_device_attestation_hash(
            attestation_blob,
            first_wer_nonce,
            app_measurement,
        );
        &expected == declared_hash
    }
}
