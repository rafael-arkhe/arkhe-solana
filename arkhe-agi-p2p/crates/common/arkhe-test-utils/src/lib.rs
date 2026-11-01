//! Common test fixtures and simulation generators.

use arkhe_core::Digest32;
use arkhe_crypto::MlDsa65Keypair;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

pub fn generate_mock_device_attestation(seed: &[u8]) -> (Digest32, [u8; 32]) {
    let nonce = Digest32::blake3_with_domain(b"NONCE\0", seed);
    let blob_hash = Digest32::blake3_with_domain(b"TITAN_M2_ATTESTATION\0", seed);
    (blob_hash, *nonce.as_bytes())
}

pub fn generate_mock_hybrid_keys() -> (MlDsa65Keypair, SigningKey) {
    let mldsa = MlDsa65Keypair::generate_deterministic(b"test-mldsa-seed");
    let mut rng = OsRng;
    let ed = SigningKey::generate(&mut rng);
    (mldsa, ed)
}
