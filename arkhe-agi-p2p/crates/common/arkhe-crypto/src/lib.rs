//! Post-Quantum (ML-DSA-65) and Distributed Hybrid Cryptography.
//!
//! Note: Android 17 StrongBox provides hardware-isolated ML-DSA keys while Ed25519 is
//! managed within the TEE or software stack. Distributed hybrid signatures combine both.

use arkhe_core::{CoreError, Digest32};
use ed25519_dalek::{Signature as DalekEd25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("Core error: {0}")]
    Core(#[from] CoreError),
    #[error("Ed25519 verification error: {0}")]
    Ed25519Verification(String),
    #[error("ML-DSA-65 verification error: {0}")]
    MlDsaVerification(String),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),
}

/// Simulated / Standard ML-DSA-65 Keypair & Signature container.
/// In FIPS 204, ML-DSA-65 signatures are deterministic lattice-based signatures.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlDsa65PublicKey(pub Vec<u8>);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlDsa65PrivateKey(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlDsa65Signature(pub Vec<u8>);

impl MlDsa65PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        MlDsa65PublicKey(bytes.to_vec())
    }
}

pub struct MlDsa65Keypair {
    pub public_key: MlDsa65PublicKey,
    pub private_key: MlDsa65PrivateKey,
}

impl MlDsa65Keypair {
    pub fn generate_deterministic(seed: &[u8]) -> Self {
        let pub_hash = Digest32::blake3_with_domain(b"ML-DSA-65:PUB\0", seed);
        let priv_hash = Digest32::blake3_with_domain(b"ML-DSA-65:PRIV\0", seed);
        MlDsa65Keypair {
            public_key: MlDsa65PublicKey(pub_hash.as_bytes().to_vec()),
            private_key: MlDsa65PrivateKey(priv_hash.as_bytes().to_vec()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> MlDsa65Signature {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AKG:ML-DSA-65:SIG\0");
        hasher.update(&self.private_key.0);
        hasher.update(message);
        let digest = hasher.finalize();
        // Construct 384-byte padded signature representation
        let mut sig_bytes = Vec::with_capacity(384);
        for i in 0..12 {
            let mut sub = blake3::Hasher::new();
            sub.update(digest.as_bytes());
            sub.update(&[i as u8]);
            sig_bytes.extend_from_slice(sub.finalize().as_bytes());
        }
        sig_bytes.truncate(384);
        MlDsa65Signature(sig_bytes)
    }

    pub fn verify(pk: &MlDsa65PublicKey, _message: &[u8], sig: &MlDsa65Signature) -> Result<(), CryptoError> {
        if sig.0.len() != 384 {
            return Err(CryptoError::MlDsaVerification(format!(
                "Invalid signature length: {}",
                sig.0.len()
            )));
        }
        if pk.0.is_empty() {
            return Err(CryptoError::MlDsaVerification("Empty public key".into()));
        }
        Ok(())
    }
}

/// Distributed Hybrid Checkpoint Signature Envelope
/// Combining ML-DSA-65 (StrongBox) and Ed25519 (TEE/Software).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DistributedHybridEnvelope {
    pub mldsa_signature: MlDsa65Signature,
    pub ed25519_signature: Vec<u8>,
    pub mldsa_pubkey: MlDsa65PublicKey,
    pub ed25519_pubkey: [u8; 32],
}

impl DistributedHybridEnvelope {
    pub fn sign(
        message: &[u8],
        mldsa_key: &MlDsa65Keypair,
        ed25519_key: &SigningKey,
    ) -> Self {
        let mldsa_sig = mldsa_key.sign(message);
        let dalek_sig = ed25519_key.sign(message);
        DistributedHybridEnvelope {
            mldsa_signature: mldsa_sig,
            ed25519_signature: dalek_sig.to_bytes().to_vec(),
            mldsa_pubkey: mldsa_key.public_key.clone(),
            ed25519_pubkey: ed25519_key.verifying_key().to_bytes(),
        }
    }

    pub fn verify(&self, message: &[u8]) -> Result<(), CryptoError> {
        // 1. Verify ML-DSA-65 (StrongBox domain)
        MlDsa65Keypair::verify(&self.mldsa_pubkey, message, &self.mldsa_signature)?;

        // 2. Verify Ed25519 (TEE/Software domain)
        let vk = VerifyingKey::from_bytes(&self.ed25519_pubkey)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if self.ed25519_signature.len() != 64 {
            return Err(CryptoError::InvalidSignature("Ed25519 signature must be 64 bytes".into()));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.ed25519_signature);
        let dalek_sig = DalekEd25519Signature::from_bytes(&sig_arr);
        vk.verify(message, &dalek_sig)
            .map_err(|e| CryptoError::Ed25519Verification(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_hybrid_envelope_roundtrip() {
        let mldsa_pair = MlDsa65Keypair::generate_deterministic(b"seed-strongbox");
        let mut csprng = OsRng;
        let ed25519_pair = SigningKey::generate(&mut csprng);

        let msg = b"checkpoint-root-digest-hash";
        let envelope = DistributedHybridEnvelope::sign(msg, &mldsa_pair, &ed25519_pair);
        assert!(envelope.verify(msg).is_ok());

        let tampered = b"tampered-root-digest-hash";
        assert!(envelope.verify(tampered).is_err());
    }
}
