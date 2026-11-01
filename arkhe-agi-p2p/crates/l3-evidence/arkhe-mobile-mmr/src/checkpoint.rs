//! Signed Checkpoint generation combining MMR root, hardware attestation, and distributed hybrid envelope.

use crate::mmr::LocalMmr;
use crate::strongbox::StrongBoxStorage;
use arkhe_core::{Digest32, DOMAIN_CHECKPOINT};
use arkhe_crypto::{CryptoError, DistributedHybridEnvelope};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub mmr_size: u64,
    pub mmr_root: Digest32,
    pub device_attestation_hash: Digest32,
    pub timestamp: u64,
    pub hybrid_envelope: DistributedHybridEnvelope,
}

impl SignedCheckpoint {
    pub fn compute_checkpoint_digest(
        mmr_size: u64,
        mmr_root: &Digest32,
        device_attestation_hash: &Digest32,
        timestamp: u64,
    ) -> Digest32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_CHECKPOINT);
        hasher.update(&mmr_size.to_be_bytes());
        hasher.update(mmr_root.as_bytes());
        hasher.update(device_attestation_hash.as_bytes());
        hasher.update(&timestamp.to_be_bytes());
        Digest32(*hasher.finalize().as_bytes())
    }

    pub fn create(
        mmr: &LocalMmr,
        device_attestation_hash: Digest32,
        timestamp: u64,
        strongbox: &dyn StrongBoxStorage,
        ed25519_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let size = mmr.leaves.len() as u64;
        let root = mmr.bag_peaks();
        let digest = Self::compute_checkpoint_digest(size, &root, &device_attestation_hash, timestamp);

        let mldsa_sig = strongbox.sign_checkpoint(digest.as_bytes())?;
        let ed_sig = ed25519_key.sign(digest.as_bytes()).to_bytes().to_vec();

        let envelope = DistributedHybridEnvelope {
            mldsa_signature: mldsa_sig,
            ed25519_signature: ed_sig,
            mldsa_pubkey: strongbox.get_public_key(),
            ed25519_pubkey: ed25519_key.verifying_key().to_bytes(),
        };

        Ok(Self {
            mmr_size: size,
            mmr_root: root,
            device_attestation_hash,
            timestamp,
            hybrid_envelope: envelope,
        })
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        let digest = Self::compute_checkpoint_digest(
            self.mmr_size,
            &self.mmr_root,
            &self.device_attestation_hash,
            self.timestamp,
        );
        self.hybrid_envelope.verify(digest.as_bytes())
    }
}
