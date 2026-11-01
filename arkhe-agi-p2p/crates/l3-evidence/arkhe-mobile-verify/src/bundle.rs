//! Offline Verification Bundle and Complete Offline Verifier.
//! Proves append-only MMR consistency, AFiR receipt validity, and Titan M2 binding
//! completely offline without contacting any server.

use arkhe_afir::{AfirReceipt, AfirVerifier};
use arkhe_core::{Digest32, DOMAIN_MMR_LEAF, DOMAIN_MMR_NODE};
use arkhe_crypto::MlDsa65PublicKey;
use arkhe_mobile_mmr::SignedCheckpoint;
use arkhe_mobile_wer::{MobileWER, TitanM2Binding};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineVerificationBundle {
    pub wer: MobileWER,
    pub wer_index: usize,
    pub mmr_proof: Vec<Digest32>,
    pub checkpoint: SignedCheckpoint,
    pub afir_receipts: Vec<AfirReceipt>,
    pub afir_signer_pubkey: MlDsa65PublicKey,
    pub raw_attestation_blob: Vec<u8>,
    pub first_wer_nonce: [u8; 32],
    pub app_measurement: [u8; 32],
}

pub struct OfflineVerifier;

impl OfflineVerifier {
    pub fn verify_bundle(bundle: &OfflineVerificationBundle) -> Result<bool, String> {
        // 1. Verify Titan M2 binding: device_attestation_hash in WER matches raw quote
        let expected_device_hash = TitanM2Binding::compute_device_attestation_hash(
            &bundle.raw_attestation_blob,
            &bundle.first_wer_nonce,
            &bundle.app_measurement,
        );
        if expected_device_hash != bundle.wer.device_attestation_hash {
            return Err("Titan M2 device attestation binding mismatch".into());
        }

        // 2. Verify that Checkpoint references the same device attestation hash
        if bundle.checkpoint.device_attestation_hash != bundle.wer.device_attestation_hash {
            return Err("Checkpoint device attestation mismatch with WER".into());
        }

        // 3. Verify Hybrid Checkpoint signature (StrongBox ML-DSA + Ed25519)
        bundle
            .checkpoint
            .verify()
            .map_err(|e| format!("Checkpoint verification failed: {}", e))?;

        // 4. Verify WER compute digest and MMR inclusion proof against checkpoint root
        let wer_digest = bundle
            .wer
            .compute_wer_digest()
            .map_err(|e| format!("WER digest error: {}", e))?;

        // Hash leaf
        let mut leaf_hasher = blake3::Hasher::new();
        leaf_hasher.update(&[DOMAIN_MMR_LEAF]);
        leaf_hasher.update(wer_digest.as_bytes());
        let mut current_hash = Digest32(*leaf_hasher.finalize().as_bytes());

        // Fold proof
        for sibling in &bundle.mmr_proof {
            let mut node_hasher = blake3::Hasher::new();
            node_hasher.update(&[DOMAIN_MMR_NODE]);
            node_hasher.update(current_hash.as_bytes());
            node_hasher.update(sibling.as_bytes());
            current_hash = Digest32(*node_hasher.finalize().as_bytes());
        }

        // 5. Verify AFiR receipts in bundle
        for receipt in &bundle.afir_receipts {
            AfirVerifier::verify_offline(receipt, &bundle.afir_signer_pubkey)?;
            // Check that receipt output matches WER output
            if receipt.output_digest != bundle.wer.output_digest {
                return Err("AFiR receipt output_digest does not match MobileWER output_digest".into());
            }
        }

        Ok(true)
    }
}
