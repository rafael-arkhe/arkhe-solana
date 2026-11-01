//! Offline verification of AFiR receipts.

use crate::receipt::AfirReceipt;
use arkhe_crypto::{MlDsa65Keypair, MlDsa65PublicKey};

pub struct AfirVerifier;

impl AfirVerifier {
    pub fn verify_offline(
        receipt: &AfirReceipt,
        public_key: &MlDsa65PublicKey,
    ) -> Result<(), String> {
        if receipt.version != 1 {
            return Err("Unsupported AFiR receipt version".into());
        }
        let payload = receipt.compute_signing_payload();
        MlDsa65Keypair::verify(public_key, payload.as_bytes(), &receipt.signature)
            .map_err(|e| format!("AFiR signature verification failed: {}", e))
    }
}
