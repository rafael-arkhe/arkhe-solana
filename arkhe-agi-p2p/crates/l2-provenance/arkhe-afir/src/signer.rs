//! ML-DSA-65 Signer for AFiR Receipts.

use crate::receipt::AfirReceipt;
use arkhe_core::Digest32;
use arkhe_crypto::MlDsa65Keypair;

pub struct AfirSigner<'a> {
    pub keypair: &'a MlDsa65Keypair,
}

impl<'a> AfirSigner<'a> {
    pub fn new(keypair: &'a MlDsa65Keypair) -> Self {
        Self { keypair }
    }

    pub fn issue_receipt(
        &self,
        session_id: Digest32,
        step_index: u32,
        input_digest: Digest32,
        output_digest: Digest32,
        model_cid: String,
        execution_timestamp: u64,
    ) -> AfirReceipt {
        let mut receipt = AfirReceipt {
            version: 1,
            session_id,
            step_index,
            input_digest,
            output_digest,
            model_cid,
            execution_timestamp,
            signature: arkhe_crypto::MlDsa65Signature(vec![]),
        };

        let payload_digest = receipt.compute_signing_payload();
        let sig = self.keypair.sign(payload_digest.as_bytes());
        receipt.signature = sig;
        receipt
    }
}
