//! Mobile Work Evidence Record (MobileWER) struct and canonical hashing.

use crate::action::MobileAction;
use arkhe_core::{to_canonical_cbor, CoreError, Digest32, DOMAIN_MOBILE_ACTION};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileWER {
    pub version: u8,
    pub device_attestation_hash: Digest32, // H(attestation_blob || first_wer_nonce || app_measurement)
    pub app_id: Digest32,
    pub action: MobileAction,
    pub input_digest: Digest32,
    pub output_digest: Digest32,
    pub policy_digest: Digest32,
    pub performed_at: u64,
    pub evidence_refs: Vec<Digest32>,
}

impl MobileWER {
    pub fn compute_wer_digest(&self) -> Result<Digest32, CoreError> {
        let canonical_cbor = to_canonical_cbor(self)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_MOBILE_ACTION);
        hasher.update(&canonical_cbor);
        Ok(Digest32(*hasher.finalize().as_bytes()))
    }
}
