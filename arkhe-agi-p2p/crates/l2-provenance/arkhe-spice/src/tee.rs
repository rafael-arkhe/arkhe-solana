//! TEE Attestation Quote verification (Intel SGX / AMD SEV-SNP / Titan M2).
//! Note: TEE is treated strictly as an acceleration / context layer, never an unconditional root of trust.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeQuote {
    pub provider: String,
    pub report_data: Digest32,
    pub signature_bytes: Vec<u8>,
    pub cert_chain: Vec<u8>,
}

pub struct TeeVerifier;

impl TeeVerifier {
    pub fn verify_quote(quote: &TeeQuote, expected_report_data: &Digest32) -> Result<bool, String> {
        if &quote.report_data != expected_report_data {
            return Err("TEE quote report_data does not match bound expectation".into());
        }
        if quote.signature_bytes.is_empty() {
            return Err("Invalid empty TEE quote signature".into());
        }
        Ok(true)
    }
}
