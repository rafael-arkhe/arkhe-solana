//! WASM bindings and serialization for browser / offline execution.

use crate::bundle::{OfflineVerificationBundle, OfflineVerifier};

pub fn verify_bundle_json(bundle_json: &str) -> Result<bool, String> {
    let bundle: OfflineVerificationBundle = serde_json::from_str(bundle_json)
        .map_err(|e| format!("Invalid bundle JSON: {}", e))?;
    OfflineVerifier::verify_bundle(&bundle)
}
