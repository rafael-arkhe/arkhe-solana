//! CIDv1 encoding based on BLAKE3 content-addressed weights.
//! Multicodec for raw binary is 0x55, BLAKE3-256 multihash code is 0x1e.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CidV1(pub String);

impl CidV1 {
    pub fn from_blake3_digest(digest: &Digest32) -> Self {
        // Base32 / hex CIDv1 representation: "bafk" prefix + multihash (0x1e, 0x20, 32 bytes)
        let mut raw = Vec::with_capacity(36);
        raw.push(0x01); // CIDv1
        raw.push(0x55); // raw binary multicodec
        raw.push(0x1e); // blake3 multihash code
        raw.push(0x20); // 32-byte digest length
        raw.extend_from_slice(digest.as_bytes());
        CidV1(format!("bafk{}", hex::encode(&raw)))
    }

    pub fn to_digest(&self) -> Option<Digest32> {
        let hex_part = self.0.strip_prefix("bafk")?;
        let bytes = hex::decode(hex_part).ok()?;
        if bytes.len() == 36 && bytes[0] == 0x01 && bytes[1] == 0x55 && bytes[2] == 0x1e && bytes[3] == 0x20 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[4..36]);
            Some(Digest32(arr))
        } else {
            None
        }
    }
}
