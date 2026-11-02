//! Core cryptographic types, canonical serialization, and domain separators.

use serde::{Deserialize, Serialize};
use std::fmt;

pub const DOMAIN_MOBILE_ACTION: &[u8] = b"AKG:MOBILE:ACT:v1\0";
pub const DOMAIN_CHECKPOINT: &[u8] = b"AKG:CHECKPOINT:v1\0";
pub const DOMAIN_AFIR_RECEIPT: &[u8] = b"AKG:AFIR:RECEIPT:v1\0";
pub const DOMAIN_MMR_LEAF: u8 = 0x00;
pub const DOMAIN_MMR_NODE: u8 = 0x01;
pub const DOMAIN_MMR_ROOT: u8 = 0x02;

pub mod file_types;
pub use file_types::{
    classify_file, is_extension_prohibited, is_extension_restricted, validate_arkhe_file,
    ArkheFileType, ArkheLayer, ExtensionStatus,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Digest32(#[serde(with = "hex_serde")] pub [u8; 32]);

impl Digest32 {
    pub const ZERO: Digest32 = Digest32([0u8; 32]);

    pub fn new(bytes: [u8; 32]) -> Self {
        Digest32(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.len() != 32 {
            return Err(CoreError::InvalidDigestLength(slice.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Ok(Digest32(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn blake3_hash(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Digest32(*hash.as_bytes())
    }

    pub fn blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> Self {
        let hash = blake3::keyed_hash(key, data);
        Digest32(*hash.as_bytes())
    }

    pub fn blake3_with_domain(domain: &[u8], data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(data);
        Digest32(*hasher.finalize().as_bytes())
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32({})", hex::encode(self.0))
    }
}

mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(s).map_err(serde::de::Error::custom)?;
        if vec.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("Invalid digest length: expected 32, got {0}")]
    InvalidDigestLength(usize),
    #[error("CBOR serialization failed: {0}")]
    CborError(String),
}

/// Canonical deterministic CBOR encoding wrapper
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    let mut buf = Vec::new();
    cbor4ii::serde::to_writer(&mut buf, value)
        .map_err(|e| CoreError::CborError(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_blake3() {
        let d = Digest32::blake3_hash(b"test-data");
        assert_ne!(d, Digest32::ZERO);
        let hex_str = format!("{}", d);
        assert_eq!(hex_str.len(), 64);
    }
}
