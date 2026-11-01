//! Content-addressed chunk fetcher over P2P network.

use crate::cid::CidV1;
use crate::chunker::ModelWeightChunk;
use arkhe_core::Digest32;
use std::collections::HashMap;

#[derive(Default)]
pub struct OmniNodeFetcher {
    store: HashMap<CidV1, ModelWeightChunk>,
}

impl OmniNodeFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_chunk(&mut self, chunk: ModelWeightChunk) {
        self.store.insert(chunk.cid.clone(), chunk);
    }

    /// Fetches chunk by CIDv1 and strictly validates that BLAKE3 hash matches
    pub fn fetch_and_verify(&self, cid: &CidV1) -> Result<&ModelWeightChunk, String> {
        let chunk = self.store.get(cid).ok_or_else(|| "Chunk not found".to_string())?;
        let computed = Digest32::blake3_hash(&chunk.data);
        if computed != chunk.digest {
            return Err("Hash mismatch between payload and declared digest".into());
        }
        let expected_cid = CidV1::from_blake3_digest(&computed);
        if &expected_cid != cid {
            return Err("CID mismatch".into());
        }
        Ok(chunk)
    }
}
