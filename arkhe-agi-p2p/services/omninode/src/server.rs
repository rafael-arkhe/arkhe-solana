//! OmniNode server endpoints and P2P handlers.

use crate::storage::ChunkStorage;
use arkhe_core::Digest32;
use arkhe_omninode_client::CidV1;
use std::sync::{Arc, Mutex};

pub struct OmniNodeServer {
    pub storage: Arc<Mutex<ChunkStorage>>,
}

impl Default for OmniNodeServer {
    fn default() -> Self {
        Self::new()
    }
}

impl OmniNodeServer {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(ChunkStorage::new())),
        }
    }

    pub fn handle_chunk_upload(&self, data: Vec<u8>) -> CidV1 {
        let digest = Digest32::blake3_hash(&data);
        let cid = CidV1::from_blake3_digest(&digest);
        let mut storage = self.storage.lock().unwrap();
        storage.put(cid.clone(), data);
        cid
    }

    pub fn handle_chunk_fetch(&self, cid: &CidV1) -> Option<Vec<u8>> {
        let storage = self.storage.lock().unwrap();
        storage.get(cid).cloned()
    }
}
