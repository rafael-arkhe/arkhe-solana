//! Storage of model chunks.

use arkhe_omninode_client::CidV1;
use std::collections::HashMap;

#[derive(Default)]
pub struct ChunkStorage {
    storage: HashMap<CidV1, Vec<u8>>,
}

impl ChunkStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, cid: CidV1, data: Vec<u8>) {
        self.storage.insert(cid, data);
    }

    pub fn get(&self, cid: &CidV1) -> Option<&Vec<u8>> {
        self.storage.get(cid)
    }

    pub fn exists(&self, cid: &CidV1) -> bool {
        self.storage.contains_key(cid)
    }
}
