//! Chunks transformer weights (e.g. GGUF tensors) per transformer block.

use crate::cid::CidV1;
use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelWeightChunk {
    pub layer_index: usize,
    pub block_name: String,
    pub data: Vec<u8>,
    pub digest: Digest32,
    pub cid: CidV1,
}

pub struct WeightChunker;

impl WeightChunker {
    pub fn chunk_tensor_blocks(tensors: Vec<(String, usize, Vec<u8>)>) -> Vec<ModelWeightChunk> {
        tensors
            .into_iter()
            .map(|(block_name, layer_index, data)| {
                let digest = Digest32::blake3_hash(&data);
                let cid = CidV1::from_blake3_digest(&digest);
                ModelWeightChunk {
                    layer_index,
                    block_name,
                    data,
                    digest,
                    cid,
                }
            })
            .collect()
    }
}
