pub mod cid;
pub mod chunker;
pub mod fetcher;

pub use cid::CidV1;
pub use chunker::{ModelWeightChunk, WeightChunker};
pub use fetcher::OmniNodeFetcher;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_and_fetch() {
        let sample_weights = b"weight_tensor_matrix_layer_0".to_vec();
        let chunks = WeightChunker::chunk_tensor_blocks(vec![
            ("blk.0.attn_q.weight".to_string(), 0, sample_weights),
        ]);
        assert_eq!(chunks.len(), 1);

        let mut fetcher = OmniNodeFetcher::new();
        fetcher.register_chunk(chunks[0].clone());

        let retrieved = fetcher.fetch_and_verify(&chunks[0].cid).unwrap();
        assert_eq!(retrieved.layer_index, 0);
    }
}
