//! Hyperspace consensus engine node participant.

use arkhe_core::Digest32;
use arkhe_hyperspace_sdk::{DagBlock, MysticetiDagReader};
use std::sync::{Arc, Mutex};

pub struct HyperspaceNodeConsensus {
    pub dag: Arc<Mutex<MysticetiDagReader>>,
}

impl Default for HyperspaceNodeConsensus {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperspaceNodeConsensus {
    pub fn new() -> Self {
        Self {
            dag: Arc::new(Mutex::new(MysticetiDagReader::new())),
        }
    }

    pub fn commit_payment_tx(&self, tx: Digest32) -> u64 {
        let mut dag = self.dag.lock().unwrap();
        let current_round = dag.latest_round() + 1;
        let block = DagBlock {
            round: current_round,
            author: "local_hyperspace_validator".into(),
            parents: vec![],
            transactions: vec![tx],
            block_digest: Digest32::blake3_hash(&current_round.to_be_bytes()),
        };
        dag.append_committed_block(block);
        current_round
    }
}
