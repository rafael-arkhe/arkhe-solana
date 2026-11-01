//! Mysticeti DAG state reader and fast path commit tracker.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DagBlock {
    pub round: u64,
    pub author: String,
    pub parents: Vec<Digest32>,
    pub transactions: Vec<Digest32>,
    pub block_digest: Digest32,
}

#[derive(Default)]
pub struct MysticetiDagReader {
    committed_blocks: Vec<DagBlock>,
}

impl MysticetiDagReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append_committed_block(&mut self, block: DagBlock) {
        self.committed_blocks.push(block);
    }

    pub fn latest_round(&self) -> u64 {
        self.committed_blocks.last().map(|b| b.round).unwrap_or(0)
    }

    pub fn is_transaction_committed(&self, tx: &Digest32) -> bool {
        self.committed_blocks
            .iter()
            .any(|b| b.transactions.contains(tx))
    }
}
