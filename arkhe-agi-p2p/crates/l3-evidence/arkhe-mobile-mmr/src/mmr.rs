//! Merkle Mountain Range (MMR) append-only accumulator.
//!
//! Enforces:
//! - Domain separation: 0x00 leaf, 0x01 node, 0x02 root
//! - Right-to-Left peak bagging order
//! - Unconditional bagging with total MMR size (8-byte big endian) as prefix

use arkhe_core::{Digest32, DOMAIN_MMR_LEAF, DOMAIN_MMR_NODE, DOMAIN_MMR_ROOT};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalMmr {
    pub leaves: Vec<Digest32>,
}

impl Default for LocalMmr {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalMmr {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    pub fn append(&mut self, leaf_digest: Digest32) -> usize {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[DOMAIN_MMR_LEAF]);
        hasher.update(leaf_digest.as_bytes());
        let hashed_leaf = Digest32(*hasher.finalize().as_bytes());
        self.leaves.push(hashed_leaf);
        self.leaves.len() - 1
    }

    pub fn get_peaks(&self) -> Vec<Digest32> {
        if self.leaves.is_empty() {
            return Vec::new();
        }

        let mut peaks = Vec::new();
        let mut remaining = self.leaves.len();
        let mut offset = 0;

        while remaining > 0 {
            // Find largest power of 2 <= remaining
            let mut power = 1;
            while power * 2 <= remaining {
                power *= 2;
            }

            // Calculate peak for this complete subtree of size `power`
            let sub_leaves = &self.leaves[offset..offset + power];
            let peak = Self::subtree_root(sub_leaves);
            peaks.push(peak);

            offset += power;
            remaining -= power;
        }

        peaks
    }

    fn subtree_root(leaves: &[Digest32]) -> Digest32 {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mid = leaves.len() / 2;
        let left = Self::subtree_root(&leaves[..mid]);
        let right = Self::subtree_root(&leaves[mid..]);

        let mut hasher = blake3::Hasher::new();
        hasher.update(&[DOMAIN_MMR_NODE]);
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        Digest32(*hasher.finalize().as_bytes())
    }

    /// Computes the MMR root using Right-to-Left bagging order
    /// Bagging: root = BLAKE3( 0x02 || size_u64_be || p_k || ... || p_1 )
    pub fn bag_peaks(&self) -> Digest32 {
        let peaks = self.get_peaks();
        let size = self.leaves.len() as u64;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&[DOMAIN_MMR_ROOT]);
        hasher.update(&size.to_be_bytes());

        // Right-to-Left order: reverse peaks
        for peak in peaks.iter().rev() {
            hasher.update(peak.as_bytes());
        }

        Digest32(*hasher.finalize().as_bytes())
    }

    /// Generates inclusion proof for a given leaf index
    pub fn get_inclusion_proof(&self, leaf_index: usize) -> Option<Vec<Digest32>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        // Subtree path proof
        let mut proof = Vec::new();
        let mut remaining = self.leaves.len();
        let mut offset = 0;

        while remaining > 0 {
            let mut power = 1;
            while power * 2 <= remaining {
                power *= 2;
            }

            if leaf_index >= offset && leaf_index < offset + power {
                // Leaf is within this subtree
                let sub_leaves = &self.leaves[offset..offset + power];
                Self::collect_subtree_proof(sub_leaves, leaf_index - offset, &mut proof);
                break;
            }

            offset += power;
            remaining -= power;
        }

        Some(proof)
    }

    fn collect_subtree_proof(leaves: &[Digest32], idx: usize, proof: &mut Vec<Digest32>) {
        if leaves.len() == 1 {
            return;
        }
        let mid = leaves.len() / 2;
        if idx < mid {
            let right_root = Self::subtree_root(&leaves[mid..]);
            proof.push(right_root);
            Self::collect_subtree_proof(&leaves[..mid], idx, proof);
        } else {
            let left_root = Self::subtree_root(&leaves[..mid]);
            proof.push(left_root);
            Self::collect_subtree_proof(&leaves[mid..], idx - mid, proof);
        }
    }
}
