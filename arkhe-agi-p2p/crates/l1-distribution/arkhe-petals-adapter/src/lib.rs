//! Petals swarm layer distribution fallback.
//!
//! Note on security: Petals delegates layer execution across untrusted peers.
//! Integrity is explicitly NOT guaranteed by Petals; integrity must be strictly
//! anchored and proven via Layer 2 (AFiR / SPICE) and Layer 3 (MobileWER).

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmLayerAssignment {
    pub model_id: String,
    pub start_block: usize,
    pub end_block: usize,
    pub peer_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwarmInferenceHop {
    pub hop_index: usize,
    pub peer_id: String,
    pub input_tensor_digest: Digest32,
    pub output_tensor_digest: Digest32,
}

#[derive(Default)]
pub struct PetalsSwarmRouter {
    assignments: Vec<SwarmLayerAssignment>,
}

impl PetalsSwarmRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_layer_assignment(&mut self, assignment: SwarmLayerAssignment) {
        self.assignments.push(assignment);
    }

    pub fn find_peer_for_layer(&self, block: usize) -> Option<String> {
        self.assignments
            .iter()
            .find(|a| block >= a.start_block && block <= a.end_block)
            .map(|a| a.peer_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_petals_layer_lookup() {
        let mut router = PetalsSwarmRouter::new();
        router.register_layer_assignment(SwarmLayerAssignment {
            model_id: "llama-3-8b".into(),
            start_block: 0,
            end_block: 15,
            peer_id: "peer_node_alpha".into(),
        });
        router.register_layer_assignment(SwarmLayerAssignment {
            model_id: "llama-3-8b".into(),
            start_block: 16,
            end_block: 31,
            peer_id: "peer_node_beta".into(),
        });

        assert_eq!(router.find_peer_for_layer(5), Some("peer_node_alpha".into()));
        assert_eq!(router.find_peer_for_layer(20), Some("peer_node_beta".into()));
        assert_eq!(router.find_peer_for_layer(35), None);
    }
}
