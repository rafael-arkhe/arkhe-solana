//! A.N.N. (Autonomous Neural Network) Formal Cryptographic Accumulator Specification.
//!
//! Formal property:
//! Zero central weight authority; trust is derived solely from cryptographic verification
//! against a quasi-periodic winding accumulator state.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindingAccumulatorState {
    pub epoch: u64,
    pub accumulator_digest: Digest32,
    pub participant_count: usize,
    pub settlement_commitment: Digest32,
}

impl WindingAccumulatorState {
    pub fn initial() -> Self {
        Self {
            epoch: 0,
            accumulator_digest: Digest32::blake3_with_domain(b"ANN:ACCUMULATOR:GENESIS\0", b"genesis"),
            participant_count: 0,
            settlement_commitment: Digest32::ZERO,
        }
    }

    pub fn transition_epoch(
        &self,
        new_weights_digest: &Digest32,
        settlement_tx: &Digest32,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ANN:ACCUMULATOR:STEP\0");
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(self.accumulator_digest.as_bytes());
        hasher.update(new_weights_digest.as_bytes());

        Self {
            epoch: self.epoch + 1,
            accumulator_digest: Digest32(*hasher.finalize().as_bytes()),
            participant_count: self.participant_count + 1,
            settlement_commitment: *settlement_tx,
        }
    }

    pub fn verify_weights_inclusion(
        &self,
        previous_state: &WindingAccumulatorState,
        declared_weights: &Digest32,
        settlement_tx: &Digest32,
    ) -> bool {
        let expected = previous_state.transition_epoch(declared_weights, settlement_tx);
        expected.accumulator_digest == self.accumulator_digest && expected.epoch == self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ann_accumulator_transition() {
        let genesis = WindingAccumulatorState::initial();
        let weights = Digest32::blake3_hash(b"federated_layer_weights_epoch_1");
        let settlement = Digest32::blake3_hash(b"zk_settlement_tx");

        let epoch1 = genesis.transition_epoch(&weights, &settlement);
        assert_eq!(epoch1.epoch, 1);
        assert!(epoch1.verify_weights_inclusion(&genesis, &weights, &settlement));
    }
}
