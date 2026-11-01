pub mod bft;
pub mod proposal;
pub mod reputation;

pub use bft::{BftConsensusEngine, Vote, VoteType};
pub use proposal::SelfImprovementProposal;
pub use reputation::ReputationTracker;

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_core::Digest32;

    #[test]
    fn test_bft_simulation_with_byzantine_faults() {
        let total_nodes = 20;
        let mut engine = BftConsensusEngine::new(total_nodes);
        assert_eq!(engine.quorum_threshold(), 14); // 20 * 2 / 3 + 1 = 14

        let proposal = SelfImprovementProposal::new(
            "agent_0".into(),
            "Optimize attention cache".into(),
            "transformer_kv_cache".into(),
            Digest32::blake3_hash(b"diff_bytes"),
            "latency_p99 < 15ms".into(),
            1712000000,
        );

        // 20% Byzantine nodes (4 out of 20)
        let byzantine_count = 4;
        let honest_count = total_nodes - byzantine_count; // 16 honest nodes

        for i in 0..total_nodes {
            let is_byzantine = i >= honest_count;
            engine.cast_vote(Vote {
                proposal_id: proposal.proposal_id,
                voter_id: format!("node_{}", i),
                vote_type: VoteType::Precommit,
                is_byzantine,
            });
        }

        // Even with 4 Byzantine nodes dropping/corrupting votes, 16 honest nodes finalize the proposal (threshold = 14)
        assert!(engine.is_proposal_finalized(&proposal));
    }
}
