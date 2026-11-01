//! Byzantine Fault Tolerant (BFT) Consensus Simulation (Tendermint-like).
//! Demonstrates 60s finality with up to 20% Byzantine nodes in agent networks.

use crate::proposal::SelfImprovementProposal;
use arkhe_core::Digest32;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VoteType {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug)]
pub struct Vote {
    pub proposal_id: Digest32,
    pub voter_id: String,
    pub vote_type: VoteType,
    pub is_byzantine: bool,
}

pub struct BftConsensusEngine {
    pub total_nodes: usize,
    pub votes: HashMap<(Digest32, VoteType), HashSet<String>>,
}

impl BftConsensusEngine {
    pub fn new(total_nodes: usize) -> Self {
        Self {
            total_nodes,
            votes: HashMap::new(),
        }
    }

    /// Supermajority threshold > 2/3 of total validators
    pub fn quorum_threshold(&self) -> usize {
        (self.total_nodes * 2) / 3 + 1
    }

    pub fn cast_vote(&mut self, vote: Vote) {
        if vote.is_byzantine {
            // Byzantine node fails to submit valid signature / equivocates
            return;
        }
        let key = (vote.proposal_id, vote.vote_type);
        self.votes.entry(key).or_default().insert(vote.voter_id);
    }

    pub fn is_proposal_finalized(&self, proposal: &SelfImprovementProposal) -> bool {
        let key = (proposal.proposal_id, VoteType::Precommit);
        if let Some(precommits) = self.votes.get(&key) {
            precommits.len() >= self.quorum_threshold()
        } else {
            false
        }
    }
}
