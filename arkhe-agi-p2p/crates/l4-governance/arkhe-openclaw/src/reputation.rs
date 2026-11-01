//! Agent reputation and peer scoring.

use std::collections::HashMap;

#[derive(Default, Clone, Debug)]
pub struct ReputationTracker {
    scores: HashMap<String, i64>,
}

impl ReputationTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_honest_inference(&mut self, agent_id: &str) {
        let entry = self.scores.entry(agent_id.to_string()).or_insert(100);
        *entry += 10;
    }

    pub fn slash_byzantine_fault(&mut self, agent_id: &str) {
        let entry = self.scores.entry(agent_id.to_string()).or_insert(100);
        *entry -= 50;
    }

    pub fn get_score(&self, agent_id: &str) -> i64 {
        *self.scores.get(agent_id).unwrap_or(&100)
    }

    pub fn is_trusted(&self, agent_id: &str) -> bool {
        self.get_score(agent_id) >= 80
    }
}
