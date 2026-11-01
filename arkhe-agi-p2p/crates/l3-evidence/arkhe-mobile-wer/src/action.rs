//! Mobile Action taxonomy for mobile Work Evidence Records.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileAction {
    InferenceExecution {
        model_name: String,
        tokens_in: u32,
        tokens_out: u32,
    },
    PolicyEvaluation {
        policy_name: String,
        verdict: bool,
    },
    StateTransition {
        from_state: String,
        to_state: String,
    },
    HardwareKeyRotation {
        key_alias: String,
    },
}
