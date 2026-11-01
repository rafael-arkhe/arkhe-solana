//! Semantic inference router connecting L2 provenance to L3 evidence anchoring.

use arkhe_afir::AfirReceipt;
use arkhe_core::Digest32;
use arkhe_spice::InferenceChain;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProvenanceMode {
    AfirDefault,
    ZkmlHighAssurance,
    TeeAccelerated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutedInferenceResult {
    pub mode: ProvenanceMode,
    pub inference_root: Digest32,
    pub receipt: Option<AfirReceipt>,
}

pub struct InferenceRouter;

impl InferenceRouter {
    pub fn route_afir_inference(
        chain: &InferenceChain,
        receipt: AfirReceipt,
    ) -> RoutedInferenceResult {
        let root = chain.compute_inference_root();
        RoutedInferenceResult {
            mode: ProvenanceMode::AfirDefault,
            inference_root: root,
            receipt: Some(receipt),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_afir::AfirSigner;
    use arkhe_crypto::MlDsa65Keypair;
    use arkhe_spice::InferenceHopEntry;

    #[test]
    fn test_router() {
        let mut chain = InferenceChain::new();
        let hop = InferenceHopEntry::new(
            0,
            "mod1".into(),
            Digest32::ZERO,
            Digest32::ZERO,
            Digest32::ZERO,
        );
        chain.append_hop(hop);

        let kp = MlDsa65Keypair::generate_deterministic(b"seed");
        let signer = AfirSigner::new(&kp);
        let receipt = signer.issue_receipt(
            Digest32::ZERO,
            0,
            Digest32::ZERO,
            Digest32::ZERO,
            "cid".into(),
            0,
        );

        let res = InferenceRouter::route_afir_inference(&chain, receipt);
        assert_ne!(res.inference_root, Digest32::ZERO);
    }
}
