use crate::action_proof::{Digest, OperationId};

#[derive(Debug, Clone, PartialEq)]
pub struct ProofCarryingOutput {
    pub zk_solvency_proof: Vec<u8>,
    pub operation_id: OperationId,
    pub parameters_digest: Digest,
}

#[derive(Debug, PartialEq)]
pub enum ProofError {
    InvalidLinkage,
}

impl ProofCarryingOutput {
    pub fn verify_linkage(&self, expected_operation_id: &OperationId, expected_parameters_digest: &Digest) -> Result<(), ProofError> {
        if self.zk_solvency_proof.is_empty() {
            return Err(ProofError::InvalidLinkage);
        }

        if &self.operation_id != expected_operation_id {
            return Err(ProofError::InvalidLinkage);
        }

        if &self.parameters_digest != expected_parameters_digest {
            return Err(ProofError::InvalidLinkage);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_linkage() {
        let pco = ProofCarryingOutput {
            zk_solvency_proof: vec![1, 2, 3],
            operation_id: OperationId("op-xyz".to_string()),
            parameters_digest: Digest(vec![0xAA, 0xBB]),
        };

        assert_eq!(
            pco.verify_linkage(&OperationId("op-xyz".to_string()), &Digest(vec![0xAA, 0xBB])),
            Ok(())
        );
    }

    #[test]
    fn falsifier_missing_zk_proof() {
        let pco = ProofCarryingOutput {
            zk_solvency_proof: vec![],
            operation_id: OperationId("op-xyz".to_string()),
            parameters_digest: Digest(vec![0xAA, 0xBB]),
        };

        assert_eq!(
            pco.verify_linkage(&OperationId("op-xyz".to_string()), &Digest(vec![0xAA, 0xBB])),
            Err(ProofError::InvalidLinkage)
        );
    }

    #[test]
    fn falsifier_invalid_operation_id() {
        let pco = ProofCarryingOutput {
            zk_solvency_proof: vec![1, 2, 3],
            operation_id: OperationId("op-xyz".to_string()),
            parameters_digest: Digest(vec![0xAA, 0xBB]),
        };

        assert_eq!(
            pco.verify_linkage(&OperationId("op-abc".to_string()), &Digest(vec![0xAA, 0xBB])),
            Err(ProofError::InvalidLinkage)
        );
    }

    #[test]
    fn falsifier_invalid_parameters_digest() {
        let pco = ProofCarryingOutput {
            zk_solvency_proof: vec![1, 2, 3],
            operation_id: OperationId("op-xyz".to_string()),
            parameters_digest: Digest(vec![0xAA, 0xBB]),
        };

        assert_eq!(
            pco.verify_linkage(&OperationId("op-xyz".to_string()), &Digest(vec![0xCC, 0xDD])),
            Err(ProofError::InvalidLinkage)
        );
    }
}
