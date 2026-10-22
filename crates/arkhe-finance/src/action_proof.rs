#[derive(Debug, Clone, PartialEq)]
pub struct OperationId(pub String);

#[derive(Debug, Clone, PartialEq)]
pub struct Digest(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub struct Signature(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub struct MmrProof {
    pub is_valid: bool,
    pub anchored_before_execution: bool,
}

#[derive(Debug, Clone)]
pub struct Mandate {
    pub operation_id: OperationId,
    pub scope: Digest,
    pub signature: Signature,
    pub principal: String,
}

impl Mandate {
    pub fn is_signed_by_principal(&self) -> bool {
        !self.signature.0.is_empty() && self.principal == "authorized_principal"
    }

    pub fn contains_scope(&self, parameters_digest: &Digest) -> bool {
        &self.scope == parameters_digest
    }
}

#[derive(Debug, Clone)]
pub struct Execution {
    pub operation_id: OperationId,
    pub parameters_digest: Digest,
}

pub struct ActionProof {
    pub mandate: Mandate,
    pub execution: Execution,
    pub mmr_proof: MmrProof,
}

#[derive(Debug, PartialEq)]
pub enum ActionProofError {
    InvalidSignature,
    OperationIdMismatch,
    ScopeNotContained,
    InvalidMmrProof,
}

impl ActionProof {
    pub fn verify(&self) -> Result<(), ActionProofError> {
        if !self.mandate.is_signed_by_principal() {
            return Err(ActionProofError::InvalidSignature);
        }

        if self.mandate.operation_id != self.execution.operation_id {
            return Err(ActionProofError::OperationIdMismatch);
        }

        if !self.mandate.contains_scope(&self.execution.parameters_digest) {
            return Err(ActionProofError::ScopeNotContained);
        }

        if !self.mmr_proof.is_valid || !self.mmr_proof.anchored_before_execution {
            return Err(ActionProofError::InvalidMmrProof);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_mandate() -> Mandate {
        Mandate {
            operation_id: OperationId("op-123".to_string()),
            scope: Digest(vec![1, 2, 3]),
            signature: Signature(vec![255]),
            principal: "authorized_principal".to_string(),
        }
    }

    fn valid_execution() -> Execution {
        Execution {
            operation_id: OperationId("op-123".to_string()),
            parameters_digest: Digest(vec![1, 2, 3]),
        }
    }

    fn valid_mmr_proof() -> MmrProof {
        MmrProof {
            is_valid: true,
            anchored_before_execution: true,
        }
    }

    #[test]
    fn test_valid_action_proof() {
        let proof = ActionProof {
            mandate: valid_mandate(),
            execution: valid_execution(),
            mmr_proof: valid_mmr_proof(),
        };
        assert_eq!(proof.verify(), Ok(()));
    }

    #[test]
    fn falsifier_invalid_signature() {
        let mut proof = ActionProof {
            mandate: valid_mandate(),
            execution: valid_execution(),
            mmr_proof: valid_mmr_proof(),
        };
        proof.mandate.signature = Signature(vec![]);
        assert_eq!(proof.verify(), Err(ActionProofError::InvalidSignature));
    }

    #[test]
    fn falsifier_operation_id_mismatch() {
        let mut proof = ActionProof {
            mandate: valid_mandate(),
            execution: valid_execution(),
            mmr_proof: valid_mmr_proof(),
        };
        proof.execution.operation_id = OperationId("op-456".to_string());
        assert_eq!(proof.verify(), Err(ActionProofError::OperationIdMismatch));
    }

    #[test]
    fn falsifier_scope_not_contained() {
        let mut proof = ActionProof {
            mandate: valid_mandate(),
            execution: valid_execution(),
            mmr_proof: valid_mmr_proof(),
        };
        proof.execution.parameters_digest = Digest(vec![9, 9, 9]);
        assert_eq!(proof.verify(), Err(ActionProofError::ScopeNotContained));
    }

    #[test]
    fn falsifier_invalid_mmr_proof() {
        let mut proof = ActionProof {
            mandate: valid_mandate(),
            execution: valid_execution(),
            mmr_proof: valid_mmr_proof(),
        };
        proof.mmr_proof.is_valid = false;
        assert_eq!(proof.verify(), Err(ActionProofError::InvalidMmrProof));

        proof.mmr_proof.is_valid = true;
        proof.mmr_proof.anchored_before_execution = false;
        assert_eq!(proof.verify(), Err(ActionProofError::InvalidMmrProof));
    }
}
