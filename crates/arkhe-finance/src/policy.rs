#[derive(Debug, Clone, PartialEq)]
pub struct PolicyBinding {
    pub policy_id: String,
    pub compliance_proof: Option<Vec<u8>>,
}

pub struct ContainmentGate;

#[derive(Debug, PartialEq)]
pub enum ContainmentError {
    ComplianceProofAbsent,
}

impl ContainmentGate {
    pub fn execute(binding: &PolicyBinding) -> Result<(), ContainmentError> {
        if binding.compliance_proof.is_none() || binding.compliance_proof.as_ref().unwrap().is_empty() {
            return Err(ContainmentError::ComplianceProofAbsent);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_execution() {
        let binding = PolicyBinding {
            policy_id: "policy-abc".to_string(),
            compliance_proof: Some(vec![0x1, 0x2, 0x3]),
        };
        assert_eq!(ContainmentGate::execute(&binding), Ok(()));
    }

    #[test]
    fn falsifier_compliance_proof_absent() {
        let mut binding = PolicyBinding {
            policy_id: "policy-abc".to_string(),
            compliance_proof: None,
        };
        assert_eq!(ContainmentGate::execute(&binding), Err(ContainmentError::ComplianceProofAbsent));

        binding.compliance_proof = Some(vec![]);
        assert_eq!(ContainmentGate::execute(&binding), Err(ContainmentError::ComplianceProofAbsent));
    }
}
