use crate::action_proof::Digest;

#[derive(Debug, Clone, PartialEq)]
pub struct WorkerExecutionRecord {
    pub collateral_hash: Digest,
    pub execution_time: u64,
}

pub struct TemporalSealer;

#[derive(Debug, PartialEq)]
pub enum AnchorError {
    InvalidCollateralHash,
}

impl TemporalSealer {
    pub fn anchor_record(record: &WorkerExecutionRecord) -> Result<Digest, AnchorError> {
        if record.collateral_hash.0.is_empty() {
            return Err(AnchorError::InvalidCollateralHash);
        }

        // Mock anchoring logic returning a dummy receipt hash
        Ok(Digest(vec![0xAA, 0xBB, 0xCC]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_anchor() {
        let record = WorkerExecutionRecord {
            collateral_hash: Digest(vec![1, 2, 3]),
            execution_time: 123456789,
        };

        assert!(TemporalSealer::anchor_record(&record).is_ok());
    }

    #[test]
    fn falsifier_invalid_collateral_hash() {
        let record = WorkerExecutionRecord {
            collateral_hash: Digest(vec![]),
            execution_time: 123456789,
        };

        assert_eq!(
            TemporalSealer::anchor_record(&record),
            Err(AnchorError::InvalidCollateralHash)
        );
    }
}
