pub mod consensus;
pub mod payment;

pub use consensus::{DagBlock, MysticetiDagReader};
pub use payment::PaymentChannel;

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_core::Digest32;

    #[test]
    fn test_payment_and_dag() {
        let mut ch = PaymentChannel::open("agent_a".into(), "agent_b".into(), 1000);
        assert!(ch.micro_settle(250).is_ok());
        assert_eq!(ch.balance, 750);
        assert_eq!(ch.settled_amount, 250);

        let mut reader = MysticetiDagReader::new();
        let tx = Digest32::blake3_hash(b"tx_settle_250");
        reader.append_committed_block(DagBlock {
            round: 1,
            author: "validator_0".into(),
            parents: vec![],
            transactions: vec![tx],
            block_digest: Digest32::blake3_hash(b"block_1"),
        });

        assert_eq!(reader.latest_round(), 1);
        assert!(reader.is_transaction_committed(&tx));
    }
}
