//! Streaming payment channels for per-token / per-chunk inference settlement.

use arkhe_core::Digest32;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentChannel {
    pub channel_id: Digest32,
    pub sender: String,
    pub recipient: String,
    pub balance: u64,
    pub settled_amount: u64,
}

impl PaymentChannel {
    pub fn open(sender: String, recipient: String, initial_deposit: u64) -> Self {
        let id = Digest32::blake3_with_domain(
            b"HYPERSPACE:PAYMENT:CHANNEL\0",
            format!("{}:{}:{}", sender, recipient, initial_deposit).as_bytes(),
        );
        Self {
            channel_id: id,
            sender,
            recipient,
            balance: initial_deposit,
            settled_amount: 0,
        }
    }

    pub fn micro_settle(&mut self, amount: u64) -> Result<(), String> {
        if self.balance < amount {
            return Err("Insufficient channel balance".into());
        }
        self.balance -= amount;
        self.settled_amount += amount;
        Ok(())
    }
}
