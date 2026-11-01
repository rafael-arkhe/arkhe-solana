mod consensus;

pub use consensus::HyperspaceNodeConsensus;
use arkhe_core::Digest32;

#[tokio::main]
async fn main() {
    println!("Starting Hyperspace Mysticeti Node on port 9000...");
    let node = HyperspaceNodeConsensus::new();
    let tx = Digest32::blake3_hash(b"test_payment_channel_open");
    let round = node.commit_payment_tx(tx);
    println!("Committed transaction in round {}", round);
}
