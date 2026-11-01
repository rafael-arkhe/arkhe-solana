mod server;
mod storage;

pub use server::OmniNodeServer;
pub use storage::ChunkStorage;

#[tokio::main]
async fn main() {
    println!("Starting OmniNode Storage Node on port 4001...");
    let server = OmniNodeServer::new();
    let sample = b"model_chunk_payload_layer_0";
    let cid = server.handle_chunk_upload(sample.to_vec());
    println!("Stored sample chunk with CIDv1: {}", cid.0);
}
