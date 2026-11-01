pub mod checkpoint;
pub mod mmr;
pub mod strongbox;

pub use checkpoint::SignedCheckpoint;
pub use mmr::LocalMmr;
pub use strongbox::{HardwareStrongBox, StrongBoxStorage};

#[cfg(test)]
mod tests {
    use super::*;
    use arkhe_core::Digest32;
    use rand::rngs::OsRng;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_mmr_append_and_bagging() {
        let mut mmr = LocalMmr::new();
        for i in 0..5 {
            let data = format!("event_{}", i);
            let d = Digest32::blake3_hash(data.as_bytes());
            mmr.append(d);
        }

        let peaks = mmr.get_peaks();
        assert!(!peaks.is_empty());

        let root = mmr.bag_peaks();
        assert_ne!(root, Digest32::ZERO);

        let proof = mmr.get_inclusion_proof(2);
        assert!(proof.is_some());
    }

    #[test]
    fn test_signed_checkpoint() {
        let mut mmr = LocalMmr::new();
        mmr.append(Digest32::blake3_hash(b"inference_1"));
        mmr.append(Digest32::blake3_hash(b"inference_2"));

        let strongbox = HardwareStrongBox::init_isolated(b"test-strongbox-seed");
        let mut rng = OsRng;
        let ed_key = SigningKey::generate(&mut rng);

        let attestation_hash = Digest32::blake3_hash(b"device_quote");
        let cp = SignedCheckpoint::create(
            &mmr,
            attestation_hash,
            1712000100,
            &strongbox,
            &ed_key,
        ).unwrap();

        assert!(cp.verify().is_ok());

        let mut tampered = cp.clone();
        tampered.mmr_root = Digest32::blake3_hash(b"tampered");
        assert!(tampered.verify().is_err());
    }
}
