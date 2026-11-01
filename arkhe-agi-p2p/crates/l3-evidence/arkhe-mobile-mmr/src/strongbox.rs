//! Sealed StrongBox keystore abstraction.
//! Represents the hardware-isolated cryptographic boundary for key management and signing.

use arkhe_crypto::{CryptoError, MlDsa65Keypair, MlDsa65PublicKey, MlDsa65Signature};

pub trait StrongBoxStorage {
    fn sign_checkpoint(&self, checkpoint_digest: &[u8]) -> Result<MlDsa65Signature, CryptoError>;
    fn get_public_key(&self) -> MlDsa65PublicKey;
}

pub struct HardwareStrongBox {
    keypair: MlDsa65Keypair,
}

impl HardwareStrongBox {
    pub fn init_isolated(seed: &[u8]) -> Self {
        Self {
            keypair: MlDsa65Keypair::generate_deterministic(seed),
        }
    }
}

impl StrongBoxStorage for HardwareStrongBox {
    fn sign_checkpoint(&self, checkpoint_digest: &[u8]) -> Result<MlDsa65Signature, CryptoError> {
        Ok(self.keypair.sign(checkpoint_digest))
    }

    fn get_public_key(&self) -> MlDsa65PublicKey {
        self.keypair.public_key.clone()
    }
}
