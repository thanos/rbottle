use crate::errors::Result;
use rand::RngCore;

/// Trait for types that can sign data
pub trait Sign {
    /// Sign the given message
    fn sign(&self, rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for types that can verify signatures
pub trait Verify {
    /// Verify a signature against a message
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()>;
}

/// Generic sign function that works with any Signer
pub fn sign<R: RngCore, S: Sign>(
    rng: &mut R,
    signer: &S,
    message: &[u8],
) -> Result<Vec<u8>> {
    signer.sign(rng, message)
}

/// Generic verify function that works with any Verifier
pub fn verify<V: Verify>(verifier: &V, message: &[u8], signature: &[u8]) -> Result<()> {
    verifier.verify(message, signature)
}


