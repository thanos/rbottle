use crate::errors::Result;
use rand::RngCore;

/// Trait for types that can sign data.
///
/// This trait is implemented by all key types that support signing operations,
/// such as `Ed25519Key` and `EcdsaP256Key`. The `sign` method produces a
/// cryptographic signature of the message.
///
/// # Example
///
/// ```rust
/// use rbottle::signing::Sign;
/// use rbottle::keys::Ed25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = Ed25519Key::generate(rng);
/// let message = b"Test message";
///
/// let signature = key.sign(rng, message).unwrap();
/// ```
pub trait Sign {
    /// Sign the given message.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator (may be used for non-deterministic signing)
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Signature bytes
    /// * `Err(BottleError::VerifyFailed)` - If signing fails
    fn sign(&self, rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for types that can verify signatures.
///
/// This trait is implemented by all key types that support signature verification.
/// The `verify` method checks that a signature is valid for a given message.
///
/// # Example
///
/// ```rust
/// use rbottle::signing::{Sign, Verify};
/// use rbottle::keys::Ed25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = Ed25519Key::generate(rng);
/// let message = b"Test message";
///
/// let signature = key.sign(rng, message).unwrap();
/// assert!(key.verify(message, &signature).is_ok());
/// ```
pub trait Verify {
    /// Verify a signature against a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Signature is valid
    /// * `Err(BottleError::VerifyFailed)` - If signature verification fails
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()>;
}

/// Generic sign function that works with any signer.
///
/// This is a convenience function that calls the `sign` method on any type
/// implementing the `Sign` trait.
///
/// # Arguments
///
/// * `rng` - A random number generator
/// * `signer` - A signer implementing the `Sign` trait
/// * `message` - The message to sign
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Signature bytes
/// * `Err(BottleError::VerifyFailed)` - If signing fails
pub fn sign<R: RngCore, S: Sign>(
    rng: &mut R,
    signer: &S,
    message: &[u8],
) -> Result<Vec<u8>> {
    signer.sign(rng, message)
}

/// Generic verify function that works with any verifier.
///
/// This is a convenience function that calls the `verify` method on any type
/// implementing the `Verify` trait.
///
/// # Arguments
///
/// * `verifier` - A verifier implementing the `Verify` trait
/// * `message` - The original message
/// * `signature` - The signature to verify
///
/// # Returns
///
/// * `Ok(())` - Signature is valid
/// * `Err(BottleError::VerifyFailed)` - If signature verification fails
pub fn verify<V: Verify>(verifier: &V, message: &[u8], signature: &[u8]) -> Result<()> {
    verifier.verify(message, signature)
}


