use crate::errors::{BottleError, Result};
use zeroize::Zeroize;

/// Securely clear sensitive data from memory.
///
/// This function uses the `zeroize` crate to overwrite memory with zeros,
/// helping to prevent sensitive data from remaining in memory after use.
/// This is important for cryptographic keys and other sensitive material.
///
/// # Arguments
///
/// * `data` - Mutable slice of bytes to clear
///
/// # Example
///
/// ```rust
/// use rbottle::utils::mem_clr;
///
/// let mut sensitive = vec![1, 2, 3, 4, 5];
/// mem_clr(&mut sensitive);
/// // sensitive is now all zeros
/// ```
pub fn mem_clr(data: &mut [u8]) {
    data.zeroize();
}

/// Encrypt a short buffer (like AES keys) to a public key.
///
/// # Note
///
/// This is a placeholder function. It will be implemented in a future release
/// to support encrypting small buffers (typically 32 bytes or less) directly
/// to public keys without using ECDH key exchange.
///
/// # Arguments
///
/// * `_rng` - A random number generator
/// * `_plaintext` - The plaintext to encrypt (should be short, e.g., 32 bytes)
/// * `_public_key` - The recipient's public key
///
/// # Returns
///
/// * `Err(BottleError::UnsupportedAlgorithm)` - Currently not implemented
///
/// # Future Implementation
///
/// This will support RSA encryption for short buffers when RSA support is added.
pub fn encrypt_short_buffer<R: rand::RngCore>(
    _rng: &mut R,
    _plaintext: &[u8],
    _public_key: &[u8],
) -> Result<Vec<u8>> {
    // This will be implemented based on the key type
    // For now, placeholder
    Err(BottleError::UnsupportedAlgorithm)
}

/// Decrypt a short buffer using a private key.
///
/// # Note
///
/// This is a placeholder function. It will be implemented in a future release
/// to support decrypting small buffers encrypted with `encrypt_short_buffer`.
///
/// # Arguments
///
/// * `_ciphertext` - The encrypted data
/// * `_private_key` - The recipient's private key
///
/// # Returns
///
/// * `Err(BottleError::UnsupportedAlgorithm)` - Currently not implemented
///
/// # Future Implementation
///
/// This will support RSA decryption for short buffers when RSA support is added.
pub fn decrypt_short_buffer(_ciphertext: &[u8], _private_key: &[u8]) -> Result<Vec<u8>> {
    // This will be implemented based on the key type
    // For now, placeholder
    Err(BottleError::UnsupportedAlgorithm)
}


