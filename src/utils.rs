use crate::errors::{BottleError, Result};
use crate::ecdh::rsa_encrypt;
use rand::{CryptoRng, RngCore};
use rsa::RsaPublicKey;
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
/// use rust_bottle::utils::mem_clr;
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
/// This function encrypts small buffers (typically 32 bytes or less, like AES keys)
/// directly to a public key without using ECDH key exchange. This is useful for
/// key wrapping scenarios.
///
/// Currently supports RSA keys only. For RSA, the plaintext must be smaller than
/// the key size minus 42 bytes (for OAEP with SHA-256 padding).
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `plaintext` - The plaintext to encrypt (should be short, e.g., 32 bytes for AES-256 keys)
/// * `public_key` - The recipient's public key (PKIX DER format or raw RSA public key bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted ciphertext
/// * `Err(BottleError::UnsupportedAlgorithm)` - If the key type is not supported
/// * `Err(BottleError::Encryption)` - If encryption fails
///
/// # Example
///
/// ```rust,no_run
/// use rust_bottle::utils::encrypt_short_buffer;
/// use rust_bottle::keys::RsaKey;
/// use rust_bottle::ecdh::rsa_encrypt;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let rsa_key = RsaKey::generate(rng, 2048).unwrap();
///
/// // Encrypt a 32-byte AES key
/// // Note: For now, use rsa_encrypt directly with RsaPublicKey
/// // PKIX parsing for RSA is not yet fully implemented
/// let aes_key = vec![0u8; 32];
/// let ciphertext = rsa_encrypt(rng, &aes_key, rsa_key.public_key()).unwrap();
/// ```
pub fn encrypt_short_buffer<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>> {
    // Try to parse as PKIX (SubjectPublicKeyInfo) format
    // Check if it looks like PKIX format (starts with DER SEQUENCE tag 0x30)
    if public_key.len() > 0 && public_key[0] == 0x30 {
        // Try to parse as PKIX and extract RSA public key
        if let Ok(rsa_pub_key) = parse_rsa_public_key_from_pkix(public_key) {
            return rsa_encrypt(rng, plaintext, &rsa_pub_key);
        }
    }
    
    // Note: PKCS#1 parsing is not yet fully implemented
    // For now, users should use rsa_encrypt directly with an RsaPublicKey reference,
    // or provide keys in PKIX format
    
    // If we can't parse as RSA, return unsupported
    Err(BottleError::UnsupportedAlgorithm)
}

/// Parse RSA public key from PKIX (SubjectPublicKeyInfo) format.
fn parse_rsa_public_key_from_pkix(der_bytes: &[u8]) -> Result<RsaPublicKey> {
    use der::asn1::BitString;
    use der::asn1::AnyRef;
    use der::Decode;
    use spki::SubjectPublicKeyInfo;
    use const_oid::db::rfc5912;
    
    let spki: SubjectPublicKeyInfo<AnyRef, BitString> = SubjectPublicKeyInfo::from_der(der_bytes)
        .map_err(|_| BottleError::InvalidKeyType)?;
    
    // Check if it's an RSA key (OID 1.2.840.113549.1.1.1)
    if spki.algorithm.oid != rfc5912::RSA_ENCRYPTION {
        return Err(BottleError::InvalidKeyType);
    }
    
    // Extract the RSA public key bytes (RSAPublicKey structure)
    let rsa_key_bytes = spki.subject_public_key.raw_bytes();
    
    // Parse RSAPublicKey structure (SEQUENCE { n INTEGER, e INTEGER })
    parse_rsa_public_key_pkcs1(rsa_key_bytes)
}

/// Parse RSA public key from PKCS#1 format (RSAPublicKey structure).
///
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
///
/// This function manually parses the DER-encoded sequence to extract
/// the modulus (n) and public exponent (e).
fn parse_rsa_public_key_pkcs1(der_bytes: &[u8]) -> Result<RsaPublicKey> {
    use der::Decode;
    use rsa::BigUint;
    
    // Manual DER parsing of SEQUENCE { INTEGER, INTEGER }
    // DER format: [0x30 (SEQUENCE tag)] [length] [INTEGER n] [INTEGER e]
    
    if der_bytes.is_empty() || der_bytes[0] != 0x30 {
        return Err(BottleError::InvalidKeyType);
    }
    
    // Skip SEQUENCE tag (0x30) and length byte(s)
    let mut pos = 1;
    if pos >= der_bytes.len() {
        return Err(BottleError::InvalidKeyType);
    }
    
    // Parse length (can be short form or long form)
    let seq_len = if (der_bytes[pos] & 0x80) == 0 {
        // Short form: length is in the byte itself
        let len = der_bytes[pos] as usize;
        pos += 1;
        len
    } else {
        // Long form: length is encoded in multiple bytes
        let len_bytes = (der_bytes[pos] & 0x7f) as usize;
        if len_bytes == 0 || len_bytes > 4 || pos + len_bytes >= der_bytes.len() {
            return Err(BottleError::InvalidKeyType);
        }
        pos += 1;
        let mut len = 0usize;
        for i in 0..len_bytes {
            len = (len << 8) | (der_bytes[pos + i] as usize);
        }
        pos += len_bytes;
        len
    };
    
    if pos + seq_len > der_bytes.len() {
        return Err(BottleError::InvalidKeyType);
    }
    
    // Now parse the two INTEGERs from the sequence content
    let seq_content = &der_bytes[pos..pos + seq_len];
    
    // Parse first INTEGER (modulus n)
    let n_uint = der::asn1::Uint::from_der(seq_content)
        .map_err(|_| BottleError::InvalidKeyType)?;
    
    // Calculate offset for second integer
    // INTEGER tag (0x02) + length + value
    let n_len = if seq_content.is_empty() || seq_content[0] != 0x02 {
        return Err(BottleError::InvalidKeyType);
    } else {
        let mut n_pos = 1;
        if n_pos >= seq_content.len() {
            return Err(BottleError::InvalidKeyType);
        }
        let n_val_len = if (seq_content[n_pos] & 0x80) == 0 {
            let len = seq_content[n_pos] as usize;
            n_pos += 1;
            len
        } else {
            let len_bytes = (seq_content[n_pos] & 0x7f) as usize;
            if len_bytes == 0 || len_bytes > 4 || n_pos + len_bytes >= seq_content.len() {
                return Err(BottleError::InvalidKeyType);
            }
            n_pos += 1;
            let mut len = 0usize;
            for i in 0..len_bytes {
                len = (len << 8) | (seq_content[n_pos + i] as usize);
            }
            n_pos += len_bytes;
            len
        };
        n_pos + n_val_len
    };
    
    if n_len >= seq_content.len() {
        return Err(BottleError::InvalidKeyType);
    }
    
    // Parse second INTEGER (exponent e)
    let e_uint = der::asn1::Uint::from_der(&seq_content[n_len..])
        .map_err(|_| BottleError::InvalidKeyType)?;
    
    // Convert to BigUint
    let n = BigUint::from_bytes_be(n_uint.as_bytes());
    let e = BigUint::from_bytes_be(e_uint.as_bytes());
    
    // Create RsaPublicKey
    RsaPublicKey::new(n, e)
        .map_err(|_| BottleError::InvalidKeyType)
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


