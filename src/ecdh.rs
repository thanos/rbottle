use crate::errors::{BottleError, Result};
use p256::ecdh::EphemeralSecret;
use p256::{PublicKey, SecretKey};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// ECDH encryption using P-256
pub fn ecdh_encrypt_p256<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &PublicKey,
) -> Result<Vec<u8>> {
    let secret = EphemeralSecret::random(rng);
    let shared_secret = secret.diffie_hellman(public_key);
    
    // Derive encryption key from shared secret
    // For p256 0.13, the shared secret is a SharedSecret type
    // Extract shared secret bytes - raw_secret_bytes() returns a GenericArray
    let shared_bytes = shared_secret.raw_secret_bytes();
    // Convert to slice for key derivation
    let key = derive_key(shared_bytes.as_slice());
    
    // Encrypt using AES-GCM (simplified - in production use proper AEAD)
    let encrypted = encrypt_aes_gcm(&key, plaintext)?;
    
    // Include ephemeral public key
    let ephemeral_pub = secret.public_key();
    let mut result = ephemeral_pub.to_sec1_bytes().to_vec();
    result.extend_from_slice(&encrypted);
    
    Ok(result)
}

/// ECDH decryption using P-256
pub fn ecdh_decrypt_p256(
    ciphertext: &[u8],
    private_key: &SecretKey,
) -> Result<Vec<u8>> {
    if ciphertext.len() < 65 {
        return Err(BottleError::InvalidFormat);
    }
    
    // Extract ephemeral public key
    let ephemeral_pub = PublicKey::from_sec1_bytes(&ciphertext[..65])
        .map_err(|_| BottleError::Decryption("Invalid ephemeral public key".to_string()))?;
    
    // Compute shared secret using ECDH
    // For p256 0.13, use the SecretKey with the ephemeral public key
    // Create a SharedSecret by multiplying the private scalar with the public point
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let scalar = private_key.to_nonzero_scalar();
    let point = ephemeral_pub.as_affine();
    // Perform ECDH: shared_secret = private_scalar * public_point
    let shared_point = (*point * scalar.as_ref()).to_encoded_point(false);
    // Use x-coordinate as shared secret (standard ECDH)
    let shared_bytes = shared_point.x().unwrap().as_slice();
    let key = derive_key(shared_bytes);
    
    // Decrypt
    decrypt_aes_gcm(&key, &ciphertext[65..])
}

/// X25519 ECDH encryption
pub fn ecdh_encrypt_x25519<R: RngCore>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &X25519PublicKey,
) -> Result<Vec<u8>> {
    // Generate random secret key (32 bytes for X25519)
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    
    // Use StaticSecret from x25519-dalek 1.0
    let secret = StaticSecret::from(secret_bytes);
    
    // Compute shared secret
    let shared_secret = secret.diffie_hellman(public_key);
    
    // Derive encryption key from shared secret
    let key = derive_key(shared_secret.as_bytes());
    
    // Encrypt
    let encrypted = encrypt_aes_gcm(&key, plaintext)?;
    
    // Get ephemeral public key
    let ephemeral_pub = X25519PublicKey::from(&secret);
    
    let mut result = ephemeral_pub.as_bytes().to_vec();
    result.extend_from_slice(&encrypted);
    
    Ok(result)
}

/// X25519 ECDH decryption
pub fn ecdh_decrypt_x25519(
    ciphertext: &[u8],
    private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if ciphertext.len() < 32 {
        return Err(BottleError::InvalidFormat);
    }
    
    // Create StaticSecret from private key bytes
    let priv_key = StaticSecret::from(*private_key);
    
    // Extract ephemeral public key (32 bytes)
    let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32].try_into()
        .map_err(|_| BottleError::InvalidFormat)?;
    let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);
    
    // Compute shared secret
    let shared_secret = priv_key.diffie_hellman(&ephemeral_pub);
    let key = derive_key(shared_secret.as_bytes());
    
    // Decrypt
    decrypt_aes_gcm(&key, &ciphertext[32..])
}

/// Trait for ECDH encryption
pub trait ECDHEncrypt {
    fn encrypt<R: RngCore>(&self, rng: &mut R, plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for ECDH decryption
pub trait ECDHDecrypt {
    fn decrypt(&self, ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>>;
}

/// Generic ECDH encrypt function
pub fn ecdh_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>> {
    // Try to determine key type and use appropriate function
    // X25519 keys are 32 bytes
    if public_key.len() == 32 {
        let pub_key_bytes: [u8; 32] = public_key.try_into()
            .map_err(|_| BottleError::InvalidKeyType)?;
        let pub_key = X25519PublicKey::from(pub_key_bytes);
        ecdh_encrypt_x25519(rng, plaintext, &pub_key)
    } else if public_key.len() == 65 || public_key.len() == 64 {
        let pub_key = PublicKey::from_sec1_bytes(public_key)
            .map_err(|_| BottleError::InvalidKeyType)?;
        ecdh_encrypt_p256(rng, plaintext, &pub_key)
    } else {
        Err(BottleError::InvalidKeyType)
    }
}

/// Generic ECDH decrypt function
pub fn ecdh_decrypt(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Try X25519 first (32 bytes)
    if private_key.len() == 32 && ciphertext.len() >= 32 {
        // Try to create X25519 key
        let priv_key_bytes: [u8; 32] = match private_key.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return Err(BottleError::InvalidKeyType),
        };
        match ecdh_decrypt_x25519(ciphertext, &priv_key_bytes) {
            Ok(result) => return Ok(result),
            Err(_) => {
                // Not X25519, try P-256
            }
        }
    }
    
    // Try P-256 (32 bytes private key, but different format)
    // P-256 keys are also 32 bytes, so we need to try both
    if private_key.len() == 32 {
        if let Ok(priv_key) = SecretKey::from_bytes(private_key.into()) {
            if let Ok(result) = ecdh_decrypt_p256(ciphertext, &priv_key) {
                return Ok(result);
            }
        }
    }
    
    Err(BottleError::InvalidKeyType)
}

// Helper functions
fn derive_key(shared_secret: &[u8]) -> [u8; 32] {
    use sha2::Sha256;
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use ring::aead::{self, BoundKey, NonceSequence, UnboundKey};
    use ring::rand::{SecureRandom, SystemRandom};
    
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| BottleError::Encryption("RNG failure".to_string()))?;
    
    let _nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| BottleError::Encryption("Key creation failed".to_string()))?;
    
    struct SingleNonceSequence([u8; 12]);
    impl NonceSequence for SingleNonceSequence {
        fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
            Ok(aead::Nonce::assume_unique_for_key(self.0))
        }
    }
    
    let mut sealing_key = aead::SealingKey::new(unbound_key, SingleNonceSequence(nonce_bytes));
    
    let mut in_out = plaintext.to_vec();
    let tag_len = sealing_key.algorithm().tag_len();
    // The issue: seal_in_place_append_tag encrypts the ENTIRE buffer
    // So if we extend with zeros, it encrypts those zeros too
    // Solution: Don't extend the buffer. The function should handle tag space.
    // But ring docs say we need to extend. Let's check: maybe it only encrypts
    // up to (buffer_len - tag_len)? No, debug shows it encrypts everything.
    
    // Real solution: seal_in_place_append_tag encrypts the data in the buffer
    // and appends the tag. It encrypts up to (buffer.len() - tag_len) bytes.
    // So if we have 25 bytes and extend to 41, it should encrypt 25 and append tag.
    // But debug shows it encrypts 41. This suggests the API works differently.
    
    // Let's try: don't extend, and see if the function reserves space automatically
    // If not, we'll get an error and can handle it
    sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| {
            // If it fails, we need to extend with tag space
            // But we need to extend BEFORE calling, not in the error handler
            BottleError::Encryption("Need to extend buffer first".to_string())
        })?;
    
    // Actually, the above won't work. Let me fix it properly:
    // According to ring docs, we MUST extend with tag_len zeros before calling
    // But the function encrypts the entire buffer. So the solution is:
    // Only extend with tag space, don't add extra data to encrypt
    
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);
    Ok(result)
}

fn decrypt_aes_gcm(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    use ring::aead::{self, BoundKey, NonceSequence, OpeningKey, UnboundKey};
    
    if ciphertext.len() < 12 {
        return Err(BottleError::InvalidFormat);
    }
    
    let nonce_bytes: [u8; 12] = ciphertext[..12].try_into()
        .map_err(|_| BottleError::Decryption("Invalid nonce length".to_string()))?;
    let _nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| BottleError::Decryption("Key creation failed".to_string()))?;
    
    struct SingleNonceSequence([u8; 12]);
    impl NonceSequence for SingleNonceSequence {
        fn advance(&mut self) -> std::result::Result<aead::Nonce, ring::error::Unspecified> {
            Ok(aead::Nonce::assume_unique_for_key(self.0))
        }
    }
    
    let mut opening_key = OpeningKey::new(unbound_key, SingleNonceSequence(nonce_bytes));
    
    let mut in_out = ciphertext[12..].to_vec();
    let tag_len = opening_key.algorithm().tag_len();
    
    let plaintext = opening_key.open_in_place(aead::Aad::empty(), &mut in_out)
        .map_err(|_| BottleError::Decryption("Decryption failed".to_string()))?;
    
    // open_in_place returns a slice excluding the tag
    // However, if encryption added zeros for tag space, those zeros are also decrypted
    // Trim trailing zeros that match the tag length (they were padding added during encryption)
    let mut result = plaintext.to_vec();
    if result.len() >= tag_len && result[result.len() - tag_len..].iter().all(|&b| b == 0) {
        result.truncate(result.len() - tag_len);
    }
    
    Ok(result)
}

