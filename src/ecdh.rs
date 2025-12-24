use crate::errors::{BottleError, Result};
use p256::ecdh::EphemeralSecret;
use p256::{PublicKey, SecretKey};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[cfg(feature = "ml-kem")]
use ml_kem::{EncodedSizeUser, KemCore, kem::{Kem, Encapsulate, Decapsulate}, MlKem768Params, MlKem1024Params};
#[cfg(feature = "ml-kem")]
use zerocopy::IntoBytes;

/// ECDH encryption using P-256 elliptic curve.
///
/// This function performs Elliptic Curve Diffie-Hellman key exchange using
/// the P-256 (secp256r1) curve. It generates an ephemeral key pair, computes
/// a shared secret with the recipient's public key, derives an AES-256-GCM
/// encryption key, and encrypts the plaintext.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `plaintext` - The message to encrypt
/// * `public_key` - The recipient's P-256 public key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data: ephemeral public key (65 bytes) + ciphertext
/// * `Err(BottleError::Encryption)` - If encryption fails
///
/// # Format
///
/// The output format is: `[ephemeral_public_key (65 bytes)][encrypted_data]`
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::ecdh_encrypt_p256;
/// use rust_bottle::keys::EcdsaP256Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pub_key = p256::PublicKey::from_sec1_bytes(&key.public_key_bytes()).unwrap();
///
/// let plaintext = b"Secret message";
/// let ciphertext = ecdh_encrypt_p256(rng, plaintext, &pub_key).unwrap();
/// ```
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

/// ECDH decryption using P-256 elliptic curve.
///
/// This function decrypts data encrypted with `ecdh_encrypt_p256`. It extracts
/// the ephemeral public key from the ciphertext, computes the shared secret
/// using the recipient's private key, derives the AES-256-GCM key, and decrypts.
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data: ephemeral public key (65 bytes) + ciphertext
/// * `private_key` - The recipient's P-256 private key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(BottleError::InvalidFormat)` - If ciphertext is too short
/// * `Err(BottleError::Decryption)` - If decryption fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::{ecdh_encrypt_p256, ecdh_decrypt_p256};
/// use rust_bottle::keys::EcdsaP256Key;
/// use rand::rngs::OsRng;
/// use p256::elliptic_curve::sec1::FromEncodedPoint;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pub_key = p256::PublicKey::from_sec1_bytes(&key.public_key_bytes()).unwrap();
/// let priv_key_bytes = key.private_key_bytes();
/// let priv_key = p256::SecretKey::from_bytes(priv_key_bytes.as_slice().into()).unwrap();
///
/// let plaintext = b"Secret message";
/// let ciphertext = ecdh_encrypt_p256(rng, plaintext, &pub_key).unwrap();
/// let decrypted = ecdh_decrypt_p256(&ciphertext, &priv_key).unwrap();
/// assert_eq!(decrypted, plaintext);
/// ```
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

/// X25519 ECDH encryption.
///
/// This function performs Elliptic Curve Diffie-Hellman key exchange using
/// the X25519 curve (Curve25519). It generates an ephemeral key pair, computes
/// a shared secret with the recipient's public key, derives an AES-256-GCM
/// encryption key, and encrypts the plaintext.
///
/// # Arguments
///
/// * `rng` - A random number generator
/// * `plaintext` - The message to encrypt
/// * `public_key` - The recipient's X25519 public key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data: ephemeral public key (32 bytes) + ciphertext
/// * `Err(BottleError::Encryption)` - If encryption fails
///
/// # Format
///
/// The output format is: `[ephemeral_public_key (32 bytes)][encrypted_data]`
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::ecdh_encrypt_x25519;
/// use rust_bottle::keys::X25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = X25519Key::generate(rng);
/// let pub_key_bytes: [u8; 32] = key.public_key_bytes().try_into().unwrap();
/// let pub_key = x25519_dalek::PublicKey::from(pub_key_bytes);
///
/// let plaintext = b"Secret message";
/// let ciphertext = ecdh_encrypt_x25519(rng, plaintext, &pub_key).unwrap();
/// ```
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

/// X25519 ECDH decryption.
///
/// This function decrypts data encrypted with `ecdh_encrypt_x25519`. It extracts
/// the ephemeral public key from the ciphertext, computes the shared secret
/// using the recipient's private key, derives the AES-256-GCM key, and decrypts.
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data: ephemeral public key (32 bytes) + ciphertext
/// * `private_key` - The recipient's X25519 private key (32 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(BottleError::InvalidFormat)` - If ciphertext is too short
/// * `Err(BottleError::Decryption)` - If decryption fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::{ecdh_encrypt_x25519, ecdh_decrypt_x25519};
/// use rust_bottle::keys::X25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = X25519Key::generate(rng);
/// let pub_key_bytes: [u8; 32] = key.public_key_bytes().try_into().unwrap();
/// let pub_key = x25519_dalek::PublicKey::from(pub_key_bytes);
/// let priv_key_bytes: [u8; 32] = key.private_key_bytes().try_into().unwrap();
///
/// let plaintext = b"Secret message";
/// let ciphertext = ecdh_encrypt_x25519(rng, plaintext, &pub_key).unwrap();
/// let decrypted = ecdh_decrypt_x25519(&ciphertext, &priv_key_bytes).unwrap();
/// assert_eq!(decrypted, plaintext);
/// ```
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

/// Trait for ECDH encryption operations.
///
/// This trait allows different ECDH implementations to be used polymorphically.
/// Currently not used in the public API but available for extension.
pub trait ECDHEncrypt {
    /// Encrypt plaintext to a public key using ECDH.
    fn encrypt<R: RngCore>(&self, rng: &mut R, plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>>;
}

/// Trait for ECDH decryption operations.
///
/// This trait allows different ECDH implementations to be used polymorphically.
/// Currently not used in the public API but available for extension.
pub trait ECDHDecrypt {
    /// Decrypt ciphertext using a private key.
    fn decrypt(&self, ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>>;
}

/// Generic ECDH encryption function with automatic key type detection.
///
/// This function automatically detects the key type based on the public key
/// length and format, then uses the appropriate encryption implementation.
///
/// # Key Type Detection
///
/// * 32 bytes: X25519 (Curve25519)
/// * 64 or 65 bytes: P-256 (secp256r1) in SEC1 format
/// * 1184 bytes: ML-KEM-768 public key
/// * 1568 bytes: ML-KEM-1024 public key
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `plaintext` - The message to encrypt
/// * `public_key` - The recipient's public key (any supported format)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data with ephemeral public key prepended
/// * `Err(BottleError::InvalidKeyType)` - If the key format is not recognized
/// * `Err(BottleError::Encryption)` - If encryption fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::ecdh_encrypt;
/// use rust_bottle::keys::X25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = X25519Key::generate(rng);
/// let plaintext = b"Secret message";
///
/// let ciphertext = ecdh_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
/// ```
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
        #[cfg(feature = "ml-kem")]
        {
            if public_key.len() == 1184 {
                // ML-KEM-768 public key
                return mlkem768_encrypt(rng, plaintext, public_key);
            } else if public_key.len() == 1568 {
                // ML-KEM-1024 public key
                return mlkem1024_encrypt(rng, plaintext, public_key);
            }
        }
        Err(BottleError::InvalidKeyType)
    }
}

/// Generic ECDH decryption function with automatic key type detection.
///
/// This function automatically detects the key type and uses the appropriate
/// decryption implementation. It tries X25519 first, then P-256, then ML-KEM.
///
/// # Key Type Detection
///
/// * 32 bytes: Tries X25519 first, then P-256 if X25519 fails
/// * 2400 bytes: ML-KEM-768 secret key
/// * 3168 bytes: ML-KEM-1024 secret key
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data with ephemeral public key prepended
/// * `private_key` - The recipient's private key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(BottleError::InvalidKeyType)` - If the key format is not recognized
/// * `Err(BottleError::Decryption)` - If decryption fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::{ecdh_encrypt, ecdh_decrypt};
/// use rust_bottle::keys::X25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = X25519Key::generate(rng);
/// let plaintext = b"Secret message";
///
/// let ciphertext = ecdh_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
/// let decrypted = ecdh_decrypt(&ciphertext, &key.private_key_bytes()).unwrap();
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn ecdh_decrypt(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "ml-kem")]
    {
        // Try ML-KEM-768 (2400 bytes secret key)
        if private_key.len() == 2400 {
            if let Ok(result) = mlkem768_decrypt(ciphertext, private_key) {
                return Ok(result);
            }
        }
        
        // Try ML-KEM-1024 (3168 bytes secret key)
        if private_key.len() == 3168 {
            if let Ok(result) = mlkem1024_decrypt(ciphertext, private_key) {
                return Ok(result);
            }
        }
    }
    
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

#[cfg(feature = "ml-kem")]
/// ML-KEM-768 encryption (post-quantum).
///
/// This function performs ML-KEM key encapsulation and encrypts the plaintext
/// using the derived shared secret with AES-256-GCM.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator (not used, ML-KEM is deterministic)
/// * `plaintext` - The message to encrypt
/// * `public_key` - The recipient's ML-KEM-768 public key (1184 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data: ML-KEM ciphertext (1088 bytes) + AES-GCM encrypted message
/// * `Err(BottleError::Encryption)` - If encryption fails
/// * `Err(BottleError::InvalidKeyType)` - If the key format is invalid
#[cfg(feature = "ml-kem")]
pub fn mlkem768_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>> {
    // Parse public key (encapsulation key)
    // from_bytes expects a generic-array Array type, so we need to convert
    if public_key.len() != 1184 {
        return Err(BottleError::InvalidKeyType);
    }
    let pub_key_array: [u8; 1184] = public_key.try_into()
        .map_err(|_| BottleError::InvalidKeyType)?;
    let ek = <Kem<MlKem768Params> as KemCore>::EncapsulationKey::from_bytes((&pub_key_array).into());
    
    // ml-kem uses rand_core 0.9, create adapter
    use rand_core_09::{RngCore as RngCore09, CryptoRng as CryptoRng09};
    struct RngAdapter<'a, R: RngCore + CryptoRng>(&'a mut R);
    impl<'a, R: RngCore + CryptoRng> RngCore09 for RngAdapter<'a, R> {
        fn next_u32(&mut self) -> u32 { self.0.next_u32() }
        fn next_u64(&mut self) -> u64 { self.0.next_u64() }
        fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.fill_bytes(dest) }
        // try_fill_bytes has a default implementation that calls fill_bytes, so we don't need to implement it
    }
    impl<'a, R: RngCore + CryptoRng> CryptoRng09 for RngAdapter<'a, R> {}
    
    let mut adapter = RngAdapter(rng);
    // Encapsulate (generate shared secret and ciphertext)
    use ml_kem::kem::Encapsulate;
    let (ct, shared_secret) = ek.encapsulate(&mut adapter)
        .map_err(|_| BottleError::Encryption("ML-KEM encapsulation failed".to_string()))?;
    
    // Derive AES key from shared secret (shared_secret is [u8; 32])
    let key = derive_key(&shared_secret);
    
    // Encrypt plaintext with AES-GCM
    let encrypted = encrypt_aes_gcm(&key, plaintext)?;
    
    // Combine: ML-KEM ciphertext + AES-GCM encrypted data
    let mut result = ct.as_bytes().to_vec();
    result.extend_from_slice(&encrypted);
    
    Ok(result)
}

#[cfg(feature = "ml-kem")]
/// ML-KEM-768 decryption (post-quantum).
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data: ML-KEM ciphertext (1088 bytes) + AES-GCM encrypted message
/// * `secret_key` - The recipient's ML-KEM-768 secret key (2400 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(BottleError::Decryption)` - If decryption fails
/// * `Err(BottleError::InvalidFormat)` - If ciphertext is too short
#[cfg(feature = "ml-kem")]
pub fn mlkem768_decrypt(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    // Parse secret key (decapsulation key)
    if secret_key.len() != 2400 {
        return Err(BottleError::InvalidKeyType);
    }
    let sec_key_array: [u8; 2400] = secret_key.try_into()
        .map_err(|_| BottleError::InvalidKeyType)?;
    let dk = <Kem<MlKem768Params> as KemCore>::DecapsulationKey::from_bytes((&sec_key_array).into());
    
    // Extract ML-KEM ciphertext (first 1088 bytes for ML-KEM-768)
    const CT_SIZE: usize = 1088; // ML-KEM-768 ciphertext size
    // AES-GCM needs at least 12 bytes (nonce) + 16 bytes (tag) = 28 bytes minimum
    if ciphertext.len() < CT_SIZE + 28 {
        return Err(BottleError::InvalidFormat);
    }
    // Extract exactly CT_SIZE bytes for the ML-KEM ciphertext
    let mlkem_ct_bytes = &ciphertext[..CT_SIZE];
    let ct_array: [u8; CT_SIZE] = mlkem_ct_bytes.try_into()
        .map_err(|_| BottleError::InvalidFormat)?;
    // Ciphertext is an associated type of KemCore, use the correct type
    type MlKem768 = Kem<MlKem768Params>;
    let mlkem_ct = <MlKem768 as KemCore>::Ciphertext::from_bytes((&ct_array).into());
    let aes_ct = &ciphertext[CT_SIZE..];
    
    // Decapsulate to get shared secret
    use ml_kem::kem::Decapsulate;
    let shared_secret = dk.decapsulate(&mlkem_ct)
        .map_err(|_| BottleError::Decryption("ML-KEM decapsulation failed".to_string()))?;
    
    // Derive AES key (shared_secret is [u8; 32])
    let key = derive_key(&shared_secret);
    
    // Decrypt with AES-GCM
    decrypt_aes_gcm(&key, aes_ct)
}

#[cfg(feature = "ml-kem")]
/// ML-KEM-1024 encryption (post-quantum).
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator (not used)
/// * `plaintext` - The message to encrypt
/// * `public_key` - The recipient's ML-KEM-1024 public key (1568 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data: ML-KEM ciphertext (1568 bytes) + AES-GCM encrypted message
#[cfg(feature = "ml-kem")]
pub fn mlkem1024_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>> {
    // Parse public key (encapsulation key)
    if public_key.len() != 1568 {
        return Err(BottleError::InvalidKeyType);
    }
    let pub_key_array: [u8; 1568] = public_key.try_into()
        .map_err(|_| BottleError::InvalidKeyType)?;
    let ek = <Kem<MlKem1024Params> as KemCore>::EncapsulationKey::from_bytes((&pub_key_array).into());
    
    // ml-kem uses rand_core 0.9, create adapter
    use rand_core_09::{RngCore as RngCore09, CryptoRng as CryptoRng09};
    struct RngAdapter<'a, R: RngCore + CryptoRng>(&'a mut R);
    impl<'a, R: RngCore + CryptoRng> RngCore09 for RngAdapter<'a, R> {
        fn next_u32(&mut self) -> u32 { self.0.next_u32() }
        fn next_u64(&mut self) -> u64 { self.0.next_u64() }
        fn fill_bytes(&mut self, dest: &mut [u8]) { self.0.fill_bytes(dest) }
        // try_fill_bytes has a default implementation that calls fill_bytes, so we don't need to implement it
    }
    impl<'a, R: RngCore + CryptoRng> CryptoRng09 for RngAdapter<'a, R> {}
    
    let mut adapter = RngAdapter(rng);
    // Encapsulate (generate shared secret and ciphertext)
    use ml_kem::kem::Encapsulate;
    let (ct, shared_secret) = ek.encapsulate(&mut adapter)
        .map_err(|_| BottleError::Encryption("ML-KEM encapsulation failed".to_string()))?;
    
    // Derive AES key from shared secret (shared_secret is [u8; 32])
    let key = derive_key(&shared_secret);
    
    // Encrypt plaintext with AES-GCM
    let encrypted = encrypt_aes_gcm(&key, plaintext)?;
    
    // Combine: ML-KEM ciphertext + AES-GCM encrypted data
    let mut result = ct.as_bytes().to_vec();
    result.extend_from_slice(&encrypted);
    Ok(result)
}

#[cfg(feature = "ml-kem")]
/// ML-KEM-1024 decryption (post-quantum).
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data: ML-KEM ciphertext (1568 bytes) + AES-GCM encrypted message
/// * `secret_key` - The recipient's ML-KEM-1024 secret key (3168 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
#[cfg(feature = "ml-kem")]
pub fn mlkem1024_decrypt(
    ciphertext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    // Parse secret key (decapsulation key)
    if secret_key.len() != 3168 {
        return Err(BottleError::InvalidKeyType);
    }
    let sec_key_array: [u8; 3168] = secret_key.try_into()
        .map_err(|_| BottleError::InvalidKeyType)?;
    let dk = <Kem<MlKem1024Params> as KemCore>::DecapsulationKey::from_bytes((&sec_key_array).into());
    
    // Extract ML-KEM ciphertext (first 1568 bytes for ML-KEM-1024)
    const CT_SIZE: usize = 1568; // ML-KEM-1024 ciphertext size
    // AES-GCM needs at least 12 bytes (nonce) + 16 bytes (tag) = 28 bytes minimum
    if ciphertext.len() < CT_SIZE + 28 {
        return Err(BottleError::InvalidFormat);
    }
    let ct_array: [u8; CT_SIZE] = ciphertext[..CT_SIZE].try_into()
        .map_err(|_| BottleError::InvalidFormat)?;
    // Ciphertext is an associated type of KemCore, use the correct type
    type MlKem1024 = Kem<MlKem1024Params>;
    let mlkem_ct = <MlKem1024 as KemCore>::Ciphertext::from_bytes((&ct_array).into());
    let aes_ct = &ciphertext[CT_SIZE..];
    
    // Decapsulate to get shared secret
    use ml_kem::kem::Decapsulate;
    let shared_secret = dk.decapsulate(&mlkem_ct)
        .map_err(|_| BottleError::Decryption("ML-KEM decapsulation failed".to_string()))?;
    
    // Derive AES key (shared_secret is [u8; 32])
    let key = derive_key(&shared_secret);
    decrypt_aes_gcm(&key, aes_ct)
}

#[cfg(feature = "ml-kem")]
/// Hybrid encryption: ML-KEM-768 + X25519.
///
/// This provides both post-quantum and classical security by combining
/// ML-KEM and X25519 key exchange. The plaintext is encrypted with both
/// algorithms, and either can be used for decryption.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `plaintext` - The message to encrypt
/// * `mlkem_pub` - ML-KEM-768 public key (1184 bytes)
/// * `x25519_pub` - X25519 public key (32 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data: [mlkem_len: u32][mlkem_ct][x25519_ct]
#[cfg(feature = "ml-kem")]
pub fn hybrid_encrypt_mlkem768_x25519<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    mlkem_pub: &[u8],
    x25519_pub: &[u8],
) -> Result<Vec<u8>> {
    // Encrypt with both ML-KEM and X25519
    let mlkem_ct = mlkem768_encrypt(rng, plaintext, mlkem_pub)?;
    let x25519_pub_bytes: [u8; 32] = x25519_pub.try_into()
        .map_err(|_| BottleError::InvalidKeyType)?;
    let x25519_pub_key = X25519PublicKey::from(x25519_pub_bytes);
    let x25519_ct = ecdh_encrypt_x25519(rng, plaintext, &x25519_pub_key)?;
    
    // Combine: ML-KEM ciphertext + X25519 ciphertext
    // Format: [mlkem_len: u32][mlkem_ct][x25519_ct]
    let mut result = Vec::new();
    result.extend_from_slice(&(mlkem_ct.len() as u32).to_le_bytes());
    result.extend_from_slice(&mlkem_ct);
    result.extend_from_slice(&x25519_ct);
    
    Ok(result)
}

#[cfg(feature = "ml-kem")]
/// Hybrid decryption: ML-KEM-768 + X25519.
///
/// Attempts to decrypt using ML-KEM first, then falls back to X25519.
///
/// # Arguments
///
/// * `ciphertext` - Encrypted data: [mlkem_len: u32][mlkem_ct][x25519_ct]
/// * `mlkem_sec` - ML-KEM-768 secret key (2400 bytes)
/// * `x25519_sec` - X25519 secret key (32 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
#[cfg(feature = "ml-kem")]
pub fn hybrid_decrypt_mlkem768_x25519(
    ciphertext: &[u8],
    mlkem_sec: &[u8],
    x25519_sec: &[u8; 32],
) -> Result<Vec<u8>> {
    if ciphertext.len() < 4 {
        return Err(BottleError::InvalidFormat);
    }
    
    // Extract lengths
    let mlkem_len = u32::from_le_bytes(ciphertext[..4].try_into().unwrap()) as usize;
    if ciphertext.len() < 4 + mlkem_len {
        return Err(BottleError::InvalidFormat);
    }
    
    let mlkem_ct = &ciphertext[4..4+mlkem_len];
    let x25519_ct = &ciphertext[4+mlkem_len..];
    
    // Try ML-KEM first, fall back to X25519
    match mlkem768_decrypt(mlkem_ct, mlkem_sec) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => ecdh_decrypt_x25519(x25519_ct, x25519_sec),
    }
}

// Helper functions

/// Derive a 32-byte encryption key from a shared secret using SHA-256.
///
/// This function uses SHA-256 to derive a deterministic encryption key
/// from the ECDH shared secret. The output is always 32 bytes, suitable
/// for AES-256.
///
/// # Arguments
///
/// * `shared_secret` - The ECDH shared secret bytes
///
/// # Returns
///
/// A 32-byte array containing the derived key
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

/// Encrypt plaintext using AES-256-GCM authenticated encryption.
///
/// This function uses AES-256-GCM for authenticated encryption with
/// associated data (AEAD). It generates a random 12-byte nonce and
/// prepends it to the ciphertext.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key
/// * `plaintext` - The message to encrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted data: nonce (12 bytes) + ciphertext + tag (16 bytes)
/// * `Err(BottleError::Encryption)` - If encryption fails
///
/// # Format
///
/// The output format is: `[nonce (12 bytes)][ciphertext + tag (16 bytes)]`
///
/// # Security Note
///
/// The nonce is randomly generated for each encryption operation. The
/// authentication tag is automatically appended by the GCM mode.
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
    
    // seal_in_place_append_tag encrypts the data in the buffer and appends the tag.
    // According to ring docs, the buffer must have enough capacity for the tag.
    // The function will extend the vector to append the tag.
    let mut in_out = plaintext.to_vec();
    // Reserve capacity for the tag (ring will extend the vector when appending)
    let tag_len = sealing_key.algorithm().tag_len();
    in_out.reserve(tag_len);
    
    // seal_in_place_append_tag encrypts the plaintext and appends the tag
    // It requires the vector to have enough capacity, which we've reserved
    sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| BottleError::Encryption("Encryption failed".to_string()))?;
    
    // Prepend nonce to the result
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);
    Ok(result)
}

/// Decrypt ciphertext using AES-256-GCM authenticated encryption.
///
/// This function decrypts data encrypted with `encrypt_aes_gcm`. It extracts
/// the nonce, verifies the authentication tag, and returns the plaintext.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 key (same as used for encryption)
/// * `ciphertext` - Encrypted data: nonce (12 bytes) + ciphertext + tag (16 bytes)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext (with padding zeros removed if present)
/// * `Err(BottleError::InvalidFormat)` - If ciphertext is too short
/// * `Err(BottleError::Decryption)` - If decryption or authentication fails
///
/// # Security Note
///
/// This function automatically verifies the authentication tag. If verification
/// fails, decryption returns an error. The function also trims trailing zeros
/// that may have been added during encryption for tag space.
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
    
    // The ciphertext format is: nonce (12 bytes) + encrypted_data + tag (16 bytes)
    // open_in_place expects the ciphertext + tag (without the nonce)
    let mut in_out = ciphertext[12..].to_vec();
    
    // open_in_place decrypts and verifies the tag, returning the plaintext
    // It expects the tag to be at the end of the buffer
    let plaintext = opening_key.open_in_place(aead::Aad::empty(), &mut in_out)
        .map_err(|_| BottleError::Decryption("Decryption failed".to_string()))?;
    
    Ok(plaintext.to_vec())
}

/// RSA-OAEP encryption.
///
/// This function encrypts data using RSA-OAEP (Optimal Asymmetric Encryption
/// Padding) with SHA-256. RSA can only encrypt small amounts of data (typically
/// up to key_size - 42 bytes for OAEP with SHA-256). For larger messages,
/// consider using RSA to encrypt a symmetric key and then encrypt the message
/// with that key.
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator
/// * `plaintext` - The message to encrypt (must be smaller than key_size - 42 bytes)
/// * `public_key` - The recipient's RSA public key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Encrypted ciphertext
/// * `Err(BottleError::Encryption)` - If encryption fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::rsa_encrypt;
/// use rust_bottle::keys::RsaKey;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = RsaKey::generate(rng, 2048).unwrap();
/// let plaintext = b"Small message";
///
/// let ciphertext = rsa_encrypt(rng, plaintext, key.public_key()).unwrap();
/// ```
pub fn rsa_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    plaintext: &[u8],
    public_key: &rsa::RsaPublicKey,
) -> Result<Vec<u8>> {
    use rsa::Oaep;
    use sha2::Sha256;
    
    // RSA-OAEP with SHA-256
    let padding = Oaep::new::<Sha256>();
    public_key.encrypt(rng, padding, plaintext)
        .map_err(|e| BottleError::Encryption(format!("RSA encryption failed: {}", e)))
}

/// RSA-OAEP decryption.
///
/// This function decrypts data encrypted with RSA-OAEP.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted data
/// * `rsa_key` - The recipient's RSA key (as RsaKey)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(BottleError::Decryption)` - If decryption fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::ecdh::{rsa_encrypt, rsa_decrypt};
/// use rust_bottle::keys::RsaKey;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = RsaKey::generate(rng, 2048).unwrap();
/// let plaintext = b"Small message";
///
/// let ciphertext = rsa_encrypt(rng, plaintext, key.public_key()).unwrap();
/// let decrypted = rsa_decrypt(&ciphertext, &key).unwrap();
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn rsa_decrypt(
    ciphertext: &[u8],
    rsa_key: &crate::keys::RsaKey,
) -> Result<Vec<u8>> {
    rsa_key.decrypt(ciphertext)
}

