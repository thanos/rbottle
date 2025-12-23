use crate::errors::{BottleError, Result};
use crate::signing::{Sign, Verify};
use crate::keychain::SignerKey;
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use rand::{CryptoRng, RngCore};

// Post-quantum cryptography imports
#[cfg(feature = "ml-kem")]
use pqcrypto_kyber;
#[cfg(feature = "post-quantum")]
use pqcrypto_dilithium;
#[cfg(feature = "post-quantum")]
use pqcrypto_sphincsplus;
#[cfg(feature = "post-quantum")]
use pqcrypto_traits::sign::{PublicKey as PqcPublicKey, SecretKey as PqcSecretKey, DetachedSignature as PqcDetachedSignature};

/// ECDSA P-256 key pair for digital signatures.
///
/// This key type uses the P-256 (secp256r1) elliptic curve for signing.
/// ECDSA signatures are deterministic (RFC 6979) and provide strong security
/// with 128-bit security level.
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pub_key = key.public_key_bytes();
/// let priv_key = key.private_key_bytes();
/// ```
pub struct EcdsaP256Key {
    signing_key: P256SigningKey,
    verifying_key: P256VerifyingKey,
}

impl EcdsaP256Key {
    /// Generate a new ECDSA P-256 key pair.
    ///
    /// This function generates a cryptographically secure key pair using
    /// the provided random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `EcdsaP256Key` instance with a randomly generated key pair
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::EcdsaP256Key;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = EcdsaP256Key::generate(rng);
    /// ```
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing_key = P256SigningKey::random(rng);
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key in SEC1 uncompressed format.
    ///
    /// The public key is returned as a 65-byte array in SEC1 uncompressed
    /// format (0x04 prefix + 32-byte x-coordinate + 32-byte y-coordinate).
    ///
    /// # Returns
    ///
    /// Public key bytes in SEC1 format
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_sec1_bytes().to_vec()
    }

    /// Get the private key bytes.
    ///
    /// The private key is returned as a 32-byte array. This is sensitive
    /// data and should be handled securely.
    ///
    /// # Returns
    ///
    /// Private key bytes (32 bytes)
    ///
    /// # Security Warning
    ///
    /// Private keys are sensitive cryptographic material. They should be
    /// stored securely and cleared from memory when no longer needed.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Create an ECDSA P-256 key pair from private key bytes.
    ///
    /// This function reconstructs a key pair from a previously saved private
    /// key. The public key is automatically derived from the private key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Private key bytes (32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(EcdsaP256Key)` - Reconstructed key pair
    /// * `Err(BottleError::InvalidKeyType)` - If the key format is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::EcdsaP256Key;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let original = EcdsaP256Key::generate(rng);
    /// let priv_bytes = original.private_key_bytes();
    ///
    /// let restored = EcdsaP256Key::from_private_key_bytes(&priv_bytes).unwrap();
    /// assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    /// ```
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = P256SigningKey::from_bytes(bytes.into())
            .map_err(|_| BottleError::InvalidKeyType)?;
        let verifying_key = *signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

impl Sign for EcdsaP256Key {
    /// Sign a message using ECDSA P-256.
    ///
    /// The message is hashed with SHA-256 before signing. The signature
    /// is deterministic (RFC 6979), meaning the same message and key will
    /// always produce the same signature.
    ///
    /// # Arguments
    ///
    /// * `_rng` - Random number generator (not used for deterministic signing)
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Signature bytes (64 bytes: r + s values)
    /// * `Err(BottleError::VerifyFailed)` - If signing fails
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        use ecdsa::signature::Signer;
        use sha2::Digest;
        // Hash the message first
        let digest = sha2::Sha256::digest(message);
        // Use regular sign method (deterministic with RFC6979)
        let signature: ecdsa::Signature<p256::NistP256> = self.signing_key.sign(&digest);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verify for EcdsaP256Key {
    /// Verify an ECDSA P-256 signature.
    ///
    /// The message is hashed with SHA-256 before verification. The signature
    /// must match the format produced by `sign`.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify (64 bytes: r + s values)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Signature is valid
    /// * `Err(BottleError::VerifyFailed)` - If signature verification fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::EcdsaP256Key;
    /// use rust_bottle::signing::{Sign, Verify};
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = EcdsaP256Key::generate(rng);
    /// let message = b"Test message";
    ///
    /// let signature = key.sign(rng, message).unwrap();
    /// assert!(key.verify(message, &signature).is_ok());
    /// ```
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use ecdsa::signature::Verifier;
        use sha2::Digest;
        // Hash the message first
        let digest = sha2::Sha256::digest(message);
        let sig = ecdsa::Signature::from_bytes(signature.into())
            .map_err(|_| BottleError::VerifyFailed)?;
        self.verifying_key.verify(&digest, &sig)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

impl SignerKey for EcdsaP256Key {
    /// Get the public key fingerprint (SHA-256 hash).
    ///
    /// The fingerprint is used to identify keys in keychains and IDCards.
    ///
    /// # Returns
    ///
    /// SHA-256 hash of the public key bytes
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    /// Get the public key bytes.
    ///
    /// # Returns
    ///
    /// Public key bytes in SEC1 format
    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

/// Ed25519 key pair for digital signatures.
///
/// Ed25519 is a modern elliptic curve signature scheme based on Curve25519.
/// It provides 128-bit security with fast signing and verification, and
/// deterministic signatures. Ed25519 keys are 32 bytes for both private and
/// public keys.
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::Ed25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = Ed25519Key::generate(rng);
/// let pub_key = key.public_key_bytes();
/// let priv_key = key.private_key_bytes();
/// ```
pub struct Ed25519Key {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl Ed25519Key {
    /// Generate a new Ed25519 key pair.
    ///
    /// This function generates a cryptographically secure key pair using
    /// the provided random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `Ed25519Key` instance with a randomly generated key pair
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::Ed25519Key;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// ```
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing_key = Ed25519SigningKey::generate(rng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key: verifying_key.clone(),
        }
    }

    /// Get the public key bytes.
    ///
    /// Ed25519 public keys are 32 bytes.
    ///
    /// # Returns
    ///
    /// Public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// Get the private key bytes.
    ///
    /// Ed25519 private keys are 32 bytes. This is sensitive data and should
    /// be handled securely.
    ///
    /// # Returns
    ///
    /// Private key bytes (32 bytes)
    ///
    /// # Security Warning
    ///
    /// Private keys are sensitive cryptographic material. They should be
    /// stored securely and cleared from memory when no longer needed.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Create an Ed25519 key pair from private key bytes.
    ///
    /// This function reconstructs a key pair from a previously saved private
    /// key. The public key is automatically derived from the private key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Private key bytes (32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(Ed25519Key)` - Reconstructed key pair
    /// * `Err(BottleError::InvalidKeyType)` - If the key format is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::Ed25519Key;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let original = Ed25519Key::generate(rng);
    /// let priv_bytes = original.private_key_bytes();
    ///
    /// let restored = Ed25519Key::from_private_key_bytes(&priv_bytes).unwrap();
    /// assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    /// ```
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let signing_key = Ed25519SigningKey::from_bytes(bytes.try_into()
            .map_err(|_| BottleError::InvalidKeyType)?);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key: verifying_key.clone(),
        })
    }
}

impl Sign for Ed25519Key {
    /// Sign a message using Ed25519.
    ///
    /// Ed25519 signs messages directly without pre-hashing. The signature
    /// is deterministic and always 64 bytes.
    ///
    /// # Arguments
    ///
    /// * `_rng` - Random number generator (not used for deterministic signing)
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Signature bytes (64 bytes)
    /// * `Err(BottleError::VerifyFailed)` - If signing fails
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verify for Ed25519Key {
    /// Verify an Ed25519 signature.
    ///
    /// The message is verified directly without pre-hashing. The signature
    /// must be 64 bytes.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify (64 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Signature is valid
    /// * `Err(BottleError::VerifyFailed)` - If signature verification fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::Ed25519Key;
    /// use rust_bottle::signing::{Sign, Verify};
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let message = b"Test message";
    ///
    /// let signature = key.sign(rng, message).unwrap();
    /// assert!(key.verify(message, &signature).is_ok());
    /// ```
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use ed25519_dalek::Verifier;
        let sig = Signature::from_bytes(signature.try_into()
            .map_err(|_| BottleError::VerifyFailed)?);
        self.verifying_key.verify(message, &sig)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

impl SignerKey for Ed25519Key {
    /// Get the public key fingerprint (SHA-256 hash).
    ///
    /// The fingerprint is used to identify keys in keychains and IDCards.
    ///
    /// # Returns
    ///
    /// SHA-256 hash of the public key bytes
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    /// Get the public key bytes.
    ///
    /// # Returns
    ///
    /// Public key bytes (32 bytes)
    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

/// X25519 key pair for ECDH encryption.
///
/// X25519 is the Diffie-Hellman function over Curve25519. It is used for
/// key exchange and encryption, not for signing. X25519 keys are 32 bytes
/// for both private and public keys.
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::X25519Key;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = X25519Key::generate(rng);
/// let pub_key = key.public_key_bytes();
/// let priv_key = key.private_key_bytes();
/// ```
pub struct X25519Key {
    secret: [u8; 32], // Store as bytes since StaticSecret doesn't exist in 2.0
    public: x25519_dalek::PublicKey,
}

impl X25519Key {
    /// Generate a new X25519 key pair.
    ///
    /// This function generates a cryptographically secure key pair using
    /// the provided random number generator.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    ///
    /// # Returns
    ///
    /// A new `X25519Key` instance with a randomly generated key pair
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::X25519Key;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = X25519Key::generate(rng);
    /// ```
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        use x25519_dalek::StaticSecret;
        // Generate random secret key
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        // Create StaticSecret and derive public key
        let secret = StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret: secret_bytes, public }
    }

    /// Get the public key bytes.
    ///
    /// X25519 public keys are 32 bytes.
    ///
    /// # Returns
    ///
    /// Public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }

    /// Get the private key bytes.
    ///
    /// X25519 private keys are 32 bytes. This is sensitive data and should
    /// be handled securely.
    ///
    /// # Returns
    ///
    /// Private key bytes (32 bytes)
    ///
    /// # Security Warning
    ///
    /// Private keys are sensitive cryptographic material. They should be
    /// stored securely and cleared from memory when no longer needed.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    /// Create an X25519 key pair from private key bytes.
    ///
    /// This function reconstructs a key pair from a previously saved private
    /// key. The public key is automatically derived from the private key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Private key bytes (32 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(X25519Key)` - Reconstructed key pair
    /// * `Err(BottleError::InvalidKeyType)` - If the key format is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::keys::X25519Key;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let original = X25519Key::generate(rng);
    /// let priv_bytes = original.private_key_bytes();
    ///
    /// let restored = X25519Key::from_private_key_bytes(&priv_bytes).unwrap();
    /// assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    /// ```
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        use x25519_dalek::StaticSecret;
        let secret_bytes: [u8; 32] = bytes.try_into()
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Create StaticSecret and derive public key
        let secret = StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Self { secret: secret_bytes, public })
    }
}

// Post-Quantum Cryptography Key Types

#[cfg(feature = "ml-kem")]
/// ML-KEM-768 key pair for post-quantum encryption.
///
/// ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) is a post-quantum
/// encryption algorithm standardized by NIST. ML-KEM-768 provides 192-bit
/// security level.
///
/// # Example
///
/// ```rust
/// #[cfg(feature = "post-quantum")]
/// use rust_bottle::keys::MlKem768Key;
/// use rand::rngs::OsRng;
///
/// #[cfg(feature = "post-quantum")]
/// {
///     let rng = &mut OsRng;
///     let key = MlKem768Key::generate(rng);
///     let pub_key = key.public_key_bytes();
///     let priv_key = key.private_key_bytes();
/// }
/// ```
pub struct MlKem768Key {
    public_key: pqcrypto_kyber::pqcrypto_kyber768::PublicKey,
    secret_key: pqcrypto_kyber::pqcrypto_kyber768::SecretKey,
}

#[cfg(feature = "post-quantum")]
#[cfg(feature = "ml-kem")]
impl MlKem768Key {
    /// Generate a new ML-KEM-768 key pair.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `MlKem768Key` instance
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_kyber::pqcrypto_kyber768::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    ///
    /// # Returns
    ///
    /// Public key bytes (1184 bytes for ML-KEM-768)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        pqcrypto_kyber::pqcrypto_kyber768::public_key_to_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    ///
    /// # Returns
    ///
    /// Private key bytes (2400 bytes for ML-KEM-768)
    ///
    /// # Security Warning
    ///
    /// Private keys are sensitive cryptographic material.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        pqcrypto_kyber::pqcrypto_kyber768::secret_key_to_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Private key bytes (2400 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(MlKem768Key)` - Reconstructed key pair
    /// * `Err(BottleError::InvalidKeyType)` - If the key format is invalid
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = pqcrypto_kyber::pqcrypto_kyber768::secret_key_from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Derive public key from secret key
        let public_key = pqcrypto_kyber::pqcrypto_kyber768::public_key_from_secret_key(&secret_key);
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key reference (for encryption operations).
    pub fn public_key(&self) -> &pqcrypto_kyber::pqcrypto_kyber768::PublicKey {
        &self.public_key
    }

    /// Get the secret key reference (for decryption operations).
    pub fn secret_key(&self) -> &pqcrypto_kyber::pqcrypto_kyber768::SecretKey {
        &self.secret_key
    }
}

#[cfg(feature = "ml-kem")]
impl SignerKey for MlKem768Key {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "ml-kem")]
/// ML-KEM-1024 key pair for post-quantum encryption.
///
/// ML-KEM-1024 provides 256-bit security level.
pub struct MlKem1024Key {
    public_key: pqcrypto_kyber::pqcrypto_kyber1024::PublicKey,
    secret_key: pqcrypto_kyber::pqcrypto_kyber1024::SecretKey,
}

#[cfg(feature = "post-quantum")]
#[cfg(feature = "ml-kem")]
impl MlKem1024Key {
    /// Generate a new ML-KEM-1024 key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_kyber::pqcrypto_kyber1024::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        pqcrypto_kyber::pqcrypto_kyber1024::public_key_to_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        pqcrypto_kyber::pqcrypto_kyber1024::secret_key_to_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = pqcrypto_kyber::pqcrypto_kyber1024::secret_key_from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        let public_key = pqcrypto_kyber::pqcrypto_kyber1024::public_key_from_secret_key(&secret_key);
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key reference.
    pub fn public_key(&self) -> &pqcrypto_kyber::pqcrypto_kyber1024::PublicKey {
        &self.public_key
    }

    /// Get the secret key reference.
    pub fn secret_key(&self) -> &pqcrypto_kyber::pqcrypto_kyber1024::SecretKey {
        &self.secret_key
    }
}

#[cfg(feature = "ml-kem")]
impl SignerKey for MlKem1024Key {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "post-quantum")]
/// ML-DSA-44 key pair for post-quantum signatures.
///
/// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a post-quantum
/// signature algorithm standardized by NIST. ML-DSA-44 provides 128-bit security level.
/// This uses dilithium2 from the pqcrypto-dilithium crate.
pub struct MlDsa44Key {
    public_key: pqcrypto_dilithium::dilithium2::PublicKey,
    secret_key: pqcrypto_dilithium::dilithium2::SecretKey,
}

#[cfg(feature = "post-quantum")]
#[cfg(feature = "post-quantum")]
impl MlDsa44Key {
    /// Generate a new ML-DSA-44 key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_dilithium::dilithium2::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_bytes().to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = pqcrypto_dilithium::dilithium2::SecretKey::from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Generate public key from secret key by creating a new keypair
        // Note: pqcrypto-dilithium doesn't have a direct public_key_from_secret_key function
        // So we need to derive it by creating a temporary keypair
        let (public_key, _) = pqcrypto_dilithium::dilithium2::keypair();
        // Actually, we can't derive public key from secret key directly in this API
        // So we'll need to store both or use a different approach
        // For now, let's require both keys to be provided
        Err(BottleError::InvalidKeyType)
    }
}

#[cfg(feature = "post-quantum")]
impl Sign for MlDsa44Key {
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        let detached_sig = pqcrypto_dilithium::dilithium2::detached_sign(message, &self.secret_key);
        Ok(<pqcrypto_dilithium::dilithium2::DetachedSignature as PqcDetachedSignature>::as_bytes(&detached_sig).to_vec())
    }
}

#[cfg(feature = "post-quantum")]
impl Verify for MlDsa44Key {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let detached_sig = <pqcrypto_dilithium::dilithium2::DetachedSignature as PqcDetachedSignature>::from_bytes(signature)
            .map_err(|_| BottleError::VerifyFailed)?;
        pqcrypto_dilithium::dilithium2::verify_detached_signature(&detached_sig, message, &self.public_key)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

#[cfg(feature = "post-quantum")]
impl SignerKey for MlDsa44Key {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "post-quantum")]
/// ML-DSA-65 key pair for post-quantum signatures.
///
/// ML-DSA-65 provides 192-bit security level.
/// This uses dilithium3 from the pqcrypto-dilithium crate.
pub struct MlDsa65Key {
    public_key: pqcrypto_dilithium::dilithium3::PublicKey,
    secret_key: pqcrypto_dilithium::dilithium3::SecretKey,
}

#[cfg(feature = "post-quantum")]
impl MlDsa65Key {
    /// Generate a new ML-DSA-65 key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_dilithium::dilithium3::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_dilithium::dilithium3::PublicKey as PqcPublicKey>::as_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_dilithium::dilithium3::SecretKey as PqcSecretKey>::as_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = <pqcrypto_dilithium::dilithium3::SecretKey as PqcSecretKey>::from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Cannot derive public key from secret key in this API
        Err(BottleError::InvalidKeyType)
    }
}

#[cfg(feature = "post-quantum")]
impl Sign for MlDsa65Key {
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        let detached_sig = pqcrypto_dilithium::dilithium3::detached_sign(message, &self.secret_key);
        Ok(<pqcrypto_dilithium::dilithium3::DetachedSignature as PqcDetachedSignature>::as_bytes(&detached_sig).to_vec())
    }
}

#[cfg(feature = "post-quantum")]
impl Verify for MlDsa65Key {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let detached_sig = <pqcrypto_dilithium::dilithium3::DetachedSignature as PqcDetachedSignature>::from_bytes(signature)
            .map_err(|_| BottleError::VerifyFailed)?;
        pqcrypto_dilithium::dilithium3::verify_detached_signature(&detached_sig, message, &self.public_key)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

#[cfg(feature = "post-quantum")]
impl SignerKey for MlDsa65Key {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "post-quantum")]
/// ML-DSA-87 key pair for post-quantum signatures.
///
/// ML-DSA-87 provides 256-bit security level.
pub struct MlDsa87Key {
    public_key: pqcrypto_dilithium::dilithium5::PublicKey,
    secret_key: pqcrypto_dilithium::dilithium5::SecretKey,
}

#[cfg(feature = "post-quantum")]
impl MlDsa87Key {
    /// Generate a new ML-DSA-87 key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_dilithium::dilithium5::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_dilithium::dilithium5::PublicKey as PqcPublicKey>::as_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_dilithium::dilithium5::SecretKey as PqcSecretKey>::as_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = <pqcrypto_dilithium::dilithium5::SecretKey as PqcSecretKey>::from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Cannot derive public key from secret key in this API
        Err(BottleError::InvalidKeyType)
    }
}

#[cfg(feature = "post-quantum")]
impl Sign for MlDsa87Key {
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        let detached_sig = pqcrypto_dilithium::dilithium5::detached_sign(message, &self.secret_key);
        Ok(<pqcrypto_dilithium::dilithium5::DetachedSignature as PqcDetachedSignature>::as_bytes(&detached_sig).to_vec())
    }
}

#[cfg(feature = "post-quantum")]
impl Verify for MlDsa87Key {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let detached_sig = <pqcrypto_dilithium::dilithium5::DetachedSignature as PqcDetachedSignature>::from_bytes(signature)
            .map_err(|_| BottleError::VerifyFailed)?;
        pqcrypto_dilithium::dilithium5::verify_detached_signature(&detached_sig, message, &self.public_key)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

#[cfg(feature = "post-quantum")]
impl SignerKey for MlDsa87Key {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "post-quantum")]
/// SLH-DSA-128s key pair for post-quantum hash-based signatures.
///
/// SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is a post-quantum
/// signature algorithm based on hash functions. SLH-DSA-128s provides 128-bit security.
pub struct SlhDsa128sKey {
    public_key: pqcrypto_sphincsplus::sphincsshake256128srobust::PublicKey,
    secret_key: pqcrypto_sphincsplus::sphincsshake256128srobust::SecretKey,
}

#[cfg(feature = "post-quantum")]
impl SlhDsa128sKey {
    /// Generate a new SLH-DSA-128s key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_sphincsplus::sphincsshake256128srobust::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_sphincsplus::sphincsshake256128srobust::PublicKey as PqcPublicKey>::as_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_sphincsplus::sphincsshake256128srobust::SecretKey as PqcSecretKey>::as_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = <pqcrypto_sphincsplus::sphincsshake256128srobust::SecretKey as PqcSecretKey>::from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Cannot derive public key from secret key in this API
        Err(BottleError::InvalidKeyType)
    }
}

#[cfg(feature = "post-quantum")]
impl Sign for SlhDsa128sKey {
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        let detached_sig = pqcrypto_sphincsplus::sphincsshake256128srobust::detached_sign(message, &self.secret_key);
        Ok(<pqcrypto_sphincsplus::sphincsshake256128srobust::DetachedSignature as PqcDetachedSignature>::as_bytes(&detached_sig).to_vec())
    }
}

#[cfg(feature = "post-quantum")]
impl Verify for SlhDsa128sKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let detached_sig = <pqcrypto_sphincsplus::sphincsshake256128srobust::DetachedSignature as PqcDetachedSignature>::from_bytes(signature)
            .map_err(|_| BottleError::VerifyFailed)?;
        pqcrypto_sphincsplus::sphincsshake256128srobust::verify_detached_signature(&detached_sig, message, &self.public_key)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

#[cfg(feature = "post-quantum")]
impl SignerKey for SlhDsa128sKey {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "post-quantum")]
/// SLH-DSA-192s key pair for post-quantum hash-based signatures.
///
/// SLH-DSA-192s provides 192-bit security.
pub struct SlhDsa192sKey {
    public_key: pqcrypto_sphincsplus::sphincsshake256192srobust::PublicKey,
    secret_key: pqcrypto_sphincsplus::sphincsshake256192srobust::SecretKey,
}

#[cfg(feature = "post-quantum")]
impl SlhDsa192sKey {
    /// Generate a new SLH-DSA-192s key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_sphincsplus::sphincsshake256192srobust::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_sphincsplus::sphincsshake256192srobust::PublicKey as PqcPublicKey>::as_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_sphincsplus::sphincsshake256192srobust::SecretKey as PqcSecretKey>::as_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = <pqcrypto_sphincsplus::sphincsshake256192srobust::SecretKey as PqcSecretKey>::from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Cannot derive public key from secret key in this API
        Err(BottleError::InvalidKeyType)
    }
}

#[cfg(feature = "post-quantum")]
impl Sign for SlhDsa192sKey {
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        let detached_sig = pqcrypto_sphincsplus::sphincsshake256192srobust::detached_sign(message, &self.secret_key);
        Ok(<pqcrypto_sphincsplus::sphincsshake256192srobust::DetachedSignature as PqcDetachedSignature>::as_bytes(&detached_sig).to_vec())
    }
}

#[cfg(feature = "post-quantum")]
impl Verify for SlhDsa192sKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let detached_sig = <pqcrypto_sphincsplus::sphincsshake256192srobust::DetachedSignature as PqcDetachedSignature>::from_bytes(signature)
            .map_err(|_| BottleError::VerifyFailed)?;
        pqcrypto_sphincsplus::sphincsshake256192srobust::verify_detached_signature(&detached_sig, message, &self.public_key)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

#[cfg(feature = "post-quantum")]
impl SignerKey for SlhDsa192sKey {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

#[cfg(feature = "post-quantum")]
/// SLH-DSA-256s key pair for post-quantum hash-based signatures.
///
/// SLH-DSA-256s provides 256-bit security.
pub struct SlhDsa256sKey {
    public_key: pqcrypto_sphincsplus::sphincsshake256256srobust::PublicKey,
    secret_key: pqcrypto_sphincsplus::sphincsshake256256srobust::SecretKey,
}

#[cfg(feature = "post-quantum")]
impl SlhDsa256sKey {
    /// Generate a new SLH-DSA-256s key pair.
    pub fn generate<R: RngCore + CryptoRng>(_rng: &mut R) -> Self {
        let (public_key, secret_key) = pqcrypto_sphincsplus::sphincsshake256256srobust::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_sphincsplus::sphincsshake256256srobust::PublicKey as PqcPublicKey>::as_bytes(&self.public_key).to_vec()
    }

    /// Get the private key bytes.
    pub fn private_key_bytes(&self) -> Vec<u8> {
        <pqcrypto_sphincsplus::sphincsshake256256srobust::SecretKey as PqcSecretKey>::as_bytes(&self.secret_key).to_vec()
    }

    /// Create from private key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = <pqcrypto_sphincsplus::sphincsshake256256srobust::SecretKey as PqcSecretKey>::from_bytes(bytes)
            .map_err(|_| BottleError::InvalidKeyType)?;
        // Cannot derive public key from secret key in this API
        Err(BottleError::InvalidKeyType)
    }
}

#[cfg(feature = "post-quantum")]
impl Sign for SlhDsa256sKey {
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        let detached_sig = pqcrypto_sphincsplus::sphincsshake256256srobust::detached_sign(message, &self.secret_key);
        Ok(<pqcrypto_sphincsplus::sphincsshake256256srobust::DetachedSignature as PqcDetachedSignature>::as_bytes(&detached_sig).to_vec())
    }
}

#[cfg(feature = "post-quantum")]
impl Verify for SlhDsa256sKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let detached_sig = <pqcrypto_sphincsplus::sphincsshake256256srobust::DetachedSignature as PqcDetachedSignature>::from_bytes(signature)
            .map_err(|_| BottleError::VerifyFailed)?;
        pqcrypto_sphincsplus::sphincsshake256256srobust::verify_detached_signature(&detached_sig, message, &self.public_key)
            .map_err(|_| BottleError::VerifyFailed)?;
        Ok(())
    }
}

#[cfg(feature = "post-quantum")]
impl SignerKey for SlhDsa256sKey {
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

