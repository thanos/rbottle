use crate::ecdh::{ecdh_decrypt, ecdh_encrypt};
use crate::errors::{BottleError, Result};
use crate::signing::Sign;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Bottle is a layered message container with encryption and signatures.
///
/// Bottles support multiple layers of encryption (each for a different recipient)
/// and multiple signatures (from different signers). The encryption layers are
/// applied sequentially, with the outermost layer being the last one added.
///
/// # Example
///
/// ```rust
/// use rbottle::*;
/// use rand::rngs::OsRng;
///
/// let message = b"Secret message";
/// let mut bottle = Bottle::new(message.to_vec());
///
/// // Encrypt to multiple recipients (layered encryption)
/// let rng = &mut OsRng;
/// let bob_key = X25519Key::generate(rng);
/// let charlie_key = X25519Key::generate(rng);
///
/// // First encryption (innermost)
/// bottle.encrypt(rng, &bob_key.public_key_bytes()).unwrap();
/// // Second encryption (outermost)
/// bottle.encrypt(rng, &charlie_key.public_key_bytes()).unwrap();
///
/// // Sign the bottle
/// let alice_key = Ed25519Key::generate(rng);
/// let alice_pub = alice_key.public_key_bytes();
/// bottle.sign(rng, &alice_key, &alice_pub).unwrap();
///
/// // Serialize for storage/transmission
/// let serialized = bottle.to_bytes().unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bottle {
    /// The message payload (may be encrypted if encryption layers exist)
    message: Vec<u8>,
    /// Encryption layers (outermost first, innermost last)
    encryptions: Vec<EncryptionLayer>,
    /// Signature layers (all signers)
    signatures: Vec<SignatureLayer>,
    /// Application-specific metadata (key-value pairs)
    metadata: HashMap<String, String>,
}

/// An encryption layer in a bottle.
///
/// Each encryption layer represents one level of encryption, typically for
/// a different recipient. Layers are applied sequentially, with the
/// outermost layer being the last one added.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptionLayer {
    /// Encrypted data (ciphertext)
    ciphertext: Vec<u8>,
    /// Public key fingerprint (SHA-256 hash of recipient's public key)
    key_fingerprint: Vec<u8>,
    /// Algorithm identifier (e.g., "ECDH-AES256-GCM")
    algorithm: String,
}

/// A signature layer in a bottle.
///
/// Multiple signatures can be applied to a bottle, each from a different
/// signer. All signatures are verified independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureLayer {
    /// Signature bytes
    signature: Vec<u8>,
    /// Public key fingerprint (SHA-256 hash of signer's public key)
    key_fingerprint: Vec<u8>,
    /// Algorithm identifier (e.g., "ECDSA-SHA256", "Ed25519")
    algorithm: String,
}

/// Information about a bottle without decrypting it.
///
/// This structure provides metadata about a bottle's encryption and signature
/// status without requiring decryption keys.
///
/// # Example
///
/// ```rust
/// use rbottle::*;
///
/// let bottle = Bottle::new(b"Message".to_vec());
/// let opener = Opener::new();
/// let info = opener.open_info(&bottle).unwrap();
///
/// assert!(!info.is_encrypted);
/// assert!(!info.is_signed);
/// ```
#[derive(Debug, Clone)]
pub struct BottleInfo {
    /// Whether the bottle has any encryption layers
    pub is_encrypted: bool,
    /// Whether the bottle has any signature layers
    pub is_signed: bool,
    /// Public key fingerprints of all signers
    pub signers: Vec<Vec<u8>>,
    /// Public key fingerprints of all recipients (if encrypted)
    pub recipients: Vec<Vec<u8>>,
}

impl Bottle {
    /// Create a new bottle with a message.
    ///
    /// The message is initially unencrypted and unsigned. Encryption and
    /// signatures can be added using the `encrypt` and `sign` methods.
    ///
    /// # Arguments
    ///
    /// * `message` - The message payload to store in the bottle
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::Bottle;
    ///
    /// let bottle = Bottle::new(b"Hello, world!".to_vec());
    /// assert!(!bottle.is_encrypted());
    /// assert!(!bottle.is_signed());
    /// ```
    pub fn new(message: Vec<u8>) -> Self {
        Self {
            message,
            encryptions: Vec::new(),
            signatures: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Get the message payload.
    ///
    /// If the bottle is encrypted, this returns the encrypted ciphertext
    /// (outermost layer). Use `Opener::open` to decrypt.
    ///
    /// # Returns
    ///
    /// A reference to the message bytes (encrypted or plaintext)
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Check if the bottle has any encryption layers.
    ///
    /// # Returns
    ///
    /// `true` if the bottle has one or more encryption layers, `false` otherwise
    pub fn is_encrypted(&self) -> bool {
        !self.encryptions.is_empty()
    }

    /// Check if the bottle has any signature layers.
    ///
    /// # Returns
    ///
    /// `true` if the bottle has one or more signatures, `false` otherwise
    pub fn is_signed(&self) -> bool {
        !self.signatures.is_empty()
    }

    /// Get the number of encryption layers.
    ///
    /// Each call to `encrypt` adds a new encryption layer. Layers are
    /// applied sequentially, with the last added layer being the outermost.
    ///
    /// # Returns
    ///
    /// The number of encryption layers (0 if unencrypted)
    pub fn encryption_count(&self) -> usize {
        self.encryptions.len()
    }

    /// Encrypt the bottle to a public key.
    ///
    /// This adds a new encryption layer. If the bottle is already encrypted,
    /// the existing ciphertext is encrypted again (layered encryption).
    /// Each layer can target a different recipient.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    /// * `public_key` - The recipient's public key (X25519 or P-256 format)
    ///
    /// # Returns
    ///
    /// * `Ok(())` if encryption succeeds
    /// * `Err(BottleError::Encryption)` if encryption fails
    /// * `Err(BottleError::InvalidKeyType)` if the key format is invalid
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut bottle = Bottle::new(b"Secret".to_vec());
    /// let rng = &mut OsRng;
    /// let key = X25519Key::generate(rng);
    ///
    /// bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
    /// assert!(bottle.is_encrypted());
    /// ```
    pub fn encrypt<R: RngCore + rand::CryptoRng>(&mut self, rng: &mut R, public_key: &[u8]) -> Result<()> {
        // Determine what to encrypt
        let data_to_encrypt = if self.encryptions.is_empty() {
            // First encryption: encrypt the message directly
            self.message.clone()
        } else {
            // Additional encryption: encrypt the current message (which is already encrypted)
            self.message.clone()
        };

        // Encrypt using ECDH
        let ciphertext = ecdh_encrypt(rng, &data_to_encrypt, public_key)?;

        // Create encryption layer
        let fingerprint = crate::hash::sha256(public_key);
        let layer = EncryptionLayer {
            ciphertext: ciphertext.clone(),
            key_fingerprint: fingerprint,
            algorithm: "ECDH-AES256-GCM".to_string(),
        };

        // Replace message with the new ciphertext
        self.message = ciphertext;
        
        // Add the layer
        self.encryptions.push(layer);
        Ok(())
    }

    /// Sign the bottle with a private key.
    ///
    /// This adds a new signature layer. Multiple signers can sign the same
    /// bottle by calling this method multiple times. The signature covers
    /// the message and all encryption layers.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator (may be used for non-deterministic signing)
    /// * `signer` - A signer implementing the `Sign` trait (e.g., `Ed25519Key`, `EcdsaP256Key`)
    /// * `public_key` - The signer's public key (used for fingerprinting)
    ///
    /// # Returns
    ///
    /// * `Ok(())` if signing succeeds
    /// * `Err(BottleError::VerifyFailed)` if signing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut bottle = Bottle::new(b"Message".to_vec());
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let pub_key = key.public_key_bytes();
    ///
    /// bottle.sign(rng, &key, &pub_key).unwrap();
    /// assert!(bottle.is_signed());
    /// ```
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign, public_key: &[u8]) -> Result<()> {
        // Create data to sign (message + all encryptions)
        let data_to_sign = self.create_signing_data()?;

        // Sign the data
        let signature = signer.sign(rng, &data_to_sign)?;

        // Create signature layer
        // Use the public key to create the fingerprint
        let fingerprint = crate::hash::sha256(public_key);
        let layer = SignatureLayer {
            signature,
            key_fingerprint: fingerprint,
            algorithm: "ECDSA-SHA256".to_string(), // Will be determined from signer type
        };

        self.signatures.push(layer);
        Ok(())
    }

    /// Set metadata key-value pair.
    ///
    /// Metadata is application-specific data stored with the bottle.
    /// It is not encrypted or signed, so it should not contain sensitive
    /// information.
    ///
    /// # Arguments
    ///
    /// * `key` - Metadata key
    /// * `value` - Metadata value
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::Bottle;
    ///
    /// let mut bottle = Bottle::new(b"Message".to_vec());
    /// bottle.set_metadata("sender", "alice@example.com");
    /// bottle.set_metadata("timestamp", "2024-01-01T00:00:00Z");
    /// ```
    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Get metadata value by key.
    ///
    /// # Arguments
    ///
    /// * `key` - Metadata key to look up
    ///
    /// # Returns
    ///
    /// * `Some(&str)` if the key exists
    /// * `None` if the key is not found
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::Bottle;
    ///
    /// let mut bottle = Bottle::new(b"Message".to_vec());
    /// bottle.set_metadata("sender", "alice");
    /// assert_eq!(bottle.metadata("sender"), Some("alice"));
    /// ```
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Create data to sign (message + encryption layers).
    ///
    /// The signature covers both the message and all encryption layers
    /// to ensure integrity of the entire bottle structure.
    ///
    /// # Returns
    ///
    /// Concatenated bytes of message and all encryption ciphertexts
    fn create_signing_data(&self) -> Result<Vec<u8>> {
        let mut data = self.message.clone();
        for enc in &self.encryptions {
            data.extend_from_slice(&enc.ciphertext);
        }
        Ok(data)
    }

    /// Serialize bottle to bytes using bincode.
    ///
    /// The serialized format is binary and efficient. It includes all
    /// encryption layers, signatures, and metadata.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized bottle bytes
    /// * `Err(BottleError::Serialization)` - If serialization fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::Bottle;
    ///
    /// let bottle = Bottle::new(b"Message".to_vec());
    /// let bytes = bottle.to_bytes().unwrap();
    /// let restored = Bottle::from_bytes(&bytes).unwrap();
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize bottle: {}", e))
        })
    }

    /// Deserialize bottle from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Serialized bottle bytes (from `to_bytes`)
    ///
    /// # Returns
    ///
    /// * `Ok(Bottle)` - Deserialized bottle
    /// * `Err(BottleError::Deserialization)` - If deserialization fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::Bottle;
    ///
    /// let bottle = Bottle::new(b"Message".to_vec());
    /// let bytes = bottle.to_bytes().unwrap();
    /// let restored = Bottle::from_bytes(&bytes).unwrap();
    /// assert_eq!(bottle.message(), restored.message());
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            BottleError::Deserialization(format!("Failed to deserialize bottle: {}", e))
        })
    }
}

/// Opener for bottles.
///
/// The Opener provides methods to decrypt and inspect bottles. It can
/// decrypt bottles with multiple encryption layers, working from the
/// outermost layer inward.
///
/// # Example
///
/// ```rust
/// use rbottle::*;
/// use rand::rngs::OsRng;
///
/// let mut bottle = Bottle::new(b"Secret".to_vec());
/// let rng = &mut OsRng;
/// let key = X25519Key::generate(rng);
/// bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
///
/// let opener = Opener::new();
/// let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
/// ```
pub struct Opener {
    // Optional keychain for automatic key lookup
    // keychain: Option<Keychain>,
}

impl Opener {
    /// Create a new opener.
    ///
    /// # Returns
    ///
    /// A new `Opener` instance
    pub fn new() -> Self {
        Self {}
    }

    /// Open a bottle, decrypting if needed.
    ///
    /// This method decrypts all encryption layers sequentially, starting
    /// from the outermost layer and working inward. Each layer requires
    /// the appropriate private key.
    ///
    /// # Arguments
    ///
    /// * `bottle` - The bottle to open
    /// * `private_key` - Optional private key for decryption. Required if the bottle is encrypted.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The decrypted message
    /// * `Err(BottleError::NoAppropriateKey)` - If encryption exists but no key provided
    /// * `Err(BottleError::Decryption)` - If decryption fails
    /// * `Err(BottleError::InvalidKeyType)` - If the key format is invalid
    ///
    /// # Note
    ///
    /// For layered encryption, the same key is used for all layers in the
    /// current implementation. Future versions may support different keys
    /// per layer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let message = b"Hello, world!";
    /// let mut bottle = Bottle::new(message.to_vec());
    ///
    /// let rng = &mut OsRng;
    /// let key = X25519Key::generate(rng);
    /// bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
    ///
    /// let opener = Opener::new();
    /// let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
    /// assert_eq!(decrypted, message);
    /// ```
    pub fn open(&self, bottle: &Bottle, private_key: Option<&[u8]>) -> Result<Vec<u8>> {
        if bottle.encryptions.is_empty() {
            // No encryption, return message directly
            return Ok(bottle.message.clone());
        }

        let key = private_key.ok_or(BottleError::NoAppropriateKey)?;

        // Decrypt layers from outermost to innermost
        // The message contains the outermost ciphertext
        let mut current_data = bottle.message.clone();
        
        for _layer in bottle.encryptions.iter().rev() {
            // Decrypt this layer
            current_data = ecdh_decrypt(&current_data, key)?;
        }

        // After decrypting all layers, we have the original message
        Ok(current_data)
    }

    /// Get information about a bottle without decrypting it.
    ///
    /// This method provides metadata about encryption and signature status
    /// without requiring decryption keys. Useful for inspecting bottles
    /// before attempting to decrypt them.
    ///
    /// # Arguments
    ///
    /// * `bottle` - The bottle to inspect
    ///
    /// # Returns
    ///
    /// * `Ok(BottleInfo)` - Information about the bottle
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut bottle = Bottle::new(b"Message".to_vec());
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let pub_key = key.public_key_bytes();
    /// bottle.sign(rng, &key, &pub_key).unwrap();
    ///
    /// let opener = Opener::new();
    /// let info = opener.open_info(&bottle).unwrap();
    /// assert!(info.is_signed);
    /// assert!(info.is_signed_by(&pub_key));
    /// ```
    pub fn open_info(&self, bottle: &Bottle) -> Result<BottleInfo> {
        Ok(BottleInfo {
            is_encrypted: bottle.is_encrypted(),
            is_signed: bottle.is_signed(),
            signers: bottle.signatures.iter().map(|s| s.key_fingerprint.clone()).collect(),
            recipients: bottle.encryptions.iter().map(|e| e.key_fingerprint.clone()).collect(),
        })
    }
}

impl Default for Opener {
    fn default() -> Self {
        Self::new()
    }
}

impl BottleInfo {
    /// Check if the bottle is signed by a specific public key.
    ///
    /// This method compares the public key's fingerprint against the list
    /// of signer fingerprints in the bottle.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to check (any format)
    ///
    /// # Returns
    ///
    /// * `true` if the key's fingerprint matches a signer
    /// * `false` otherwise
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut bottle = Bottle::new(b"Message".to_vec());
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let pub_key = key.public_key_bytes();
    /// bottle.sign(rng, &key, &pub_key).unwrap();
    ///
    /// let opener = Opener::new();
    /// let info = opener.open_info(&bottle).unwrap();
    /// assert!(info.is_signed_by(&pub_key));
    /// ```
    pub fn is_signed_by(&self, public_key: &[u8]) -> bool {
        let fingerprint = crate::hash::sha256(public_key);
        self.signers.contains(&fingerprint)
    }
}

