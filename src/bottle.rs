use crate::ecdh::{ecdh_decrypt, ecdh_encrypt};
use crate::errors::{BottleError, Result};
use crate::signing::Sign;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Bottle is a layered message container with encryption and signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bottle {
    /// The message payload (may be encrypted)
    message: Vec<u8>,
    /// Encryption layers (outermost first)
    encryptions: Vec<EncryptionLayer>,
    /// Signature layers
    signatures: Vec<SignatureLayer>,
    /// Metadata
    metadata: HashMap<String, String>,
}

/// An encryption layer
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptionLayer {
    /// Encrypted data
    ciphertext: Vec<u8>,
    /// Public key fingerprint (for identification)
    key_fingerprint: Vec<u8>,
    /// Algorithm identifier
    algorithm: String,
}

/// A signature layer
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureLayer {
    /// Signature bytes
    signature: Vec<u8>,
    /// Public key fingerprint
    key_fingerprint: Vec<u8>,
    /// Algorithm identifier
    algorithm: String,
}

/// Information about an opened bottle
#[derive(Debug, Clone)]
pub struct BottleInfo {
    /// Whether the bottle is encrypted
    pub is_encrypted: bool,
    /// Whether the bottle is signed
    pub is_signed: bool,
    /// Signers' public key fingerprints
    pub signers: Vec<Vec<u8>>,
    /// Recipients' public key fingerprints (if encrypted)
    pub recipients: Vec<Vec<u8>>,
}

impl Bottle {
    /// Create a new bottle with a message
    pub fn new(message: Vec<u8>) -> Self {
        Self {
            message,
            encryptions: Vec::new(),
            signatures: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Get the message (may be encrypted)
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Check if the bottle is encrypted
    pub fn is_encrypted(&self) -> bool {
        !self.encryptions.is_empty()
    }

    /// Check if the bottle is signed
    pub fn is_signed(&self) -> bool {
        !self.signatures.is_empty()
    }

    /// Get the number of encryption layers
    pub fn encryption_count(&self) -> usize {
        self.encryptions.len()
    }

    /// Encrypt the bottle to a public key
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

    /// Sign the bottle with a private key
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

    /// Set metadata
    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Get metadata
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Create data to sign (message + encryption layers)
    fn create_signing_data(&self) -> Result<Vec<u8>> {
        let mut data = self.message.clone();
        for enc in &self.encryptions {
            data.extend_from_slice(&enc.ciphertext);
        }
        Ok(data)
    }

    /// Serialize bottle to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize bottle: {}", e))
        })
    }

    /// Deserialize bottle from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            BottleError::Deserialization(format!("Failed to deserialize bottle: {}", e))
        })
    }
}

/// Opener for bottles
pub struct Opener {
    // Optional keychain for automatic key lookup
    // keychain: Option<Keychain>,
}

impl Opener {
    /// Create a new opener
    pub fn new() -> Self {
        Self {}
    }

    /// Open a bottle (decrypt if needed)
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

    /// Get information about a bottle without opening it
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
    /// Check if signed by a specific public key (by fingerprint)
    pub fn is_signed_by(&self, public_key: &[u8]) -> bool {
        let fingerprint = crate::hash::sha256(public_key);
        self.signers.contains(&fingerprint)
    }
}

