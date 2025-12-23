use crate::errors::{BottleError, Result};
use crate::signing::Sign;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// An IDCard allows entities to declare sub-keys with specific purposes.
///
/// IDCards provide a way to manage multiple keys for an entity, each with
/// specific purposes (e.g., "sign", "decrypt"). Keys can have expiration
/// dates, and the IDCard can be signed to establish trust. IDCards also
/// support metadata and group memberships.
///
/// # Example
///
/// ```rust
/// use rbottle::*;
/// use rand::rngs::OsRng;
/// use std::time::Duration;
///
/// let rng = &mut OsRng;
/// let primary_key = Ed25519Key::generate(rng);
/// let mut idcard = IDCard::new(&primary_key.public_key_bytes());
///
/// idcard.set_metadata("name", "Alice");
/// idcard.set_key_purposes(&primary_key.public_key_bytes(), &["sign", "decrypt"]);
/// idcard.set_key_duration(&primary_key.public_key_bytes(), Duration::from_secs(365 * 24 * 3600));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDCard {
    /// Primary public key for this entity
    primary_key: Vec<u8>,
    /// Additional keys with their purposes and metadata, indexed by fingerprint
    keys: HashMap<Vec<u8>, KeyInfo>,
    /// Application-specific metadata (key-value pairs)
    metadata: HashMap<String, String>,
    /// Serialized group memberships this entity belongs to
    groups: Vec<Vec<u8>>,
    /// Cryptographic signature of the IDCard (if signed)
    signature: Option<Vec<u8>>,
}

/// Information about a key in an IDCard.
///
/// This structure stores the purposes a key is authorized for and its
/// expiration time, if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyInfo {
    /// List of purposes this key is authorized for (e.g., "sign", "decrypt")
    purposes: Vec<String>,
    /// Expiration time for this key (None if it doesn't expire)
    expires_at: Option<SystemTime>,
}

impl IDCard {
    /// Create a new IDCard for a public key.
    ///
    /// The primary key is automatically added with default purposes "sign"
    /// and "decrypt" and no expiration.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The primary public key for this entity
    ///
    /// # Returns
    ///
    /// A new `IDCard` instance with the primary key registered
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let idcard = IDCard::new(&key.public_key_bytes());
    /// ```
    pub fn new(public_key: &[u8]) -> Self {
        let mut keys = HashMap::new();
        let fingerprint = crate::hash::sha256(public_key);
        keys.insert(
            fingerprint,
            KeyInfo {
                purposes: vec!["sign".to_string(), "decrypt".to_string()],
                expires_at: None,
            },
        );

        Self {
            primary_key: public_key.to_vec(),
            keys,
            metadata: HashMap::new(),
            groups: Vec::new(),
            signature: None,
        }
    }

    /// Set metadata key-value pair.
    ///
    /// Metadata is application-specific data stored with the IDCard. It is
    /// not encrypted or signed, so it should not contain sensitive information.
    ///
    /// # Arguments
    ///
    /// * `key` - Metadata key
    /// * `value` - Metadata value
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let mut idcard = IDCard::new(&key.public_key_bytes());
    /// idcard.set_metadata("name", "Alice");
    /// idcard.set_metadata("email", "alice@example.com");
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
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Set the purposes for a key in the IDCard.
    ///
    /// Purposes define what operations a key is authorized for. Common
    /// purposes include "sign" and "decrypt". If the key is not already
    /// in the IDCard, it will be added.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to set purposes for
    /// * `purposes` - Array of purpose strings (e.g., ["sign", "decrypt"])
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let mut idcard = IDCard::new(&key.public_key_bytes());
    /// idcard.set_key_purposes(&key.public_key_bytes(), &["sign"]);
    /// ```
    pub fn set_key_purposes(&mut self, public_key: &[u8], purposes: &[&str]) {
        let fingerprint = crate::hash::sha256(public_key);
        let key_info = self.keys.entry(fingerprint).or_insert_with(|| KeyInfo {
            purposes: Vec::new(),
            expires_at: None,
        });
        key_info.purposes = purposes.iter().map(|s| s.to_string()).collect();
    }

    /// Set the expiration duration for a key.
    ///
    /// This sets when the key will expire from now. If the key is not already
    /// in the IDCard, it will be added with no purposes.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to set expiration for
    /// * `duration` - Duration from now until expiration
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    /// use std::time::Duration;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let mut idcard = IDCard::new(&key.public_key_bytes());
    /// idcard.set_key_duration(&key.public_key_bytes(), Duration::from_secs(365 * 24 * 3600));
    /// ```
    pub fn set_key_duration(&mut self, public_key: &[u8], duration: Duration) {
        let fingerprint = crate::hash::sha256(public_key);
        let key_info = self.keys.entry(fingerprint).or_insert_with(|| KeyInfo {
            purposes: Vec::new(),
            expires_at: None,
        });
        key_info.expires_at = Some(SystemTime::now() + duration);
    }

    /// Test if a key has a specific purpose and is not expired.
    ///
    /// This method checks both that the key has the specified purpose and
    /// that it hasn't expired (if it has an expiration date).
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to test
    /// * `purpose` - The purpose to check for (e.g., "sign")
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Key has the purpose and is not expired
    /// * `Err(BottleError::KeyNotFound)` - Key is not in the IDCard
    /// * `Err(BottleError::KeyUnfit)` - Key doesn't have the purpose or is expired
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let mut idcard = IDCard::new(&key.public_key_bytes());
    /// idcard.set_key_purposes(&key.public_key_bytes(), &["sign"]);
    ///
    /// assert!(idcard.test_key_purpose(&key.public_key_bytes(), "sign").is_ok());
    /// assert!(idcard.test_key_purpose(&key.public_key_bytes(), "decrypt").is_err());
    /// ```
    pub fn test_key_purpose(&self, public_key: &[u8], purpose: &str) -> Result<()> {
        let fingerprint = crate::hash::sha256(public_key);
        if let Some(key_info) = self.keys.get(&fingerprint) {
            // Check expiration
            if let Some(expires_at) = key_info.expires_at {
                if SystemTime::now() > expires_at {
                    return Err(BottleError::KeyUnfit);
                }
            }

            // Check purpose
            if key_info.purposes.contains(&purpose.to_string()) {
                Ok(())
            } else {
                Err(BottleError::KeyUnfit)
            }
        } else {
            Err(BottleError::KeyNotFound)
        }
    }

    /// Get all key fingerprints that have a specific purpose and are not expired.
    ///
    /// # Arguments
    ///
    /// * `purpose` - The purpose to filter by (e.g., "sign")
    ///
    /// # Returns
    ///
    /// A vector of key fingerprints (SHA-256 hashes) that have the specified
    /// purpose and are not expired
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key1 = Ed25519Key::generate(rng);
    /// let key2 = Ed25519Key::generate(rng);
    /// let mut idcard = IDCard::new(&key1.public_key_bytes());
    ///
    /// idcard.set_key_purposes(&key1.public_key_bytes(), &["sign"]);
    /// idcard.set_key_purposes(&key2.public_key_bytes(), &["decrypt"]);
    ///
    /// let sign_keys = idcard.get_keys("sign");
    /// assert_eq!(sign_keys.len(), 1);
    /// ```
    pub fn get_keys(&self, purpose: &str) -> Vec<Vec<u8>> {
        self.keys
            .iter()
            .filter(|(_, info)| {
                info.purposes.contains(&purpose.to_string())
                    && info.expires_at.map_or(true, |exp| SystemTime::now() <= exp)
            })
            .map(|(fingerprint, _)| fingerprint.clone())
            .collect()
    }

    /// Update the list of group memberships.
    ///
    /// Groups are stored as serialized membership data. This replaces the
    /// entire list of groups.
    ///
    /// # Arguments
    ///
    /// * `groups` - Vector of serialized membership data
    pub fn update_groups(&mut self, groups: Vec<Vec<u8>>) {
        self.groups = groups;
    }

    /// Sign the IDCard with a private key.
    ///
    /// This creates a cryptographic signature of the IDCard (excluding the
    /// signature field itself) and stores it. The signed IDCard is then
    /// serialized and returned.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    /// * `signer` - A signer implementing the `Sign` trait
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized signed IDCard
    /// * `Err(BottleError::Serialization)` - If serialization fails
    /// * `Err(BottleError::VerifyFailed)` - If signing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let mut idcard = IDCard::new(&key.public_key_bytes());
    ///
    /// let signed_bytes = idcard.sign(rng, &key).unwrap();
    /// ```
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign) -> Result<Vec<u8>> {
        // Create data to sign (everything except signature)
        let data_to_sign = self.create_signing_data()?;
        let signature = signer.sign(rng, &data_to_sign)?;
        self.signature = Some(signature.clone());

        // Serialize signed IDCard
        self.to_bytes()
    }

    /// Create data to sign (everything except the signature field).
    ///
    /// This serializes the IDCard with the signature field set to None,
    /// which is what gets signed.
    ///
    /// # Returns
    ///
    /// Serialized IDCard bytes without the signature
    fn create_signing_data(&self) -> Result<Vec<u8>> {
        // Serialize everything except signature
        let mut card = self.clone();
        card.signature = None;
        bincode::serialize(&card).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize IDCard: {}", e))
        })
    }

    /// Serialize the IDCard to bytes using bincode.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized IDCard bytes
    /// * `Err(BottleError::Serialization)` - If serialization fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let idcard = IDCard::new(&key.public_key_bytes());
    ///
    /// let bytes = idcard.to_bytes().unwrap();
    /// let restored = IDCard::from_bytes(&bytes).unwrap();
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize IDCard: {}", e))
        })
    }

    /// Deserialize an IDCard from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Serialized IDCard bytes (from `to_bytes`)
    ///
    /// # Returns
    ///
    /// * `Ok(IDCard)` - Deserialized IDCard
    /// * `Err(BottleError::Deserialization)` - If deserialization fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let idcard = IDCard::new(&key.public_key_bytes());
    ///
    /// let bytes = idcard.to_bytes().unwrap();
    /// let restored = IDCard::from_bytes(&bytes).unwrap();
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            BottleError::Deserialization(format!("Failed to deserialize IDCard: {}", e))
        })
    }

    /// Unmarshal from binary (alias for `from_bytes`).
    ///
    /// This is provided for compatibility with gobottle's API.
    ///
    /// # Arguments
    ///
    /// * `data` - Serialized IDCard bytes
    ///
    /// # Returns
    ///
    /// * `Ok(IDCard)` - Deserialized IDCard
    /// * `Err(BottleError::Deserialization)` - If deserialization fails
    pub fn unmarshal_binary(data: &[u8]) -> Result<Self> {
        Self::from_bytes(data)
    }
}


