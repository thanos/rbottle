use crate::errors::{BottleError, Result};
use crate::signing::Sign;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// An IDCard allows entities to declare sub-keys with specific purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDCard {
    /// Primary public key
    primary_key: Vec<u8>,
    /// Additional keys with their purposes
    keys: HashMap<Vec<u8>, KeyInfo>,
    /// Metadata
    metadata: HashMap<String, String>,
    /// Groups this entity belongs to
    groups: Vec<Vec<u8>>,
    /// Signature (if signed)
    signature: Option<Vec<u8>>,
}

/// Information about a key in an IDCard
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyInfo {
    /// Purposes this key is authorized for
    purposes: Vec<String>,
    /// Expiration time (if any)
    expires_at: Option<SystemTime>,
}

impl IDCard {
    /// Create a new IDCard for a public key
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

    /// Set metadata
    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Get metadata
    pub fn metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Set key purposes
    pub fn set_key_purposes(&mut self, public_key: &[u8], purposes: &[&str]) {
        let fingerprint = crate::hash::sha256(public_key);
        let key_info = self.keys.entry(fingerprint).or_insert_with(|| KeyInfo {
            purposes: Vec::new(),
            expires_at: None,
        });
        key_info.purposes = purposes.iter().map(|s| s.to_string()).collect();
    }

    /// Set key duration/expiration
    pub fn set_key_duration(&mut self, public_key: &[u8], duration: Duration) {
        let fingerprint = crate::hash::sha256(public_key);
        let key_info = self.keys.entry(fingerprint).or_insert_with(|| KeyInfo {
            purposes: Vec::new(),
            expires_at: None,
        });
        key_info.expires_at = Some(SystemTime::now() + duration);
    }

    /// Test if a key has a specific purpose
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

    /// Get all keys for a purpose
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

    /// Update groups
    pub fn update_groups(&mut self, groups: Vec<Vec<u8>>) {
        self.groups = groups;
    }

    /// Sign the IDCard
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign) -> Result<Vec<u8>> {
        // Create data to sign (everything except signature)
        let data_to_sign = self.create_signing_data()?;
        let signature = signer.sign(rng, &data_to_sign)?;
        self.signature = Some(signature.clone());

        // Serialize signed IDCard
        self.to_bytes()
    }

    /// Create data to sign
    fn create_signing_data(&self) -> Result<Vec<u8>> {
        // Serialize everything except signature
        let mut card = self.clone();
        card.signature = None;
        bincode::serialize(&card).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize IDCard: {}", e))
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize IDCard: {}", e))
        })
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            BottleError::Deserialization(format!("Failed to deserialize IDCard: {}", e))
        })
    }

    /// Unmarshal from binary (alias for from_bytes)
    pub fn unmarshal_binary(data: &[u8]) -> Result<Self> {
        Self::from_bytes(data)
    }
}


