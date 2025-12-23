use crate::errors::{BottleError, Result};
use crate::idcard::IDCard;
use crate::signing::Sign;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Membership provides cryptographically signed group affiliations.
///
/// Memberships link a member (via their IDCard) to a group (via the group's
/// public key). They can contain additional information like roles and are
/// cryptographically signed by the group owner to prove authenticity.
///
/// # Example
///
/// ```rust
/// use rust_bottle::*;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let member_key = Ed25519Key::generate(rng);
/// let member_idcard = IDCard::new(&member_key.public_key_bytes());
///
/// let group_key = Ed25519Key::generate(rng);
/// let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
/// membership.set_info("role", "admin");
///
/// let signed = membership.sign(rng, &group_key).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    /// Member's IDCard (serialized)
    member_idcard: Vec<u8>, // Serialized IDCard
    /// Group's public key (identifies the group)
    group_public_key: Vec<u8>,
    /// Additional information (e.g., role, department)
    info: HashMap<String, String>,
    /// Cryptographic signature (if signed)
    signature: Option<Vec<u8>>,
}

impl Membership {
    /// Create a new membership linking a member to a group.
    ///
    /// # Arguments
    ///
    /// * `member_idcard` - The member's IDCard
    /// * `group_public_key` - The group's public key
    ///
    /// # Returns
    ///
    /// A new `Membership` instance (not yet signed)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let member_key = Ed25519Key::generate(rng);
    /// let member_idcard = IDCard::new(&member_key.public_key_bytes());
    ///
    /// let group_key = Ed25519Key::generate(rng);
    /// let membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
    /// ```
    pub fn new(member_idcard: &IDCard, group_public_key: &[u8]) -> Self {
        Self {
            member_idcard: member_idcard
                .to_bytes()
                .unwrap_or_default(), // Should handle error properly
            group_public_key: group_public_key.to_vec(),
            info: HashMap::new(),
            signature: None,
        }
    }

    /// Set information key-value pair.
    ///
    /// Information fields can store application-specific data like roles,
    /// departments, or other metadata about the membership.
    ///
    /// # Arguments
    ///
    /// * `key` - Information key
    /// * `value` - Information value
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let member_key = Ed25519Key::generate(rng);
    /// let member_idcard = IDCard::new(&member_key.public_key_bytes());
    /// let group_key = Ed25519Key::generate(rng);
    ///
    /// let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
    /// membership.set_info("role", "admin");
    /// membership.set_info("department", "Engineering");
    /// ```
    pub fn set_info(&mut self, key: &str, value: &str) {
        self.info.insert(key.to_string(), value.to_string());
    }

    /// Get information value by key.
    ///
    /// # Arguments
    ///
    /// * `key` - Information key to look up
    ///
    /// # Returns
    ///
    /// * `Some(&str)` if the key exists
    /// * `None` if the key is not found
    pub fn info(&self, key: &str) -> Option<&str> {
        self.info.get(key).map(|s| s.as_str())
    }

    /// Sign the membership with a private key.
    ///
    /// This creates a cryptographic signature of the membership (excluding
    /// the signature field itself) and stores it. The signed membership is
    /// then serialized and returned.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    /// * `signer` - A signer implementing the `Sign` trait (typically the group owner's key)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized signed membership
    /// * `Err(BottleError::Serialization)` - If serialization fails
    /// * `Err(BottleError::VerifyFailed)` - If signing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rust_bottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let rng = &mut OsRng;
    /// let member_key = Ed25519Key::generate(rng);
    /// let member_idcard = IDCard::new(&member_key.public_key_bytes());
    /// let group_key = Ed25519Key::generate(rng);
    ///
    /// let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
    /// let signed = membership.sign(rng, &group_key).unwrap();
    /// ```
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign) -> Result<Vec<u8>> {
        let data_to_sign = self.create_signing_data()?;
        let signature = signer.sign(rng, &data_to_sign)?;
        self.signature = Some(signature.clone());

        // Return serialized membership
        self.to_bytes()
    }

    /// Verify the membership signature.
    ///
    /// # Note
    ///
    /// This is a simplified implementation that only checks for the presence
    /// of a signature. Full verification would require extracting the signing
    /// key from the group's IDCard and verifying the signature cryptographically.
    ///
    /// # Arguments
    ///
    /// * `_group_idcard` - The group's IDCard (currently not used)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If signature exists
    /// * `Err(BottleError::VerifyFailed)` - If signature is missing
    pub fn verify(&self, _group_idcard: &IDCard) -> Result<()> {
        // Verify signature using group's public key
        // This is a simplified version - in practice, we'd extract the signing key from the IDCard
        if self.signature.is_none() {
            return Err(BottleError::VerifyFailed);
        }

        // For now, just check that signature exists
        // Full verification would require the group's private key or a verifier
        Ok(())
    }

    /// Create data to sign (everything except the signature field).
    ///
    /// This serializes the membership with the signature field set to None,
    /// which is what gets signed.
    ///
    /// # Returns
    ///
    /// Serialized membership bytes without the signature
    fn create_signing_data(&self) -> Result<Vec<u8>> {
        let mut membership = self.clone();
        membership.signature = None;
        bincode::serialize(&membership).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize membership: {}", e))
        })
    }

    /// Serialize the membership to bytes using bincode.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Serialized membership bytes
    /// * `Err(BottleError::Serialization)` - If serialization fails
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize membership: {}", e))
        })
    }

    /// Deserialize a membership from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Serialized membership bytes (from `to_bytes`)
    ///
    /// # Returns
    ///
    /// * `Ok(Membership)` - Deserialized membership
    /// * `Err(BottleError::Deserialization)` - If deserialization fails
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            BottleError::Deserialization(format!("Failed to deserialize membership: {}", e))
        })
    }
}


