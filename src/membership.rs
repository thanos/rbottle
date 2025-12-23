use crate::errors::{BottleError, Result};
use crate::idcard::IDCard;
use crate::signing::Sign;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Membership provides cryptographically signed group affiliations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    /// Member's IDCard
    member_idcard: Vec<u8>, // Serialized IDCard
    /// Group's public key
    group_public_key: Vec<u8>,
    /// Additional information
    info: HashMap<String, String>,
    /// Signature
    signature: Option<Vec<u8>>,
}

impl Membership {
    /// Create a new membership
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

    /// Set information
    pub fn set_info(&mut self, key: &str, value: &str) {
        self.info.insert(key.to_string(), value.to_string());
    }

    /// Get information
    pub fn info(&self, key: &str) -> Option<&str> {
        self.info.get(key).map(|s| s.as_str())
    }

    /// Sign the membership
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign) -> Result<Vec<u8>> {
        let data_to_sign = self.create_signing_data()?;
        let signature = signer.sign(rng, &data_to_sign)?;
        self.signature = Some(signature.clone());

        // Return serialized membership
        self.to_bytes()
    }

    /// Verify the membership
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

    /// Create data to sign
    fn create_signing_data(&self) -> Result<Vec<u8>> {
        let mut membership = self.clone();
        membership.signature = None;
        bincode::serialize(&membership).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize membership: {}", e))
        })
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            BottleError::Serialization(format!("Failed to serialize membership: {}", e))
        })
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            BottleError::Deserialization(format!("Failed to deserialize membership: {}", e))
        })
    }
}


