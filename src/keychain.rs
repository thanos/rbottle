use crate::errors::{BottleError, Result};
use crate::signing::Sign;
use rand::RngCore;
use std::collections::HashMap;

/// A keychain provides secure storage for private keys
pub struct Keychain {
    /// Keys indexed by their public key fingerprint
    keys: HashMap<Vec<u8>, Box<dyn SignerKey>>,
}

/// Trait for keys that can be stored in a keychain
pub trait SignerKey: Sign + Send + Sync {
    /// Get the public key fingerprint
    fn fingerprint(&self) -> Vec<u8>;
    /// Get the public key bytes
    fn public_key(&self) -> Vec<u8>;
}

impl Keychain {
    /// Create a new keychain
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a key to the keychain
    pub fn add_key<K: SignerKey + 'static>(&mut self, key: K) {
        let fingerprint = key.fingerprint();
        self.keys.insert(fingerprint, Box::new(key));
    }

    /// Add multiple keys at once
    pub fn add_keys<K: SignerKey + 'static>(&mut self, keys: Vec<K>) {
        for key in keys {
            self.add_key(key);
        }
    }

    /// Get a key by public key
    pub fn get_key(&self, public_key: &[u8]) -> Result<&dyn SignerKey> {
        let fingerprint = crate::hash::sha256(public_key);
        self.keys
            .get(&fingerprint)
            .map(|k| k.as_ref())
            .ok_or(BottleError::KeyNotFound)
    }

    /// Get a signer by public key
    pub fn get_signer(&self, public_key: &[u8]) -> Result<&dyn SignerKey> {
        self.get_key(public_key)
    }

    /// Sign with a specific key
    pub fn sign<R: RngCore>(
        &self,
        rng: &mut R,
        public_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let signer = self.get_signer(public_key)?;
        signer.sign(rng as &mut dyn RngCore, message)
    }

    /// Iterate over signers
    pub fn signers(&self) -> impl Iterator<Item = &dyn SignerKey> {
        self.keys.values().map(|k| k.as_ref())
    }
}

impl Default for Keychain {
    fn default() -> Self {
        Self::new()
    }
}


