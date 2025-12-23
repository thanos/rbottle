use crate::errors::{BottleError, Result};
use crate::signing::Sign;
use rand::RngCore;
use std::collections::HashMap;

/// A keychain provides secure storage for private keys.
///
/// Keychains store private keys indexed by their public key fingerprints,
/// allowing easy lookup and signing operations. Keys must implement the
/// `SignerKey` trait, which includes both `Sign` and key identification
/// methods.
///
/// # Example
///
/// ```rust
/// use rbottle::*;
/// use rand::rngs::OsRng;
///
/// let mut keychain = Keychain::new();
/// let rng = &mut OsRng;
///
/// let key1 = Ed25519Key::generate(rng);
/// let key2 = EcdsaP256Key::generate(rng);
///
/// keychain.add_key(key1);
/// keychain.add_key(key2);
///
/// let pub_key = keychain.signers().next().unwrap().public_key();
/// let signature = keychain.sign(rng, &pub_key, b"Message").unwrap();
/// ```
pub struct Keychain {
    /// Keys indexed by their public key fingerprint (SHA-256 hash)
    keys: HashMap<Vec<u8>, Box<dyn SignerKey>>,
}

/// Trait for keys that can be stored in a keychain.
///
/// This trait extends `Sign` with methods for key identification. All key
/// types in rbottle implement this trait, allowing them to be stored in
/// keychains.
///
/// # Requirements
///
/// * `Sign`: Must be able to sign messages
/// * `Send + Sync`: Must be safe to send across threads
pub trait SignerKey: Sign + Send + Sync {
    /// Get the public key fingerprint (SHA-256 hash of public key).
    ///
    /// The fingerprint is used as the key in the keychain's internal
    /// HashMap for fast lookup.
    ///
    /// # Returns
    ///
    /// SHA-256 hash of the public key bytes
    fn fingerprint(&self) -> Vec<u8>;
    /// Get the public key bytes.
    ///
    /// # Returns
    ///
    /// Public key bytes in the key's native format
    fn public_key(&self) -> Vec<u8>;
}

impl Keychain {
    /// Create a new empty keychain.
    ///
    /// # Returns
    ///
    /// A new `Keychain` instance with no keys
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::Keychain;
    ///
    /// let keychain = Keychain::new();
    /// ```
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a key to the keychain.
    ///
    /// The key is indexed by its public key fingerprint. If a key with the
    /// same fingerprint already exists, it will be replaced.
    ///
    /// # Arguments
    ///
    /// * `key` - A key implementing `SignerKey` (e.g., `Ed25519Key`, `EcdsaP256Key`)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut keychain = Keychain::new();
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    ///
    /// keychain.add_key(key);
    /// ```
    pub fn add_key<K: SignerKey + 'static>(&mut self, key: K) {
        let fingerprint = key.fingerprint();
        self.keys.insert(fingerprint, Box::new(key));
    }

    /// Add multiple keys to the keychain at once.
    ///
    /// # Arguments
    ///
    /// * `keys` - A vector of keys to add
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut keychain = Keychain::new();
    /// let rng = &mut OsRng;
    /// let key1 = Ed25519Key::generate(rng);
    /// let key2 = Ed25519Key::generate(rng);
    ///
    /// keychain.add_keys(vec![key1, key2]);
    /// ```
    pub fn add_keys<K: SignerKey + 'static>(&mut self, keys: Vec<K>) {
        for key in keys {
            self.add_key(key);
        }
    }

    /// Get a key by its public key.
    ///
    /// The public key is hashed to find the corresponding private key in
    /// the keychain.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to look up
    ///
    /// # Returns
    ///
    /// * `Ok(&dyn SignerKey)` - Reference to the key
    /// * `Err(BottleError::KeyNotFound)` - If the key is not in the keychain
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut keychain = Keychain::new();
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let pub_key = key.public_key_bytes();
    ///
    /// keychain.add_key(key);
    /// let retrieved = keychain.get_key(&pub_key).unwrap();
    /// ```
    pub fn get_key(&self, public_key: &[u8]) -> Result<&dyn SignerKey> {
        let fingerprint = crate::hash::sha256(public_key);
        self.keys
            .get(&fingerprint)
            .map(|k| k.as_ref())
            .ok_or(BottleError::KeyNotFound)
    }

    /// Get a signer by its public key (alias for `get_key`).
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to look up
    ///
    /// # Returns
    ///
    /// * `Ok(&dyn SignerKey)` - Reference to the signer
    /// * `Err(BottleError::KeyNotFound)` - If the key is not in the keychain
    pub fn get_signer(&self, public_key: &[u8]) -> Result<&dyn SignerKey> {
        self.get_key(public_key)
    }

    /// Sign a message with a specific key from the keychain.
    ///
    /// This is a convenience method that looks up the key and signs the
    /// message in one operation.
    ///
    /// # Arguments
    ///
    /// * `rng` - A random number generator
    /// * `public_key` - The public key of the key to use for signing
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Signature bytes
    /// * `Err(BottleError::KeyNotFound)` - If the key is not in the keychain
    /// * `Err(BottleError::VerifyFailed)` - If signing fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut keychain = Keychain::new();
    /// let rng = &mut OsRng;
    /// let key = Ed25519Key::generate(rng);
    /// let pub_key = key.public_key_bytes();
    ///
    /// keychain.add_key(key);
    /// let signature = keychain.sign(rng, &pub_key, b"Message").unwrap();
    /// ```
    pub fn sign<R: RngCore>(
        &self,
        rng: &mut R,
        public_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let signer = self.get_signer(public_key)?;
        signer.sign(rng as &mut dyn RngCore, message)
    }

    /// Iterate over all signers in the keychain.
    ///
    /// # Returns
    ///
    /// An iterator over all stored keys (as `&dyn SignerKey`)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rbottle::*;
    /// use rand::rngs::OsRng;
    ///
    /// let mut keychain = Keychain::new();
    /// let rng = &mut OsRng;
    /// let key1 = Ed25519Key::generate(rng);
    /// let key2 = EcdsaP256Key::generate(rng);
    ///
    /// keychain.add_key(key1);
    /// keychain.add_key(key2);
    ///
    /// for signer in keychain.signers() {
    ///     let pub_key = signer.public_key();
    ///     println!("Key: {:?}", pub_key);
    /// }
    /// ```
    pub fn signers(&self) -> impl Iterator<Item = &dyn SignerKey> {
        self.keys.values().map(|k| k.as_ref())
    }
}

impl Default for Keychain {
    fn default() -> Self {
        Self::new()
    }
}


