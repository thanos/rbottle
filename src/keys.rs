use crate::errors::{BottleError, Result};
use crate::signing::{Sign, Verify};
use crate::keychain::SignerKey;
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey, Signature};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use rand::{CryptoRng, RngCore};

/// ECDSA P-256 key pair
pub struct EcdsaP256Key {
    signing_key: P256SigningKey,
    verifying_key: P256VerifyingKey,
}

impl EcdsaP256Key {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing_key = P256SigningKey::random(rng);
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_sec1_bytes().to_vec()
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Create from private key bytes
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
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

/// Ed25519 key pair
pub struct Ed25519Key {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl Ed25519Key {
    /// Generate a new Ed25519 key pair
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing_key = Ed25519SigningKey::generate(rng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key: verifying_key.clone(),
        }
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    /// Create from private key bytes
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
    fn sign(&self, _rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

impl Verify for Ed25519Key {
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
    fn fingerprint(&self) -> Vec<u8> {
        crate::hash::sha256(&self.public_key_bytes())
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes()
    }
}

/// X25519 key pair for ECDH
pub struct X25519Key {
    secret: [u8; 32], // Store as bytes since StaticSecret doesn't exist in 2.0
    public: x25519_dalek::PublicKey,
}

impl X25519Key {
    /// Generate a new X25519 key pair
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

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public.as_bytes().to_vec()
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    /// Create from private key bytes
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

