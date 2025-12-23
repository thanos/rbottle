# rbottle API Reference

This document provides comprehensive API documentation with detailed examples for every public function and method in the rbottle library.

## Table of Contents

1. [Bottle API](#bottle-api)
2. [Opener API](#opener-api)
3. [Key Types API](#key-types-api)
4. [Post-Quantum Key Types API](#post-quantum-key-types-api)
5. [ECDH Encryption API](#ecdh-encryption-api)
6. [IDCard API](#idcard-api)
7. [Keychain API](#keychain-api)
8. [Membership API](#membership-api)
9. [Signing and Verification API](#signing-and-verification-api)
10. [Hash Functions API](#hash-functions-api)
11. [Utility Functions API](#utility-functions-api)
12. [Error Handling](#error-handling)

---

## Bottle API

The `Bottle` type is the core message container that supports layered encryption and multiple signatures.

### `Bottle::new(message: Vec<u8>) -> Bottle`

Creates a new bottle with a message payload.

**Example:**
```rust
use rbottle::Bottle;

let message = b"Hello, world!".to_vec();
let bottle = Bottle::new(message);

// Initially unencrypted and unsigned
assert!(!bottle.is_encrypted());
assert!(!bottle.is_signed());
```

### `Bottle::message(&self) -> &[u8]`

Returns a reference to the message payload. If encrypted, returns the encrypted ciphertext.

**Example:**
```rust
use rbottle::Bottle;

let bottle = Bottle::new(b"Secret message".to_vec());
let message_ref = bottle.message();
assert_eq!(message_ref, b"Secret message");
```

### `Bottle::is_encrypted(&self) -> bool`

Checks if the bottle has any encryption layers.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
assert!(!bottle.is_encrypted());

let rng = &mut OsRng;
let key = X25519Key::generate(rng);
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
assert!(bottle.is_encrypted());
```

### `Bottle::is_signed(&self) -> bool`

Checks if the bottle has any signature layers.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
assert!(!bottle.is_signed());

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let pub_key = key.public_key_bytes();
bottle.sign(rng, &key, &pub_key).unwrap();
assert!(bottle.is_signed());
```

### `Bottle::encryption_count(&self) -> usize`

Returns the number of encryption layers.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
assert_eq!(bottle.encryption_count(), 0);

let rng = &mut OsRng;
let key1 = X25519Key::generate(rng);
let key2 = X25519Key::generate(rng);

// Add first encryption layer
bottle.encrypt(rng, &key1.public_key_bytes()).unwrap();
assert_eq!(bottle.encryption_count(), 1);

// Add second encryption layer
bottle.encrypt(rng, &key2.public_key_bytes()).unwrap();
assert_eq!(bottle.encryption_count(), 2);
```

### `Bottle::encrypt<R: RngCore + CryptoRng>(&mut self, rng: &mut R, public_key: &[u8]) -> Result<()>`

Encrypts the bottle to a public key, adding a new encryption layer.

**Example - Single Encryption:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Secret message".to_vec());
let rng = &mut OsRng;
let recipient_key = X25519Key::generate(rng);

// Encrypt to recipient
bottle.encrypt(rng, &recipient_key.public_key_bytes()).unwrap();
assert!(bottle.is_encrypted());
```

**Example - Layered Encryption (Multiple Recipients):**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Multi-recipient message".to_vec());
let rng = &mut OsRng;

// Generate keys for multiple recipients
let alice_key = X25519Key::generate(rng);
let bob_key = X25519Key::generate(rng);
let charlie_key = X25519Key::generate(rng);

// Encrypt to each recipient (creates layered encryption)
bottle.encrypt(rng, &alice_key.public_key_bytes()).unwrap();
bottle.encrypt(rng, &bob_key.public_key_bytes()).unwrap();
bottle.encrypt(rng, &charlie_key.public_key_bytes()).unwrap();

assert_eq!(bottle.encryption_count(), 3);
```

**Example - Using P-256 Keys:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"P-256 encrypted message".to_vec());
let rng = &mut OsRng;
let key = EcdsaP256Key::generate(rng);

bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
assert!(bottle.is_encrypted());
```

### `Bottle::sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign, public_key: &[u8]) -> Result<()>`

Signs the bottle with a private key, adding a new signature layer.

**Example - Single Signature:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Signed message".to_vec());
let rng = &mut OsRng;
let signer_key = Ed25519Key::generate(rng);
let pub_key = signer_key.public_key_bytes();

bottle.sign(rng, &signer_key, &pub_key).unwrap();
assert!(bottle.is_signed());
```

**Example - Multiple Signatures:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Multi-signed message".to_vec());
let rng = &mut OsRng;

// Generate keys for multiple signers
let alice_key = Ed25519Key::generate(rng);
let bob_key = EcdsaP256Key::generate(rng);
let charlie_key = Ed25519Key::generate(rng);

// Each signer signs the bottle
bottle.sign(rng, &alice_key, &alice_key.public_key_bytes()).unwrap();
bottle.sign(rng, &bob_key, &bob_key.public_key_bytes()).unwrap();
bottle.sign(rng, &charlie_key, &charlie_key.public_key_bytes()).unwrap();

assert!(bottle.is_signed());

// Verify signatures
let opener = Opener::new();
let info = opener.open_info(&bottle).unwrap();
assert_eq!(info.signers.len(), 3);
```

**Example - Encrypted and Signed Bottle:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Encrypted and signed".to_vec());
let rng = &mut OsRng;

// Generate keys
let encryption_key = X25519Key::generate(rng);
let signing_key = Ed25519Key::generate(rng);
let signing_pub = signing_key.public_key_bytes();

// Encrypt first
bottle.encrypt(rng, &encryption_key.public_key_bytes()).unwrap();

// Then sign
bottle.sign(rng, &signing_key, &signing_pub).unwrap();

assert!(bottle.is_encrypted());
assert!(bottle.is_signed());
```

### `Bottle::set_metadata(&mut self, key: &str, value: &str)`

Sets a metadata key-value pair. Metadata is not encrypted or signed.

**Example:**
```rust
use rbottle::Bottle;

let mut bottle = Bottle::new(b"Message".to_vec());

bottle.set_metadata("sender", "alice@example.com");
bottle.set_metadata("timestamp", "2024-01-01T00:00:00Z");
bottle.set_metadata("subject", "Important message");
bottle.set_metadata("priority", "high");

// Retrieve metadata
assert_eq!(bottle.metadata("sender"), Some("alice@example.com"));
assert_eq!(bottle.metadata("timestamp"), Some("2024-01-01T00:00:00Z"));
```

### `Bottle::metadata(&self, key: &str) -> Option<&str>`

Retrieves a metadata value by key.

**Example:**
```rust
use rbottle::Bottle;

let mut bottle = Bottle::new(b"Message".to_vec());
bottle.set_metadata("sender", "alice");

match bottle.metadata("sender") {
    Some(value) => println!("Sender: {}", value),
    None => println!("No sender metadata"),
}

// Non-existent key returns None
assert_eq!(bottle.metadata("nonexistent"), None);
```

### `Bottle::to_bytes(&self) -> Result<Vec<u8>>`

Serializes the bottle to bytes using bincode.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
let rng = &mut OsRng;
let key = X25519Key::generate(rng);
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

// Serialize for storage or transmission
let serialized = bottle.to_bytes().unwrap();

// Save to file, send over network, etc.
// std::fs::write("bottle.bin", &serialized).unwrap();
```

### `Bottle::from_bytes(data: &[u8]) -> Result<Bottle>`

Deserializes a bottle from bytes.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

// Create and serialize a bottle
let mut bottle = Bottle::new(b"Message".to_vec());
let rng = &mut OsRng;
let key = X25519Key::generate(rng);
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
let serialized = bottle.to_bytes().unwrap();

// Deserialize
let deserialized = Bottle::from_bytes(&serialized).unwrap();
assert_eq!(bottle.message(), deserialized.message());
assert_eq!(bottle.encryption_count(), deserialized.encryption_count());
```

---

## Opener API

The `Opener` type provides methods to decrypt and inspect bottles.

### `Opener::new() -> Opener`

Creates a new opener instance.

**Example:**
```rust
use rbottle::Opener;

let opener = Opener::new();
```

### `Opener::open(&self, bottle: &Bottle, private_key: Option<&[u8]>) -> Result<Vec<u8>>`

Opens a bottle, decrypting all encryption layers if needed.

**Example - Opening Unencrypted Bottle:**
```rust
use rbottle::*;

let bottle = Bottle::new(b"Plain message".to_vec());
let opener = Opener::new();

// No key needed for unencrypted bottles
let message = opener.open(&bottle, None).unwrap();
assert_eq!(message, b"Plain message");
```

**Example - Opening Encrypted Bottle:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Secret message".to_vec());
let rng = &mut OsRng;
let key = X25519Key::generate(rng);

// Encrypt
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

// Decrypt
let opener = Opener::new();
let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
assert_eq!(decrypted, b"Secret message");
```

**Example - Opening Layered Encrypted Bottle:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Layered message".to_vec());
let rng = &mut OsRng;
let key = X25519Key::generate(rng);

// Add multiple encryption layers
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

// Decrypt all layers
let opener = Opener::new();
let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
assert_eq!(decrypted, b"Layered message");
```

**Example - Error Handling:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Secret".to_vec());
let rng = &mut OsRng;
let key = X25519Key::generate(rng);
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

let opener = Opener::new();

// Wrong key fails
let wrong_key = X25519Key::generate(rng);
match opener.open(&bottle, Some(&wrong_key.private_key_bytes())) {
    Ok(_) => panic!("Should have failed"),
    Err(e) => println!("Decryption failed: {:?}", e),
}

// Missing key for encrypted bottle fails
match opener.open(&bottle, None) {
    Ok(_) => panic!("Should have failed"),
    Err(BottleError::NoAppropriateKey) => println!("Correct error"),
    Err(e) => panic!("Wrong error: {:?}", e),
}
```

### `Opener::open_info(&self, bottle: &Bottle) -> Result<BottleInfo>`

Gets information about a bottle without decrypting it.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
let rng = &mut OsRng;

// Encrypt
let enc_key = X25519Key::generate(rng);
bottle.encrypt(rng, &enc_key.public_key_bytes()).unwrap();

// Sign
let sig_key = Ed25519Key::generate(rng);
let sig_pub = sig_key.public_key_bytes();
bottle.sign(rng, &sig_key, &sig_pub).unwrap();

// Get info without decrypting
let opener = Opener::new();
let info = opener.open_info(&bottle).unwrap();

assert!(info.is_encrypted);
assert!(info.is_signed);
assert_eq!(info.recipients.len(), 1);
assert_eq!(info.signers.len(), 1);
```

### `BottleInfo::is_signed_by(&self, public_key: &[u8]) -> bool`

Checks if the bottle is signed by a specific public key.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
let rng = &mut OsRng;
let signer_key = Ed25519Key::generate(rng);
let pub_key = signer_key.public_key_bytes();

bottle.sign(rng, &signer_key, &pub_key).unwrap();

let opener = Opener::new();
let info = opener.open_info(&bottle).unwrap();

// Check if signed by specific key
assert!(info.is_signed_by(&pub_key));

// Different key returns false
let other_key = Ed25519Key::generate(rng);
assert!(!info.is_signed_by(&other_key.public_key_bytes()));
```

---

## Key Types API

The library provides classical key types: `EcdsaP256Key`, `Ed25519Key`, and `X25519Key`. Post-quantum key types are available with feature flags (see [Post-Quantum Key Types API](#post-quantum-key-types-api)).

### ECDSA P-256 Keys

#### `EcdsaP256Key::generate<R: RngCore + CryptoRng>(rng: &mut R) -> EcdsaP256Key`

Generates a new ECDSA P-256 key pair.

**Example:**
```rust
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = EcdsaP256Key::generate(rng);
```

#### `EcdsaP256Key::public_key_bytes(&self) -> Vec<u8>`

Gets the public key in SEC1 uncompressed format (65 bytes).

**Example:**
```rust
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = EcdsaP256Key::generate(rng);
let pub_key = key.public_key_bytes();
assert_eq!(pub_key.len(), 65); // SEC1 uncompressed format
```

#### `EcdsaP256Key::private_key_bytes(&self) -> Vec<u8>`

Gets the private key bytes (32 bytes).

**Example:**
```rust
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = EcdsaP256Key::generate(rng);
let priv_key = key.private_key_bytes();
assert_eq!(priv_key.len(), 32);
```

#### `EcdsaP256Key::from_private_key_bytes(bytes: &[u8]) -> Result<EcdsaP256Key>`

Reconstructs a key pair from private key bytes.

**Example:**
```rust
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let original = EcdsaP256Key::generate(rng);
let priv_bytes = original.private_key_bytes();

// Reconstruct from private key
let restored = EcdsaP256Key::from_private_key_bytes(&priv_bytes).unwrap();
assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
```

### Ed25519 Keys

#### `Ed25519Key::generate<R: RngCore + CryptoRng>(rng: &mut R) -> Ed25519Key`

Generates a new Ed25519 key pair.

**Example:**
```rust
use rbottle::keys::Ed25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
```

#### `Ed25519Key::public_key_bytes(&self) -> Vec<u8>`

Gets the public key bytes (32 bytes).

**Example:**
```rust
use rbottle::keys::Ed25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let pub_key = key.public_key_bytes();
assert_eq!(pub_key.len(), 32);
```

#### `Ed25519Key::private_key_bytes(&self) -> Vec<u8>`

Gets the private key bytes (32 bytes).

**Example:**
```rust
use rbottle::keys::Ed25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let priv_key = key.private_key_bytes();
assert_eq!(priv_key.len(), 32);
```

#### `Ed25519Key::from_private_key_bytes(bytes: &[u8]) -> Result<Ed25519Key>`

Reconstructs a key pair from private key bytes.

**Example:**
```rust
use rbottle::keys::Ed25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let original = Ed25519Key::generate(rng);
let priv_bytes = original.private_key_bytes();

let restored = Ed25519Key::from_private_key_bytes(&priv_bytes).unwrap();
assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
```

### X25519 Keys

#### `X25519Key::generate<R: RngCore>(rng: &mut R) -> X25519Key`

Generates a new X25519 key pair for ECDH encryption.

**Example:**
```rust
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = X25519Key::generate(rng);
```

#### `X25519Key::public_key_bytes(&self) -> Vec<u8>`

Gets the public key bytes (32 bytes).

**Example:**
```rust
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = X25519Key::generate(rng);
let pub_key = key.public_key_bytes();
assert_eq!(pub_key.len(), 32);
```

#### `X25519Key::private_key_bytes(&self) -> Vec<u8>`

Gets the private key bytes (32 bytes).

**Example:**
```rust
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = X25519Key::generate(rng);
let priv_key = key.private_key_bytes();
assert_eq!(priv_key.len(), 32);
```

#### `X25519Key::from_private_key_bytes(bytes: &[u8]) -> Result<X25519Key>`

Reconstructs a key pair from private key bytes.

**Example:**
```rust
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let original = X25519Key::generate(rng);
let priv_bytes = original.private_key_bytes();

let restored = X25519Key::from_private_key_bytes(&priv_bytes).unwrap();
assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
```

---

## ECDH Encryption API

Direct ECDH encryption functions for encrypting data to public keys. Supports both classical and post-quantum key types with automatic detection.

### `ecdh_encrypt<R: RngCore + CryptoRng>(rng: &mut R, plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>>`

Encrypts plaintext to a public key using ECDH with automatic key type detection.

**Example - X25519 Encryption:**
```rust
use rbottle::ecdh::ecdh_encrypt;
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;

let plaintext = b"Secret message";
let rng = &mut OsRng;

// Generate keys
let alice_key = X25519Key::generate(rng);
let bob_key = X25519Key::generate(rng);

// Alice encrypts to Bob
let ciphertext = ecdh_encrypt(rng, plaintext, &bob_key.public_key_bytes()).unwrap();

// Bob decrypts
use rbottle::ecdh::ecdh_decrypt;
let decrypted = ecdh_decrypt(&ciphertext, &bob_key.private_key_bytes()).unwrap();
assert_eq!(decrypted, plaintext);
```

**Example - P-256 Encryption:**
```rust
use rbottle::ecdh::ecdh_encrypt;
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;

let plaintext = b"P-256 encrypted message";
let rng = &mut OsRng;

let key = EcdsaP256Key::generate(rng);
let ciphertext = ecdh_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();

use rbottle::ecdh::ecdh_decrypt;
let decrypted = ecdh_decrypt(&ciphertext, &key.private_key_bytes()).unwrap();
assert_eq!(decrypted, plaintext);
```

### `ecdh_decrypt(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>>`

Decrypts ciphertext using a private key with automatic key type detection. Supports X25519, P-256, ML-KEM-768, and ML-KEM-1024.

**Example - Classical Keys:**
```rust
use rbottle::ecdh::{ecdh_encrypt, ecdh_decrypt};
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;

let plaintext = b"Message to encrypt";
let rng = &mut OsRng;
let key = X25519Key::generate(rng);

// Encrypt
let ciphertext = ecdh_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();

// Decrypt
let decrypted = ecdh_decrypt(&ciphertext, &key.private_key_bytes()).unwrap();
assert_eq!(decrypted, plaintext);
```

**Example - Post-Quantum Keys:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::{ecdh_encrypt, ecdh_decrypt};
use rbottle::keys::MlKem768Key;
use rand::rngs::OsRng;

let plaintext = b"Post-quantum encrypted";
let rng = &mut OsRng;
let key = MlKem768Key::generate(rng);

// Automatically detects ML-KEM-768 from key size
let ciphertext = ecdh_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
let decrypted = ecdh_decrypt(&ciphertext, &key.private_key_bytes()).unwrap();
assert_eq!(decrypted, plaintext);
```

### `ecdh_encrypt_p256<R: RngCore + CryptoRng>(rng: &mut R, plaintext: &[u8], public_key: &PublicKey) -> Result<Vec<u8>>`

Encrypts using P-256 ECDH (lower-level function).

**Example:**
```rust
use rbottle::ecdh::ecdh_encrypt_p256;
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;
use p256::PublicKey;

let rng = &mut OsRng;
let key = EcdsaP256Key::generate(rng);
let pub_key = PublicKey::from_sec1_bytes(&key.public_key_bytes()).unwrap();

let plaintext = b"P-256 encrypted";
let ciphertext = ecdh_encrypt_p256(rng, plaintext, &pub_key).unwrap();
```

### `ecdh_decrypt_p256(ciphertext: &[u8], private_key: &SecretKey) -> Result<Vec<u8>>`

Decrypts using P-256 ECDH (lower-level function).

**Example:**
```rust
use rbottle::ecdh::{ecdh_encrypt_p256, ecdh_decrypt_p256};
use rbottle::keys::EcdsaP256Key;
use rand::rngs::OsRng;
use p256::{PublicKey, SecretKey};

let rng = &mut OsRng;
let key = EcdsaP256Key::generate(rng);
let pub_key = PublicKey::from_sec1_bytes(&key.public_key_bytes()).unwrap();
let priv_key = SecretKey::from_bytes(&key.private_key_bytes().as_slice().into()).unwrap();

let plaintext = b"Message";
let ciphertext = ecdh_encrypt_p256(rng, plaintext, &pub_key).unwrap();
let decrypted = ecdh_decrypt_p256(&ciphertext, &priv_key).unwrap();
assert_eq!(decrypted, plaintext);
```

### `ecdh_encrypt_x25519<R: RngCore>(rng: &mut R, plaintext: &[u8], public_key: &X25519PublicKey) -> Result<Vec<u8>>`

Encrypts using X25519 ECDH (lower-level function).

**Example:**
```rust
use rbottle::ecdh::ecdh_encrypt_x25519;
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;
use x25519_dalek::PublicKey;

let rng = &mut OsRng;
let key = X25519Key::generate(rng);
let pub_key_bytes: [u8; 32] = key.public_key_bytes().try_into().unwrap();
let pub_key = PublicKey::from(pub_key_bytes);

let plaintext = b"X25519 encrypted";
let ciphertext = ecdh_encrypt_x25519(rng, plaintext, &pub_key).unwrap();
```

### `ecdh_decrypt_x25519(ciphertext: &[u8], private_key: &[u8; 32]) -> Result<Vec<u8>>`

Decrypts using X25519 ECDH (lower-level function).

**Example:**
```rust
use rbottle::ecdh::{ecdh_encrypt_x25519, ecdh_decrypt_x25519};
use rbottle::keys::X25519Key;
use rand::rngs::OsRng;
use x25519_dalek::PublicKey;

let rng = &mut OsRng;
let key = X25519Key::generate(rng);
let pub_key_bytes: [u8; 32] = key.public_key_bytes().try_into().unwrap();
let pub_key = PublicKey::from(pub_key_bytes);
let priv_key_bytes: [u8; 32] = key.private_key_bytes().try_into().unwrap();

let plaintext = b"Message";
let ciphertext = ecdh_encrypt_x25519(rng, plaintext, &pub_key).unwrap();
let decrypted = ecdh_decrypt_x25519(&ciphertext, &priv_key_bytes).unwrap();
assert_eq!(decrypted, plaintext);
```

### Post-Quantum Encryption Functions

#### `mlkem768_encrypt<R: RngCore + CryptoRng>(rng: &mut R, plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>>`

Encrypts plaintext using ML-KEM-768 key encapsulation. Requires `ml-kem` feature.

**Example:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::mlkem768_encrypt;
use rbottle::keys::MlKem768Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem768Key::generate(rng);
let plaintext = b"Secret message";

let ciphertext = mlkem768_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
```

#### `mlkem768_decrypt(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>`

Decrypts ciphertext encrypted with ML-KEM-768. Requires `ml-kem` feature.

**Example:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::{mlkem768_encrypt, mlkem768_decrypt};
use rbottle::keys::MlKem768Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem768Key::generate(rng);
let plaintext = b"Secret message";

let ciphertext = mlkem768_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
let decrypted = mlkem768_decrypt(&ciphertext, &key.private_key_bytes()).unwrap();
assert_eq!(decrypted, plaintext);
```

#### `mlkem1024_encrypt<R: RngCore + CryptoRng>(rng: &mut R, plaintext: &[u8], public_key: &[u8]) -> Result<Vec<u8>>`

Encrypts plaintext using ML-KEM-1024 key encapsulation. Requires `ml-kem` feature.

**Example:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::mlkem1024_encrypt;
use rbottle::keys::MlKem1024Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem1024Key::generate(rng);
let plaintext = b"Secret message";

let ciphertext = mlkem1024_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
```

#### `mlkem1024_decrypt(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>`

Decrypts ciphertext encrypted with ML-KEM-1024. Requires `ml-kem` feature.

**Example:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::{mlkem1024_encrypt, mlkem1024_decrypt};
use rbottle::keys::MlKem1024Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem1024Key::generate(rng);
let plaintext = b"Secret message";

let ciphertext = mlkem1024_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
let decrypted = mlkem1024_decrypt(&ciphertext, &key.private_key_bytes()).unwrap();
assert_eq!(decrypted, plaintext);
```

#### `hybrid_encrypt_mlkem768_x25519<R: RngCore + CryptoRng>(rng: &mut R, plaintext: &[u8], mlkem_pub: &[u8], x25519_pub: &[u8]) -> Result<Vec<u8>>`

Hybrid encryption combining ML-KEM-768 and X25519 for both post-quantum and classical security. Requires `ml-kem` feature.

**Example:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::hybrid_encrypt_mlkem768_x25519;
use rbottle::keys::{MlKem768Key, X25519Key};
use rand::rngs::OsRng;

let rng = &mut OsRng;
let mlkem_key = MlKem768Key::generate(rng);
let x25519_key = X25519Key::generate(rng);
let plaintext = b"Hybrid encrypted";

let ciphertext = hybrid_encrypt_mlkem768_x25519(
    rng,
    plaintext,
    &mlkem_key.public_key_bytes(),
    &x25519_key.public_key_bytes(),
).unwrap();
```

#### `hybrid_decrypt_mlkem768_x25519(ciphertext: &[u8], mlkem_sec: &[u8], x25519_sec: &[u8; 32]) -> Result<Vec<u8>>`

Decrypts hybrid-encrypted ciphertext. Tries ML-KEM first, falls back to X25519. Requires `ml-kem` feature.

**Example:**
```rust
#[cfg(feature = "ml-kem")]
use rbottle::ecdh::{hybrid_encrypt_mlkem768_x25519, hybrid_decrypt_mlkem768_x25519};
use rbottle::keys::{MlKem768Key, X25519Key};
use rand::rngs::OsRng;

let rng = &mut OsRng;
let mlkem_key = MlKem768Key::generate(rng);
let x25519_key = X25519Key::generate(rng);
let plaintext = b"Hybrid encrypted";

let ciphertext = hybrid_encrypt_mlkem768_x25519(
    rng,
    plaintext,
    &mlkem_key.public_key_bytes(),
    &x25519_key.public_key_bytes(),
).unwrap();

let mlkem_sec = mlkem_key.private_key_bytes();
let x25519_sec: [u8; 32] = x25519_key.private_key_bytes().try_into().unwrap();
let decrypted = hybrid_decrypt_mlkem768_x25519(&ciphertext, &mlkem_sec, &x25519_sec).unwrap();
assert_eq!(decrypted, plaintext);
```

---

## IDCard API

IDCards allow entities to declare keys with specific purposes and manage key lifecycles.

### `IDCard::new(public_key: &[u8]) -> IDCard`

Creates a new IDCard for a public key.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let idcard = IDCard::new(&key.public_key_bytes());
```

### `IDCard::set_metadata(&mut self, key: &str, value: &str)`

Sets a metadata key-value pair.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let mut idcard = IDCard::new(&key.public_key_bytes());

idcard.set_metadata("name", "Alice");
idcard.set_metadata("email", "alice@example.com");
idcard.set_metadata("organization", "Example Corp");
idcard.set_metadata("department", "Engineering");
```

### `IDCard::metadata(&self, key: &str) -> Option<&str>`

Gets a metadata value by key.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let mut idcard = IDCard::new(&key.public_key_bytes());

idcard.set_metadata("name", "Alice");
assert_eq!(idcard.metadata("name"), Some("Alice"));
assert_eq!(idcard.metadata("nonexistent"), None);
```

### `IDCard::set_key_purposes(&mut self, public_key: &[u8], purposes: &[&str])`

Sets the purposes for a key (e.g., "sign", "decrypt").

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let primary_key = Ed25519Key::generate(rng);
let mut idcard = IDCard::new(&primary_key.public_key_bytes());

// Set purposes for primary key
idcard.set_key_purposes(&primary_key.public_key_bytes(), &["sign", "decrypt"]);

// Add a dedicated signing key
let signing_key = Ed25519Key::generate(rng);
idcard.set_key_purposes(&signing_key.public_key_bytes(), &["sign"]);

// Add a dedicated encryption key
let encryption_key = X25519Key::generate(rng);
idcard.set_key_purposes(&encryption_key.public_key_bytes(), &["decrypt"]);
```

### `IDCard::set_key_duration(&mut self, public_key: &[u8], duration: Duration)`

Sets the expiration duration for a key.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;
use std::time::Duration;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let mut idcard = IDCard::new(&key.public_key_bytes());

// Set key to expire in 1 year
idcard.set_key_duration(&key.public_key_bytes(), Duration::from_secs(365 * 24 * 3600));

// Set key to expire in 30 days
let temp_key = Ed25519Key::generate(rng);
idcard.set_key_duration(&temp_key.public_key_bytes(), Duration::from_secs(30 * 24 * 3600));
```

### `IDCard::test_key_purpose(&self, public_key: &[u8], purpose: &str) -> Result<()>`

Tests if a key has a specific purpose and is not expired.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let signing_key = Ed25519Key::generate(rng);
let encryption_key = X25519Key::generate(rng);
let mut idcard = IDCard::new(&signing_key.public_key_bytes());

idcard.set_key_purposes(&signing_key.public_key_bytes(), &["sign"]);
idcard.set_key_purposes(&encryption_key.public_key_bytes(), &["decrypt"]);

// Test purposes
assert!(idcard.test_key_purpose(&signing_key.public_key_bytes(), "sign").is_ok());
assert!(idcard.test_key_purpose(&encryption_key.public_key_bytes(), "decrypt").is_ok());

// Wrong purpose fails
assert!(idcard.test_key_purpose(&signing_key.public_key_bytes(), "decrypt").is_err());
assert!(idcard.test_key_purpose(&encryption_key.public_key_bytes(), "sign").is_err());
```

### `IDCard::get_keys(&self, purpose: &str) -> Vec<Vec<u8>>`

Gets all key fingerprints that have a specific purpose and are not expired.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key1 = Ed25519Key::generate(rng);
let key2 = Ed25519Key::generate(rng);
let key3 = X25519Key::generate(rng);
let mut idcard = IDCard::new(&key1.public_key_bytes());

idcard.set_key_purposes(&key1.public_key_bytes(), &["sign"]);
idcard.set_key_purposes(&key2.public_key_bytes(), &["sign"]);
idcard.set_key_purposes(&key3.public_key_bytes(), &["decrypt"]);

// Get all signing keys
let sign_keys = idcard.get_keys("sign");
assert_eq!(sign_keys.len(), 2);

// Get all decryption keys
let decrypt_keys = idcard.get_keys("decrypt");
assert_eq!(decrypt_keys.len(), 2); // Includes primary key
```

### `IDCard::update_groups(&mut self, groups: Vec<Vec<u8>>)`

Updates the list of group memberships.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let group_key = Ed25519Key::generate(rng);

let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_idcard = IDCard::new(&group_key.public_key_bytes());

// Create a membership
let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
membership.set_info("role", "member");
let signed_membership = membership.sign(rng, &group_key).unwrap();

// Add membership to member's IDCard
let mut member_idcard = IDCard::new(&member_key.public_key_bytes());
member_idcard.update_groups(vec![signed_membership]);
```

### `IDCard::sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign) -> Result<Vec<u8>>`

Signs the IDCard and returns the serialized signed IDCard.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let mut idcard = IDCard::new(&key.public_key_bytes());

idcard.set_metadata("name", "Alice");
idcard.set_key_purposes(&key.public_key_bytes(), &["sign", "decrypt"]);

// Sign the IDCard
let signed_bytes = idcard.sign(rng, &key).unwrap();

// The IDCard is now signed
assert!(idcard.signature.is_some());
```

### `IDCard::to_bytes(&self) -> Result<Vec<u8>>`

Serializes the IDCard to bytes.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let idcard = IDCard::new(&key.public_key_bytes());

let serialized = idcard.to_bytes().unwrap();
```

### `IDCard::from_bytes(data: &[u8]) -> Result<IDCard>`

Deserializes an IDCard from bytes.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let idcard = IDCard::new(&key.public_key_bytes());

let serialized = idcard.to_bytes().unwrap();
let restored = IDCard::from_bytes(&serialized).unwrap();
```

### `IDCard::unmarshal_binary(data: &[u8]) -> Result<IDCard>`

Alias for `from_bytes` (for compatibility with gobottle).

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let idcard = IDCard::new(&key.public_key_bytes());

let serialized = idcard.to_bytes().unwrap();
let restored = IDCard::unmarshal_binary(&serialized).unwrap();
```

---

## Keychain API

Keychains provide secure storage for private keys.

### `Keychain::new() -> Keychain`

Creates a new empty keychain.

**Example:**
```rust
use rbottle::Keychain;

let keychain = Keychain::new();
```

### `Keychain::add_key<K: SignerKey + 'static>(&mut self, key: K)`

Adds a key to the keychain.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;

let ed25519_key = Ed25519Key::generate(rng);
let ecdsa_key = EcdsaP256Key::generate(rng);
let x25519_key = X25519Key::generate(rng);

keychain.add_key(ed25519_key);
keychain.add_key(ecdsa_key);
keychain.add_key(x25519_key);
```

### `Keychain::add_keys<K: SignerKey + 'static>(&mut self, keys: Vec<K>)`

Adds multiple keys of the same type to the keychain.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;

let key1 = Ed25519Key::generate(rng);
let key2 = Ed25519Key::generate(rng);
let key3 = Ed25519Key::generate(rng);

keychain.add_keys(vec![key1, key2, key3]);
```

### `Keychain::get_key(&self, public_key: &[u8]) -> Result<&dyn SignerKey>`

Gets a key by its public key.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let pub_key = key.public_key_bytes();

keychain.add_key(key);
let retrieved = keychain.get_key(&pub_key).unwrap();
assert_eq!(retrieved.public_key(), pub_key);
```

### `Keychain::get_signer(&self, public_key: &[u8]) -> Result<&dyn SignerKey>`

Gets a signer by its public key (alias for `get_key`).

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let pub_key = key.public_key_bytes();

keychain.add_key(key);
let signer = keychain.get_signer(&pub_key).unwrap();
```

### `Keychain::sign<R: RngCore>(&self, rng: &mut R, public_key: &[u8], message: &[u8]) -> Result<Vec<u8>>`

Signs a message with a specific key from the keychain.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let pub_key = key.public_key_bytes();

keychain.add_key(key);

let message = b"Message to sign";
let signature = keychain.sign(rng, &pub_key, message).unwrap();
```

### `Keychain::signers(&self) -> impl Iterator<Item = &dyn SignerKey>`

Iterates over all signers in the keychain.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;

let key1 = Ed25519Key::generate(rng);
let key2 = EcdsaP256Key::generate(rng);
let key3 = Ed25519Key::generate(rng);

keychain.add_key(key1);
keychain.add_key(key2);
keychain.add_key(key3);

// Iterate over all keys
for signer in keychain.signers() {
    let pub_key = signer.public_key();
    let fingerprint = signer.fingerprint();
    println!("Key: {:?}, Fingerprint: {:?}", pub_key, fingerprint);
}
```

---

## Membership API

Memberships provide cryptographically signed group affiliations.

### `Membership::new(member_idcard: &IDCard, group_public_key: &[u8]) -> Membership`

Creates a new membership linking a member to a group.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());

let group_key = Ed25519Key::generate(rng);
let membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
```

### `Membership::set_info(&mut self, key: &str, value: &str)`

Sets information about the membership (e.g., role, department).

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_key = Ed25519Key::generate(rng);

let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
membership.set_info("role", "admin");
membership.set_info("department", "Engineering");
membership.set_info("joined", "2024-01-01");
membership.set_info("level", "senior");
```

### `Membership::info(&self, key: &str) -> Option<&str>`

Gets information value by key.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_key = Ed25519Key::generate(rng);

let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
membership.set_info("role", "admin");

assert_eq!(membership.info("role"), Some("admin"));
assert_eq!(membership.info("nonexistent"), None);
```

### `Membership::sign<R: RngCore>(&mut self, rng: &mut R, signer: &dyn Sign) -> Result<Vec<u8>>`

Signs the membership and returns the serialized signed membership.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_key = Ed25519Key::generate(rng);

let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
membership.set_info("role", "admin");

// Group owner signs the membership
let signed_bytes = membership.sign(rng, &group_key).unwrap();
```

### `Membership::verify(&self, group_idcard: &IDCard) -> Result<()>`

Verifies the membership signature (simplified implementation).

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_key = Ed25519Key::generate(rng);
let group_idcard = IDCard::new(&group_key.public_key_bytes());

let mut membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
membership.sign(rng, &group_key).unwrap();

// Verify membership
assert!(membership.verify(&group_idcard).is_ok());
```

### `Membership::to_bytes(&self) -> Result<Vec<u8>>`

Serializes the membership to bytes.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_key = Ed25519Key::generate(rng);

let membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
let serialized = membership.to_bytes().unwrap();
```

### `Membership::from_bytes(data: &[u8]) -> Result<Membership>`

Deserializes a membership from bytes.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let member_key = Ed25519Key::generate(rng);
let member_idcard = IDCard::new(&member_key.public_key_bytes());
let group_key = Ed25519Key::generate(rng);

let membership = Membership::new(&member_idcard, &group_key.public_key_bytes());
let serialized = membership.to_bytes().unwrap();
let restored = Membership::from_bytes(&serialized).unwrap();
```

---

## Signing and Verification API

The `Sign` and `Verify` traits provide generic signing and verification operations.

### `Sign::sign(&self, rng: &mut dyn RngCore, message: &[u8]) -> Result<Vec<u8>>`

Signs a message (trait method).

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let message = b"Message to sign";

let signature = key.sign(rng, message).unwrap();
```

### `Verify::verify(&self, message: &[u8], signature: &[u8]) -> Result<()>`

Verifies a signature (trait method).

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let message = b"Message to sign";

let signature = key.sign(rng, message).unwrap();
assert!(key.verify(message, &signature).is_ok());

// Wrong message fails
assert!(key.verify(b"Different message", &signature).is_err());
```

### `sign<R: RngCore, S: Sign>(rng: &mut R, signer: &S, message: &[u8]) -> Result<Vec<u8>>`

Generic sign function.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let message = b"Message";

let signature = rbottle::sign(rng, &key, message).unwrap();
```

### `verify<V: Verify>(verifier: &V, message: &[u8], signature: &[u8]) -> Result<()>`

Generic verify function.

**Example:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let message = b"Message";
let signature = key.sign(rng, message).unwrap();

assert!(rbottle::verify(&key, message, &signature).is_ok());
```

---

## Hash Functions API

The library provides various hashing functions for SHA-2 and SHA-3.

### `sha256(data: &[u8]) -> Vec<u8>`

Hashes data using SHA-256.

**Example:**
```rust
use rbottle::hash::sha256;

let data = b"Hello, world!";
let hash = sha256(data);
assert_eq!(hash.len(), 32);

// Used for key fingerprinting
let key_bytes = b"public key bytes";
let fingerprint = sha256(key_bytes);
```

### `sha384(data: &[u8]) -> Vec<u8>`

Hashes data using SHA-384.

**Example:**
```rust
use rbottle::hash::sha384;

let data = b"Hello, world!";
let hash = sha384(data);
assert_eq!(hash.len(), 48);
```

### `sha512(data: &[u8]) -> Vec<u8>`

Hashes data using SHA-512.

**Example:**
```rust
use rbottle::hash::sha512;

let data = b"Hello, world!";
let hash = sha512(data);
assert_eq!(hash.len(), 64);
```

### `sha3_256(data: &[u8]) -> Vec<u8>`

Hashes data using SHA3-256.

**Example:**
```rust
use rbottle::hash::sha3_256;

let data = b"Hello, world!";
let hash = sha3_256(data);
assert_eq!(hash.len(), 32);
```

### `sha3_384(data: &[u8]) -> Vec<u8>`

Hashes data using SHA3-384.

**Example:**
```rust
use rbottle::hash::sha3_384;

let data = b"Hello, world!";
let hash = sha3_384(data);
assert_eq!(hash.len(), 48);
```

### `sha3_512(data: &[u8]) -> Vec<u8>`

Hashes data using SHA3-512.

**Example:**
```rust
use rbottle::hash::sha3_512;

let data = b"Hello, world!";
let hash = sha3_512(data);
assert_eq!(hash.len(), 64);
```

### `hash<D: Digest>(data: &[u8]) -> Vec<u8>`

Generic hash function that works with any Digest type.

**Example:**
```rust
use rbottle::hash::hash;
use sha2::Sha256;

let data = b"Hello, world!";
let hash = hash::<Sha256>(data);
assert_eq!(hash.len(), 32);
```

### `multi_hash<D: Digest>(data: &[u8], levels: usize) -> Vec<u8>`

Applies hashing multiple times.

**Example:**
```rust
use rbottle::hash::multi_hash;
use sha2::Sha256;

let data = b"Hello, world!";
let hash = multi_hash::<Sha256>(data, 3); // Hash 3 times
```

---

## Utility Functions API

### `mem_clr(data: &mut [u8])`

Securely clears sensitive data from memory.

**Example:**
```rust
use rbottle::utils::mem_clr;

let mut sensitive = vec![1, 2, 3, 4, 5];
mem_clr(&mut sensitive);
// sensitive is now all zeros
```

---

## Error Handling

All operations return `Result<T, BottleError>`. The `BottleError` enum covers all error conditions.

### Error Types

- `BottleError::NoAppropriateKey` - No key available for decryption
- `BottleError::VerifyFailed` - Signature verification failed
- `BottleError::KeyNotFound` - Key not found in keychain/IDCard
- `BottleError::KeyUnfit` - Key not authorized for the operation
- `BottleError::InvalidKeyType` - Invalid key format
- `BottleError::Serialization` - Serialization error
- `BottleError::Deserialization` - Deserialization error
- `BottleError::Encryption` - Encryption error
- `BottleError::Decryption` - Decryption error
- `BottleError::InvalidFormat` - Invalid data format
- `BottleError::UnsupportedAlgorithm` - Algorithm not supported

**Example - Error Handling:**
```rust
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Message".to_vec());
let rng = &mut OsRng;
let key = X25519Key::generate(rng);
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

let opener = Opener::new();

// Handle errors properly
match opener.open(&bottle, None) {
    Ok(message) => println!("Decrypted: {:?}", message),
    Err(BottleError::NoAppropriateKey) => println!("No key provided"),
    Err(BottleError::Decryption(e)) => println!("Decryption failed: {}", e),
    Err(e) => println!("Other error: {:?}", e),
}
```

---

## Complete Example: End-to-End Communication

Here's a complete example showing Alice and Bob communicating securely:

```rust
use rbottle::*;
use rand::rngs::OsRng;

fn main() -> Result<()> {
    let rng = &mut OsRng;

    // Alice sets up
    let alice_signing_key = Ed25519Key::generate(rng);
    let alice_encryption_key = X25519Key::generate(rng);
    let alice_idcard = IDCard::new(&alice_signing_key.public_key_bytes());
    alice_idcard.set_metadata("name", "Alice");
    alice_idcard.set_key_purposes(&alice_signing_key.public_key_bytes(), &["sign"]);
    alice_idcard.set_key_purposes(&alice_encryption_key.public_key_bytes(), &["decrypt"]);

    // Bob sets up
    let bob_signing_key = Ed25519Key::generate(rng);
    let bob_encryption_key = X25519Key::generate(rng);
    let bob_idcard = IDCard::new(&bob_signing_key.public_key_bytes());
    bob_idcard.set_metadata("name", "Bob");
    bob_idcard.set_key_purposes(&bob_signing_key.public_key_bytes(), &["sign"]);
    bob_idcard.set_key_purposes(&bob_encryption_key.public_key_bytes(), &["decrypt"]);

    // Alice creates and sends a message
    let message = b"Hello, Bob! This is a secret message.";
    let mut bottle = Bottle::new(message.to_vec());
    
    // Encrypt to Bob
    bottle.encrypt(rng, &bob_encryption_key.public_key_bytes())?;
    
    // Sign with Alice's key
    bottle.sign(rng, &alice_signing_key, &alice_signing_key.public_key_bytes())?;
    
    // Add metadata
    bottle.set_metadata("from", "alice@example.com");
    bottle.set_metadata("to", "bob@example.com");
    bottle.set_metadata("subject", "Secret message");

    // Serialize for transmission
    let serialized = bottle.to_bytes()?;

    // Bob receives and processes the message
    let received_bottle = Bottle::from_bytes(&serialized)?;
    
    // Check who signed it
    let opener = Opener::new();
    let info = opener.open_info(&received_bottle)?;
    assert!(info.is_signed_by(&alice_signing_key.public_key_bytes()));
    
    // Decrypt
    let decrypted = opener.open(&received_bottle, Some(&bob_encryption_key.private_key_bytes()))?;
    assert_eq!(decrypted, message);
    
    println!("Message received: {:?}", String::from_utf8_lossy(&decrypted));
    println!("From: {}", received_bottle.metadata("from").unwrap());
    println!("Subject: {}", received_bottle.metadata("subject").unwrap());

    Ok(())
}
```

This comprehensive API reference covers all public functions and methods in the rbottle library with detailed, working examples.

