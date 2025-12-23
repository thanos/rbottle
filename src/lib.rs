//! # rbottle
//!
//! Rust implementation of the Bottle protocol - layered message containers
//! with encryption and signatures.
//!
//! This library provides functionality similar to [gobottle](https://github.com/BottleFmt/gobottle),
//! including support for multiple key types, IDCards, Keychains, and Memberships.
//!
//! ## Overview
//!
//! The Bottle protocol provides a secure way to package messages with multiple layers
//! of encryption and signatures. Each encryption layer can target a different recipient,
//! and multiple signers can sign the same bottle. This enables complex security
//! scenarios like group messaging, multi-party encryption, and verifiable data
//! structures.
//!
//! ## Core Concepts
//!
//! - **Bottles**: Layered message containers that support multiple encryption and signature layers
//! - **IDCards**: Declarations of keys with specific purposes (sign, decrypt) and lifecycle management
//! - **Keychains**: Secure storage for private keys, indexed by public key fingerprints
//! - **Memberships**: Cryptographically signed group affiliations with role information
//!
//! ## Example
//!
//! ```rust
//! use rbottle::*;
//! use rand::rngs::OsRng;
//!
//! // Create and encrypt a message
//! let message = b"Hello, Bottle!";
//! let mut bottle = Bottle::new(message.to_vec());
//!
//! let rng = &mut OsRng;
//! let key = X25519Key::generate(rng);
//! bottle.encrypt(rng, &key.public_key_bytes()).unwrap();
//!
//! // Decrypt
//! let opener = Opener::new();
//! let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
//! assert_eq!(decrypted, message);
//! ```

pub mod bottle;
pub mod ecdh;
pub mod errors;
pub mod hash;
pub mod idcard;
pub mod keychain;
pub mod keys;
pub mod membership;
pub mod signing;
pub mod utils;

/// Core bottle types for message containers
pub use bottle::{Bottle, Opener};

/// Error types and result aliases
pub use errors::{BottleError, Result};

/// IDCard for key management
pub use idcard::IDCard;

/// Keychain for secure key storage
pub use keychain::Keychain;

/// Membership for group affiliations
pub use membership::Membership;

/// Signing and verification traits
pub use signing::{Sign, Verify};

/// ECDH encryption and decryption functions
pub use ecdh::{ecdh_encrypt, ecdh_decrypt, ECDHEncrypt, ECDHDecrypt};

/// Cryptographic key types
pub use keys::{EcdsaP256Key, Ed25519Key, X25519Key};

