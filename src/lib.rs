//! # rbottle
//!
//! Rust implementation of the Bottle protocol - layered message containers
//! with encryption and signatures.
//!
//! This library provides functionality similar to [gobottle](https://github.com/BottleFmt/gobottle),
//! including support for multiple key types, IDCards, Keychains, and Memberships.

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

pub use bottle::{Bottle, Opener};
pub use errors::{BottleError, Result};
pub use idcard::IDCard;
pub use keychain::Keychain;
pub use membership::Membership;
pub use signing::{Sign, Verify};

// Re-export commonly used types
pub use ecdh::{ecdh_encrypt, ecdh_decrypt, ECDHEncrypt, ECDHDecrypt};
pub use keys::{EcdsaP256Key, Ed25519Key, X25519Key};

