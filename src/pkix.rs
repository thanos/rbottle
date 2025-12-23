//! PKIX/PKCS#8 Key Serialization
//!
//! This module provides functions to marshal and unmarshal cryptographic keys
//! in standard PKIX (SubjectPublicKeyInfo) and PKCS#8 formats. These formats
//! enable interoperability with other cryptographic tools and libraries.
//!
//! # Supported Formats
//!
//! - **PKCS#8**: Private key format (RFC 5208)
//! - **PKIX/SPKI**: Public key format (RFC 5280)
//! - **PEM**: Base64-encoded DER with headers/footers
//! - **DER**: Binary ASN.1 encoding
//!
//! # Example
//!
//! ```rust
//! use rust_bottle::keys::EcdsaP256Key;
//! use rust_bottle::pkix;
//! use rand::rngs::OsRng;
//!
//! let rng = &mut OsRng;
//! let key = EcdsaP256Key::generate(rng);
//!
//! // Marshal public key to PKIX format
//! let pkix_der = pkix::marshal_pkix_public_key(&key.public_key_bytes()).unwrap();
//! let pkix_pem = pkix::marshal_pkix_public_key_pem(&key.public_key_bytes()).unwrap();
//!
//! // Marshal private key to PKCS#8 format
//! let pkcs8_der = pkix::marshal_pkcs8_private_key(&key.private_key_bytes(), pkix::KeyType::EcdsaP256).unwrap();
//! let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(&key.private_key_bytes(), pkix::KeyType::EcdsaP256).unwrap();
//!
//! // Unmarshal keys
//! let pub_key = pkix::parse_pkix_public_key(&pkix_der).unwrap();
//! let priv_key = pkix::parse_pkcs8_private_key(&pkcs8_der, pkix::KeyType::EcdsaP256).unwrap();
//! ```

use crate::errors::{BottleError, Result};
use const_oid::{ObjectIdentifier, db::rfc5912};
use der::{Decode, Encode};
use pkcs8::{AlgorithmIdentifierRef, PrivateKeyInfo};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Key type identifier for PKCS#8/PKIX serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// ECDSA P-256 (secp256r1)
    EcdsaP256,
    /// ECDSA P-384 (secp384r1)
    EcdsaP384,
    /// ECDSA P-521 (secp521r1)
    EcdsaP521,
    /// Ed25519
    Ed25519,
    /// X25519
    X25519,
    /// RSA (PKCS#1)
    Rsa,
    /// ML-KEM-768 (requires `ml-kem` feature)
    #[cfg(feature = "ml-kem")]
    MlKem768,
    /// ML-KEM-1024 (requires `ml-kem` feature)
    #[cfg(feature = "ml-kem")]
    MlKem1024,
    /// ML-DSA-44 (requires `post-quantum` feature)
    #[cfg(feature = "post-quantum")]
    MlDsa44,
    /// ML-DSA-65 (requires `post-quantum` feature)
    #[cfg(feature = "post-quantum")]
    MlDsa65,
    /// ML-DSA-87 (requires `post-quantum` feature)
    #[cfg(feature = "post-quantum")]
    MlDsa87,
    /// SLH-DSA-128s (requires `post-quantum` feature)
    #[cfg(feature = "post-quantum")]
    SlhDsa128s,
    /// SLH-DSA-192s (requires `post-quantum` feature)
    #[cfg(feature = "post-quantum")]
    SlhDsa192s,
    /// SLH-DSA-256s (requires `post-quantum` feature)
    #[cfg(feature = "post-quantum")]
    SlhDsa256s,
}

impl KeyType {
    /// Get the OID (Object Identifier) for this key type
    fn oid(&self) -> ObjectIdentifier {
        match self {
            KeyType::EcdsaP256 => rfc5912::ID_EC_PUBLIC_KEY, // ecPublicKey
            KeyType::EcdsaP384 => rfc5912::ID_EC_PUBLIC_KEY, // ecPublicKey
            KeyType::EcdsaP521 => rfc5912::ID_EC_PUBLIC_KEY, // ecPublicKey
            KeyType::Ed25519 => ObjectIdentifier::new("1.3.101.112").expect("Invalid Ed25519 OID"),         // Ed25519
            KeyType::X25519 => ObjectIdentifier::new("1.3.101.110").expect("Invalid X25519 OID"),          // X25519
            KeyType::Rsa => rfc5912::RSA_ENCRYPTION,     // rsaEncryption
            #[cfg(feature = "ml-kem")]
            KeyType::MlKem768 | KeyType::MlKem1024 => {
                // ML-KEM OID (NIST standard) - placeholder, actual OID may differ
                // Using a temporary OID structure - update with official OID when available
                // Note: This is a placeholder OID - update when NIST publishes official OIDs
                ObjectIdentifier::new("1.3.6.1.4.1.2.267.7.6.5").expect("Invalid ML-KEM OID")
            }
            #[cfg(feature = "post-quantum")]
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
                // ML-DSA OID (NIST standard) - placeholder, actual OID may differ
                // Note: This is a placeholder OID - update when NIST publishes official OIDs
                ObjectIdentifier::new("1.3.6.1.4.1.2.267.7.4.4").expect("Invalid ML-DSA OID")
            }
            #[cfg(feature = "post-quantum")]
            KeyType::SlhDsa128s | KeyType::SlhDsa192s | KeyType::SlhDsa256s => {
                // SLH-DSA OID (NIST standard) - placeholder, actual OID may differ
                // Note: This is a placeholder OID - update when NIST publishes official OIDs
                ObjectIdentifier::new("1.3.6.1.4.1.2.267.1.16.7").expect("Invalid SLH-DSA OID")
            }
        }
    }

    /// Get the curve OID for ECDSA keys
    #[allow(dead_code)]
    fn curve_oid(&self) -> Option<&'static [u32]> {
        match self {
            KeyType::EcdsaP256 => Some(&[1, 2, 840, 10045, 3, 1, 7]), // prime256v1
            KeyType::EcdsaP384 => Some(&[1, 3, 132, 0, 34]),         // secp384r1
            KeyType::EcdsaP521 => Some(&[1, 3, 132, 0, 35]),         // secp521r1
            _ => None,
        }
    }
}

/// Marshal a public key to PKIX (SubjectPublicKeyInfo) format in DER encoding.
///
/// This function encodes a public key in the standard PKIX format, which is
/// compatible with OpenSSL, other cryptographic libraries, and tools.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw public key bytes (format depends on key type)
/// * `key_type` - The type of key being marshaled
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - DER-encoded PKIX public key
/// * `Err(BottleError)` - If encoding fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rust_bottle::pkix;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pkix_der = pkix::marshal_pkix_public_key(&key.public_key_bytes()).unwrap();
/// ```
pub fn marshal_pkix_public_key(public_key_bytes: &[u8]) -> Result<Vec<u8>> {
    // Try to detect key type from the bytes
    let key_type = detect_key_type_from_public_key(public_key_bytes)?;
    marshal_pkix_public_key_with_type(public_key_bytes, key_type)
}

/// Marshal a public key to PKIX format with explicit key type.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw public key bytes
/// * `key_type` - The type of key being marshaled
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - DER-encoded PKIX public key
/// * `Err(BottleError)` - If encoding fails
pub fn marshal_pkix_public_key_with_type(
    public_key_bytes: &[u8],
    key_type: KeyType,
) -> Result<Vec<u8>> {
    match key_type {
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
            marshal_ecdsa_pkix(public_key_bytes, key_type)
        }
        KeyType::Ed25519 => marshal_ed25519_pkix(public_key_bytes),
        KeyType::X25519 => marshal_x25519_pkix(public_key_bytes),
        KeyType::Rsa => marshal_rsa_pkix(public_key_bytes),
        #[cfg(feature = "ml-kem")]
        KeyType::MlKem768 | KeyType::MlKem1024 => {
            marshal_mlkem_pkix(public_key_bytes, key_type)
        }
        #[cfg(feature = "post-quantum")]
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
            marshal_mldsa_pkix(public_key_bytes, key_type)
        }
        #[cfg(feature = "post-quantum")]
        KeyType::SlhDsa128s | KeyType::SlhDsa192s | KeyType::SlhDsa256s => {
            marshal_slhdsa_pkix(public_key_bytes, key_type)
        }
    }
}

/// Marshal a public key to PKIX format in PEM encoding.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw public key bytes
///
/// # Returns
///
/// * `Ok(String)` - PEM-encoded PKIX public key
/// * `Err(BottleError)` - If encoding fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rust_bottle::pkix;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pkix_pem = pkix::marshal_pkix_public_key_pem(&key.public_key_bytes()).unwrap();
/// ```
pub fn marshal_pkix_public_key_pem(public_key_bytes: &[u8]) -> Result<String> {
    let der = marshal_pkix_public_key(public_key_bytes)?;
    let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", der));
    Ok(pem)
}

/// Parse a PKIX (SubjectPublicKeyInfo) public key from DER encoding.
///
/// # Arguments
///
/// * `der_bytes` - DER-encoded PKIX public key
/// * `key_type` - Expected key type (for validation)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Raw public key bytes
/// * `Err(BottleError)` - If parsing fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rust_bottle::pkix;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pkix_der = pkix::marshal_pkix_public_key(&key.public_key_bytes()).unwrap();
/// let pub_key = pkix::parse_pkix_public_key(&pkix_der).unwrap();
/// assert_eq!(pub_key, key.public_key_bytes());
/// ```
pub fn parse_pkix_public_key(der_bytes: &[u8]) -> Result<Vec<u8>> {
    use der::asn1::BitString;
    use der::asn1::AnyRef;
    let spki: SubjectPublicKeyInfo<AnyRef, BitString> = SubjectPublicKeyInfo::from_der(der_bytes).map_err(|e| {
        BottleError::Deserialization(format!("Failed to parse PKIX public key: {}", e))
    })?;

    // Extract the raw key bytes from the SPKI structure
    // The algorithm identifier tells us the key type
    // For now, return the raw subjectPublicKey bytes
    // In a full implementation, we'd parse based on the algorithm OID
    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

/// Parse a PKIX public key from PEM encoding.
///
/// # Arguments
///
/// * `pem_str` - PEM-encoded PKIX public key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Raw public key bytes
/// * `Err(BottleError)` - If parsing fails
pub fn parse_pkix_public_key_pem(pem_str: &str) -> Result<Vec<u8>> {
    let pem = pem::parse(pem_str).map_err(|e| {
        BottleError::Deserialization(format!("Failed to parse PEM: {}", e))
    })?;
    parse_pkix_public_key(pem.contents())
}

/// Marshal a private key to PKCS#8 format in DER encoding.
///
/// # Arguments
///
/// * `private_key_bytes` - Raw private key bytes
/// * `key_type` - The type of key being marshaled
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - DER-encoded PKCS#8 private key
/// * `Err(BottleError)` - If encoding fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rust_bottle::pkix;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pkcs8_der = pkix::marshal_pkcs8_private_key(
///     &key.private_key_bytes(),
///     pkix::KeyType::EcdsaP256
/// ).unwrap();
/// ```
pub fn marshal_pkcs8_private_key(
    private_key_bytes: &[u8],
    key_type: KeyType,
) -> Result<Vec<u8>> {
    match key_type {
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
            marshal_ecdsa_pkcs8(private_key_bytes, key_type)
        }
        KeyType::Ed25519 => marshal_ed25519_pkcs8(private_key_bytes),
        KeyType::X25519 => marshal_x25519_pkcs8(private_key_bytes),
        KeyType::Rsa => marshal_rsa_pkcs8(private_key_bytes),
        #[cfg(feature = "ml-kem")]
        KeyType::MlKem768 | KeyType::MlKem1024 => {
            marshal_mlkem_pkcs8(private_key_bytes, key_type)
        }
        #[cfg(feature = "post-quantum")]
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
            marshal_mldsa_pkcs8(private_key_bytes, key_type)
        }
        #[cfg(feature = "post-quantum")]
        KeyType::SlhDsa128s | KeyType::SlhDsa192s | KeyType::SlhDsa256s => {
            marshal_slhdsa_pkcs8(private_key_bytes, key_type)
        }
    }
}

/// Marshal a private key to PKCS#8 format in PEM encoding.
///
/// # Arguments
///
/// * `private_key_bytes` - Raw private key bytes
/// * `key_type` - The type of key being marshaled
///
/// # Returns
///
/// * `Ok(String)` - PEM-encoded PKCS#8 private key
/// * `Err(BottleError)` - If encoding fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rust_bottle::pkix;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(
///     &key.private_key_bytes(),
///     pkix::KeyType::EcdsaP256
/// ).unwrap();
/// ```
pub fn marshal_pkcs8_private_key_pem(
    private_key_bytes: &[u8],
    key_type: KeyType,
) -> Result<String> {
    let der = marshal_pkcs8_private_key(private_key_bytes, key_type)?;
    let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", der));
    Ok(pem)
}

/// Parse a PKCS#8 private key from DER encoding.
///
/// # Arguments
///
/// * `der_bytes` - DER-encoded PKCS#8 private key
/// * `key_type` - Expected key type (for validation)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Raw private key bytes
/// * `Err(BottleError)` - If parsing fails
///
/// # Example
///
/// ```rust
/// use rust_bottle::keys::EcdsaP256Key;
/// use rust_bottle::pkix;
/// use rand::rngs::OsRng;
///
/// let rng = &mut OsRng;
/// let key = EcdsaP256Key::generate(rng);
/// let pkcs8_der = pkix::marshal_pkcs8_private_key(
///     &key.private_key_bytes(),
///     pkix::KeyType::EcdsaP256
/// ).unwrap();
/// let priv_key = pkix::parse_pkcs8_private_key(&pkcs8_der, pkix::KeyType::EcdsaP256).unwrap();
/// assert_eq!(priv_key, key.private_key_bytes());
/// ```
pub fn parse_pkcs8_private_key(der_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    match key_type {
        KeyType::EcdsaP256 => {
            use p256::pkcs8::DecodePrivateKey;
            use p256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_pkcs8_der(der_bytes).map_err(|e| {
                BottleError::Deserialization(format!("Failed to parse P-256 PKCS#8: {}", e))
            })?;
            Ok(signing_key.to_bytes().to_vec())
        }
        KeyType::Ed25519 => {
            use ed25519_dalek::pkcs8::DecodePrivateKey;
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_pkcs8_der(der_bytes).map_err(|e| {
                BottleError::Deserialization(format!("Failed to parse Ed25519 PKCS#8: {}", e))
            })?;
            Ok(signing_key.to_bytes().to_vec())
        }
        KeyType::X25519 => {
            // X25519 private keys are stored directly as raw bytes in PKCS#8
            let pkcs8 = PrivateKeyInfo::from_der(der_bytes).map_err(|e| {
                BottleError::Deserialization(format!("Failed to parse PKCS#8 private key: {}", e))
            })?;
            Ok(pkcs8.private_key.to_vec())
        }
        KeyType::Rsa => {
            // RSA private keys in PKCS#8 contain RSAPrivateKey structure
            // For now, return error - proper implementation requires RsaPrivateKey parsing
            // TODO: Implement proper RSA PKCS#8 deserialization
            Err(BottleError::Deserialization(
                "RSA PKCS#8 deserialization not yet implemented. Use RsaKey directly.".to_string()
            ))
        }
        _ => {
            // For other key types, return the raw private key bytes
            // (they may need special handling in the future)
            let pkcs8 = PrivateKeyInfo::from_der(der_bytes).map_err(|e| {
                BottleError::Deserialization(format!("Failed to parse PKCS#8 private key: {}", e))
            })?;
            Ok(pkcs8.private_key.to_vec())
        }
    }
}

/// Parse a PKCS#8 private key from PEM encoding.
///
/// # Arguments
///
/// * `pem_str` - PEM-encoded PKCS#8 private key
/// * `key_type` - Expected key type (for validation)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Raw private key bytes
/// * `Err(BottleError)` - If parsing fails
pub fn parse_pkcs8_private_key_pem(pem_str: &str, key_type: KeyType) -> Result<Vec<u8>> {
    let pem = pem::parse(pem_str).map_err(|e| {
        BottleError::Deserialization(format!("Failed to parse PEM: {}", e))
    })?;
    parse_pkcs8_private_key(pem.contents(), key_type)
}

// Helper functions for specific key types

fn marshal_ecdsa_pkix(public_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    match key_type {
        KeyType::EcdsaP256 => {
            use p256::pkcs8::EncodePublicKey;
            let pub_key = p256::PublicKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                BottleError::Serialization(format!("Failed to create P-256 public key: {}", e))
            })?;
            pub_key.to_public_key_der()
                .map(|doc| doc.as_bytes().to_vec())
                .map_err(|e| {
                    BottleError::Serialization(format!("Failed to encode P-256 PKIX: {}", e))
                })
        }
        _ => Err(BottleError::UnsupportedAlgorithm),
    }
}

fn marshal_ecdsa_pkcs8(private_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    match key_type {
        KeyType::EcdsaP256 => {
            use p256::pkcs8::EncodePrivateKey;
            use p256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_bytes(private_key_bytes.into()).map_err(|e| {
                BottleError::Serialization(format!("Invalid P-256 private key: {}", e))
            })?;
            signing_key.to_pkcs8_der()
                .map(|doc| doc.as_bytes().to_vec())
                .map_err(|e| {
                    BottleError::Serialization(format!("Failed to encode P-256 PKCS#8: {}", e))
                })
        }
        _ => Err(BottleError::UnsupportedAlgorithm),
    }
}

fn marshal_ed25519_pkix(public_key_bytes: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes.try_into().map_err(|_| {
            BottleError::Serialization("Invalid Ed25519 public key length".to_string())
        })?
    ).map_err(|e| {
        BottleError::Serialization(format!("Invalid Ed25519 public key: {}", e))
    })?;
    
    verifying_key.to_public_key_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| {
            BottleError::Serialization(format!("Failed to encode Ed25519 PKIX: {}", e))
        })
}

fn marshal_ed25519_pkcs8(private_key_bytes: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    
    let signing_key = SigningKey::from_bytes(
        private_key_bytes.try_into().map_err(|_| {
            BottleError::Serialization("Invalid Ed25519 private key length".to_string())
        })?
    );
    
    signing_key.to_pkcs8_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| {
            BottleError::Serialization(format!("Failed to encode Ed25519 PKCS#8: {}", e))
        })
}

fn marshal_x25519_pkix(public_key_bytes: &[u8]) -> Result<Vec<u8>> {
    // X25519 public keys are 32 bytes
    if public_key_bytes.len() != 32 {
        return Err(BottleError::Serialization("Invalid X25519 public key length".to_string()));
    }
    
    // X25519 uses a simple octet string encoding
    // This is a simplified implementation
    use der::asn1::OctetString;
    let key_octets = OctetString::new(public_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create X25519 octet string: {}", e))
    })?;
    
    // Create SPKI structure
    // X25519 uses no parameters per RFC 8410
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifier {
        oid: KeyType::X25519.oid(),
        parameters: None::<AnyRef>,
    };
    
    let spki = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: key_octets,
    };
    
    spki.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode X25519 PKIX: {}", e))
    })
}

fn marshal_x25519_pkcs8(private_key_bytes: &[u8]) -> Result<Vec<u8>> {
    // X25519 private keys are 32 bytes
    if private_key_bytes.len() != 32 {
        return Err(BottleError::Serialization("Invalid X25519 private key length".to_string()));
    }
    
    // Create PKCS#8 structure
    // X25519 uses no parameters per RFC 8410
    let algorithm = AlgorithmIdentifierRef {
        oid: KeyType::X25519.oid(),
        parameters: None,
    };
    
    let pkcs8 = PrivateKeyInfo::new(algorithm, private_key_bytes);
    
    pkcs8.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode X25519 PKCS#8: {}", e))
    })
}

fn marshal_rsa_pkix(_public_key_bytes: &[u8]) -> Result<Vec<u8>> {
    // Note: RSA public key bytes from RsaKey::public_key_bytes() are currently empty
    // This is a placeholder - proper implementation requires RsaPublicKey reference
    // For now, return an error indicating PKCS#8 serialization should be used
    // TODO: Implement proper RSA PKIX serialization using RsaPublicKey
    Err(BottleError::Serialization(
        "RSA PKIX serialization requires RsaPublicKey reference. Use PKCS#8 serialization or provide RsaPublicKey directly.".to_string()
    ))
}

fn marshal_rsa_pkcs8(_private_key_bytes: &[u8]) -> Result<Vec<u8>> {
    // Note: RSA private key bytes from RsaKey::private_key_bytes() are currently empty
    // This is a placeholder - proper implementation requires RsaPrivateKey reference
    // For now, return an error indicating direct RsaKey should be used
    // TODO: Implement proper RSA PKCS#8 serialization using RsaPrivateKey
    Err(BottleError::Serialization(
        "RSA PKCS#8 serialization requires RsaPrivateKey reference. Use RsaKey directly or provide RsaPrivateKey.".to_string()
    ))
}

#[cfg(feature = "ml-kem")]
fn marshal_mlkem_pkix(public_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    
    let key_octets = OctetString::new(public_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create ML-KEM octet string: {}", e))
    })?;
    
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifier {
        oid: key_type.oid(),
        parameters: Some(AnyRef::NULL),
    };
    
    let spki = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: key_octets,
    };
    
    spki.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode ML-KEM PKIX: {}", e))
    })
}

#[cfg(feature = "ml-kem")]
fn marshal_mlkem_pkcs8(private_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    
    let key_octets = OctetString::new(private_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create ML-KEM octet string: {}", e))
    })?;
    
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifierRef {
        oid: key_type.oid(),
        parameters: Some(AnyRef::NULL),
    };
    
    let pkcs8 = PrivateKeyInfo::new(algorithm, private_key_bytes);
    
    pkcs8.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode ML-KEM PKCS#8: {}", e))
    })
}

#[cfg(feature = "post-quantum")]
fn marshal_mldsa_pkix(public_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    
    let key_octets = OctetString::new(public_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create ML-DSA octet string: {}", e))
    })?;
    
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifier {
        oid: key_type.oid(),
        parameters: Some(AnyRef::NULL),
    };
    
    let spki = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: key_octets,
    };
    
    spki.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode ML-DSA PKIX: {}", e))
    })
}

#[cfg(feature = "post-quantum")]
fn marshal_mldsa_pkcs8(private_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    
    let key_octets = OctetString::new(private_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create ML-DSA octet string: {}", e))
    })?;
    
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifierRef {
        oid: key_type.oid(),
        parameters: Some(AnyRef::NULL),
    };
    
    let pkcs8 = PrivateKeyInfo::new(algorithm, private_key_bytes);
    
    pkcs8.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode ML-DSA PKCS#8: {}", e))
    })
}

#[cfg(feature = "post-quantum")]
fn marshal_slhdsa_pkix(public_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    
    let key_octets = OctetString::new(public_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create SLH-DSA octet string: {}", e))
    })?;
    
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifier {
        oid: key_type.oid(),
        parameters: Some(AnyRef::NULL),
    };
    
    let spki = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: key_octets,
    };
    
    spki.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode SLH-DSA PKIX: {}", e))
    })
}

#[cfg(feature = "post-quantum")]
fn marshal_slhdsa_pkcs8(private_key_bytes: &[u8], key_type: KeyType) -> Result<Vec<u8>> {
    use der::asn1::OctetString;
    
    let key_octets = OctetString::new(private_key_bytes).map_err(|e| {
        BottleError::Serialization(format!("Failed to create SLH-DSA octet string: {}", e))
    })?;
    
    use der::asn1::AnyRef;
    let algorithm = AlgorithmIdentifierRef {
        oid: key_type.oid(),
        parameters: Some(AnyRef::NULL),
    };
    
    let pkcs8 = PrivateKeyInfo::new(algorithm, private_key_bytes);
    
    pkcs8.to_der().map_err(|e| {
        BottleError::Serialization(format!("Failed to encode SLH-DSA PKCS#8: {}", e))
    })
}

/// Detect key type from public key bytes
fn detect_key_type_from_public_key(public_key_bytes: &[u8]) -> Result<KeyType> {
    match public_key_bytes.len() {
        32 => {
            // Could be Ed25519, X25519, or SLH-DSA-128s - try Ed25519 first (more common for signing)
            // In practice, you'd need context or try both
            #[cfg(feature = "post-quantum")]
            {
                // If post-quantum is enabled, could be SLH-DSA-128s, but default to Ed25519
                Ok(KeyType::Ed25519)
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                Ok(KeyType::Ed25519)
            }
        }
        65 => {
            // SEC1 uncompressed format (0x04 prefix) - likely ECDSA P-256
            if public_key_bytes[0] == 0x04 {
                Ok(KeyType::EcdsaP256)
            } else {
                Err(BottleError::InvalidKeyType)
            }
        }
        97 => {
            // SEC1 uncompressed format for P-384
            if public_key_bytes[0] == 0x04 {
                Ok(KeyType::EcdsaP384)
            } else {
                Err(BottleError::InvalidKeyType)
            }
        }
        133 => {
            // SEC1 uncompressed format for P-521
            if public_key_bytes[0] == 0x04 {
                Ok(KeyType::EcdsaP521)
            } else {
                Err(BottleError::InvalidKeyType)
            }
        }
        1184 => {
            #[cfg(feature = "ml-kem")]
            {
                Ok(KeyType::MlKem768)
            }
            #[cfg(not(feature = "ml-kem"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        1568 => {
            #[cfg(feature = "ml-kem")]
            {
                Ok(KeyType::MlKem1024)
            }
            #[cfg(not(feature = "ml-kem"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        1312 => {
            #[cfg(feature = "post-quantum")]
            {
                Ok(KeyType::MlDsa44)
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        1952 => {
            #[cfg(feature = "post-quantum")]
            {
                Ok(KeyType::MlDsa65)
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        2592 => {
            #[cfg(feature = "post-quantum")]
            {
                Ok(KeyType::MlDsa87)
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        48 => {
            #[cfg(feature = "post-quantum")]
            {
                Ok(KeyType::SlhDsa192s)
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        64 => {
            #[cfg(feature = "post-quantum")]
            {
                Ok(KeyType::SlhDsa256s)
            }
            #[cfg(not(feature = "post-quantum"))]
            {
                Err(BottleError::InvalidKeyType)
            }
        }
        _ => Err(BottleError::InvalidKeyType),
    }
}

