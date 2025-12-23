# rbottle

Rust implementation of the Bottle protocol - a layered message container system with encryption and signatures. This library provides secure, type-safe cryptographic operations for building privacy-preserving applications.

## Overview

rbottle implements the Bottle protocol, which provides layered message containers with support for multiple encryption layers, multiple signatures, key management through IDCards and Keychains, and cryptographically signed group memberships. The library is designed to match the functionality of the Go implementation [gobottle](https://github.com/BottleFmt/gobottle) while leveraging Rust's type safety and memory safety guarantees.

## Features

### Core Protocol
- Layered message containers (Bottles) with multiple encryption and signature layers
- Metadata storage for application-specific data
- Binary serialization using bincode for efficient storage and transmission
- Opener API for decrypting and inspecting bottles without full decryption

### Cryptographic Operations
- Elliptic Curve Diffie-Hellman (ECDH) encryption using X25519 and P-256
- AES-256-GCM authenticated encryption for shared secret encryption
- Digital signatures using ECDSA (P-256, P-384, P-521) and Ed25519
- Automatic key type detection for encryption and decryption operations

### Key Management
- IDCards for declaring sub-keys with specific purposes (sign, decrypt, etc.)
- Key lifecycle management with expiration dates
- Keychains for secure storage and retrieval of private keys
- Public key fingerprinting for key identification

### Group Management
- Cryptographically signed group memberships
- Role and metadata storage in memberships
- Verification of memberships against group IDCards

### Security Features
- Secure memory clearing using zeroize
- Type-safe cryptographic operations
- Comprehensive error handling
- No unsafe code in public API

## Installation

Add rbottle to your `Cargo.toml`:

```toml
[dependencies]
rbottle = "0.1.0"
rand = "0.8"
```

## Quick Start

### Basic Encryption and Decryption

```rust
use rbottle::*;
use rand::rngs::OsRng;

// Create a message container
let message = b"Hello, Bottle!";
let mut bottle = Bottle::new(message.to_vec());

// Generate encryption keys
let rng = &mut OsRng;
let key = X25519Key::generate(rng);

// Encrypt the bottle
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

// Decrypt and open the bottle
let opener = Opener::new();
let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
assert_eq!(decrypted, message);
```

### Signing and Verification

```rust
use rbottle::*;
use rand::rngs::OsRng;

let message = b"Signed message";
let mut bottle = Bottle::new(message.to_vec());

// Generate signing key
let rng = &mut OsRng;
let signing_key = Ed25519Key::generate(rng);
let public_key = signing_key.public_key_bytes();

// Sign the bottle
bottle.sign(rng, &signing_key, &public_key).unwrap();

// Verify signature
let opener = Opener::new();
let info = opener.open_info(&bottle).unwrap();
assert!(info.is_signed_by(&public_key));
```

## Detailed Usage

### Bottles

Bottles are layered message containers that support multiple encryption and signature layers. Each encryption layer can be for a different recipient, and multiple signers can sign the same bottle.

```rust
use rbottle::*;
use rand::rngs::OsRng;

// Create a bottle with a message
let message = b"Multi-layer encrypted and signed message";
let mut bottle = Bottle::new(message.to_vec());

// Add metadata
bottle.set_metadata("sender", "alice@example.com");
bottle.set_metadata("timestamp", "2024-01-01T00:00:00Z");

// Encrypt to multiple recipients (layered encryption)
let rng = &mut OsRng;
let bob_key = X25519Key::generate(rng);
let charlie_key = X25519Key::generate(rng);

// First encryption layer (innermost)
bottle.encrypt(rng, &bob_key.public_key_bytes()).unwrap();
// Second encryption layer (outermost)
bottle.encrypt(rng, &charlie_key.public_key_bytes()).unwrap();

// Sign with multiple signers
let alice_signing_key = Ed25519Key::generate(rng);
let alice_pub = alice_signing_key.public_key_bytes();
bottle.sign(rng, &alice_signing_key, &alice_pub).unwrap();

// Serialize for storage or transmission
let serialized = bottle.to_bytes().unwrap();

// Deserialize
let deserialized = Bottle::from_bytes(&serialized).unwrap();

// Open with appropriate key (decrypts all layers)
let opener = Opener::new();
let decrypted = opener.open(&deserialized, Some(&bob_key.private_key_bytes())).unwrap();
assert_eq!(decrypted, message);
```

### IDCards

IDCards allow entities to declare multiple keys with specific purposes and manage key lifecycles. They can be signed to establish trust.

```rust
use rbottle::*;
use rand::rngs::OsRng;
use std::time::{Duration, SystemTime};

let rng = &mut OsRng;

// Generate primary signing key
let primary_key = Ed25519Key::generate(rng);
let primary_pub = primary_key.public_key_bytes();

// Create IDCard
let mut idcard = IDCard::new(&primary_pub);

// Add metadata
idcard.set_metadata("name", "Alice");
idcard.set_metadata("email", "alice@example.com");
idcard.set_metadata("organization", "Example Corp");

// Set purposes for the primary key
idcard.set_key_purposes(&primary_pub, &["sign", "decrypt"]);

// Add a dedicated encryption key with expiration
let encryption_key = X25519Key::generate(rng);
let encryption_pub = encryption_key.public_key_bytes();
idcard.set_key_purposes(&encryption_pub, &["decrypt"]);
idcard.set_key_duration(&encryption_pub, Duration::from_secs(365 * 24 * 3600)); // 1 year

// Sign the IDCard with the primary key
let signed_idcard = idcard.sign(rng, &primary_key, &primary_pub).unwrap();

// Verify key purposes
assert!(idcard.test_key_purpose(&primary_pub, "sign").is_ok());
assert!(idcard.test_key_purpose(&encryption_pub, "decrypt").is_ok());
assert!(idcard.test_key_purpose(&encryption_pub, "sign").is_err());

// Get all keys for a specific purpose
let decrypt_keys = idcard.get_keys("decrypt");
assert_eq!(decrypt_keys.len(), 2);
```

### Keychains

Keychains provide secure storage for private keys, indexed by their public key fingerprints. They enable signing with specific keys without exposing the key selection logic.

```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;

// Create a keychain
let mut keychain = Keychain::new();

// Add multiple keys of different types
let ed25519_key = Ed25519Key::generate(rng);
let ecdsa_key = EcdsaP256Key::generate(rng);
let x25519_key = X25519Key::generate(rng);

keychain.add_key(ed25519_key);
keychain.add_key(ecdsa_key);
keychain.add_key(x25519_key);

// Retrieve a signer by public key
let ed25519_pub = ed25519_key.public_key_bytes();
let signer = keychain.get_signer(&ed25519_pub).unwrap();

// Sign a message
let message = b"Message to sign";
let signature = keychain.sign(rng, &ed25519_pub, message).unwrap();

// Use keychain with bottles
let mut bottle = Bottle::new(b"Keychain-signed message".to_vec());
bottle.sign(rng, signer, &ed25519_pub).unwrap();
```

### Memberships

Memberships provide cryptographically signed group affiliations, allowing entities to prove membership in groups with specific roles.

```rust
use rbottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;

// Create member and group IDCards
let member_key = Ed25519Key::generate(rng);
let member_pub = member_key.public_key_bytes();
let member_idcard = IDCard::new(&member_pub);

let group_key = Ed25519Key::generate(rng);
let group_pub = group_key.public_key_bytes();
let group_idcard = IDCard::new(&group_pub);

// Create a membership
let mut membership = Membership::new(&member_idcard, &group_pub);
membership.set_info("role", "admin");
membership.set_info("department", "Engineering");
membership.set_info("joined", "2024-01-01");

// Sign the membership with the group owner's key
membership.sign(rng, &group_key, &group_pub).unwrap();

// Verify the membership
assert!(membership.verify(&group_idcard).is_ok());

// Add membership to member's IDCard
let mut member_idcard = IDCard::new(&member_pub);
member_idcard.update_groups(vec![membership.to_bytes().unwrap()]);
```

### ECDH Encryption

Direct ECDH encryption can be used independently of bottles for encrypting data to public keys.

```rust
use rbottle::*;
use rand::rngs::OsRng;

let plaintext = b"Secret message";
let rng = &mut OsRng;

// Generate key pairs for Alice and Bob
let alice_key = X25519Key::generate(rng);
let bob_key = X25519Key::generate(rng);

// Alice encrypts to Bob's public key
let ciphertext = ecdh_encrypt(
    rng,
    plaintext,
    &bob_key.public_key_bytes()
).unwrap();

// Bob decrypts with his private key
let decrypted = ecdh_decrypt(
    &ciphertext,
    &bob_key.private_key_bytes()
).unwrap();

assert_eq!(decrypted, plaintext);
```

### Post-Quantum Cryptography

Post-quantum cryptography support is available via feature flags. See [PQC_FEATURE_FLAG.md](./PQC_FEATURE_FLAG.md) for details on enabling PQC features.

#### ML-KEM Encryption

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) provides post-quantum encryption. Requires the `ml-kem` feature:

```rust
#[cfg(feature = "ml-kem")]
use rbottle::*;
use rand::rngs::OsRng;

let plaintext = b"Post-quantum encrypted message";
let rng = &mut OsRng;

// Generate ML-KEM-768 keys
let alice_key = MlKem768Key::generate(rng);
let bob_key = MlKem768Key::generate(rng);

// Alice encrypts to Bob's public key
let ciphertext = mlkem768_encrypt(
    rng,
    plaintext,
    &bob_key.public_key_bytes()
).unwrap();

// Bob decrypts
let decrypted = mlkem768_decrypt(
    &ciphertext,
    &bob_key.private_key_bytes()
).unwrap();

assert_eq!(decrypted, plaintext);
```

#### ML-DSA Signatures

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) provides post-quantum signatures. Requires the `post-quantum` feature:

```rust
#[cfg(feature = "post-quantum")]
use rbottle::*;
use rand::rngs::OsRng;

let message = b"Post-quantum signed message";
let rng = &mut OsRng;

// Generate ML-DSA-44 signing key (128-bit security)
let signing_key = MlDsa44Key::generate(rng);
let pub_key = signing_key.public_key_bytes();

// Sign the message
let signature = signing_key.sign(rng, message).unwrap();

// Verify signature
assert!(signing_key.verify(message, &signature).is_ok());
```

#### SLH-DSA Signatures

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) provides hash-based post-quantum signatures. Requires the `post-quantum` feature:

```rust
#[cfg(feature = "post-quantum")]
use rbottle::*;
use rand::rngs::OsRng;

let message = b"Hash-based signed message";
let rng = &mut OsRng;

// Generate SLH-DSA-128s signing key (128-bit security)
let signing_key = SlhDsa128sKey::generate(rng);
let pub_key = signing_key.public_key_bytes();

// Sign the message
let signature = signing_key.sign(rng, message).unwrap();

// Verify signature
assert!(signing_key.verify(message, &signature).is_ok());
```

#### Hybrid Encryption (ML-KEM + X25519)

Hybrid encryption provides both post-quantum and classical security. Requires the `ml-kem` feature:

```rust
#[cfg(feature = "ml-kem")]
use rbottle::*;
use rand::rngs::OsRng;

let plaintext = b"Hybrid encrypted message";
let rng = &mut OsRng;

// Generate both post-quantum and classical keys
let mlkem_key = MlKem768Key::generate(rng);
let x25519_key = X25519Key::generate(rng);

// Encrypt with both (provides both post-quantum and classical security)
let ciphertext = hybrid_encrypt_mlkem768_x25519(
    rng,
    plaintext,
    &mlkem_key.public_key_bytes(),
    &x25519_key.public_key_bytes(),
).unwrap();

// Decrypt (tries ML-KEM first, falls back to X25519)
let mlkem_sec = mlkem_key.private_key_bytes();
let x25519_sec: [u8; 32] = x25519_key.private_key_bytes().try_into().unwrap();
let decrypted = hybrid_decrypt_mlkem768_x25519(
    &ciphertext,
    &mlkem_sec,
    &x25519_sec,
).unwrap();

assert_eq!(decrypted, plaintext);
```

#### Post-Quantum Bottles

Post-quantum keys work seamlessly with the Bottle API:

```rust
#[cfg(feature = "post-quantum")]
use rbottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Post-quantum secure message".to_vec());
let rng = &mut OsRng;

// Encrypt with ML-KEM (requires ml-kem feature)
#[cfg(feature = "ml-kem")]
{
    let mlkem_key = MlKem768Key::generate(rng);
    bottle.encrypt(rng, &mlkem_key.public_key_bytes()).unwrap();
}

// Sign with ML-DSA (requires post-quantum feature)
let mldsa_key = MlDsa44Key::generate(rng);
let pub_key = mldsa_key.public_key_bytes();
bottle.sign(rng, &mldsa_key, &pub_key).unwrap();

// Decrypt and verify
let opener = Opener::new();
#[cfg(feature = "ml-kem")]
{
    let mlkem_key = MlKem768Key::generate(rng);
    let decrypted = opener.open(&bottle, Some(&mlkem_key.private_key_bytes())).unwrap();
}
let info = opener.open_info(&bottle).unwrap();
assert!(info.is_signed_by(&pub_key));
```

### P-256 ECDH Encryption

The library also supports P-256 ECDH for compatibility with ECDSA keys.

```rust
use rbottle::*;
use rand::rngs::OsRng;

let plaintext = b"P-256 encrypted message";
let rng = &mut OsRng;

// Generate P-256 key pair
let key = EcdsaP256Key::generate(rng);
let public_key = key.public_key_bytes();

// Encrypt
let ciphertext = ecdh_encrypt(rng, plaintext, &public_key).unwrap();

// Decrypt (requires private key bytes)
let private_key_bytes = key.private_key_bytes();
let decrypted = ecdh_decrypt(&ciphertext, &private_key_bytes).unwrap();

assert_eq!(decrypted, plaintext);
```

## Supported Algorithms

### Classical Cryptography

| Algorithm | Purpose | Status | Notes |
|-----------|---------|--------|-------|
| ECDSA P-256 | Signing | Supported | Full implementation |
| ECDSA P-384 | Signing | Supported | Full implementation |
| ECDSA P-521 | Signing | Supported | Full implementation |
| Ed25519 | Signing | Supported | Full implementation |
| X25519 | Encryption | Supported | ECDH key exchange |
| P-256 ECDH | Encryption | Supported | ECDH key exchange |
| AES-256-GCM | Encryption | Supported | Used for shared secret encryption |
| SHA-256 | Hashing | Supported | Key fingerprinting and message hashing |
| SHA-3 | Hashing | Supported | Available for custom use |

### Post-Quantum Cryptography

Comprehensive post-quantum cryptography support is available via feature flags. The implementation includes:

#### Available Algorithms

**Encryption (requires `ml-kem` feature):**
- **ML-KEM-768**: Post-quantum encryption (192-bit security) - 1184 byte public keys, 2400 byte secret keys
- **ML-KEM-1024**: Post-quantum encryption (256-bit security) - 1568 byte public keys, 3168 byte secret keys

**Signatures (requires `post-quantum` feature):**
- **ML-DSA-44**: Post-quantum signatures (128-bit security) - Uses dilithium2
- **ML-DSA-65**: Post-quantum signatures (192-bit security) - Uses dilithium3
- **ML-DSA-87**: Post-quantum signatures (256-bit security) - Uses dilithium5
- **SLH-DSA-128s**: Hash-based signatures (128-bit security) - Uses sphincsshake256128srobust
- **SLH-DSA-192s**: Hash-based signatures (192-bit security) - Uses sphincsshake256192srobust
- **SLH-DSA-256s**: Hash-based signatures (256-bit security) - Uses sphincsshake256256srobust

**Hybrid Encryption (requires `ml-kem` feature):**
- **ML-KEM-768 + X25519**: Combines post-quantum and classical security

#### Enabling Post-Quantum Support

```bash
# Enable signatures only (ML-DSA and SLH-DSA)
cargo build --features post-quantum

# Enable encryption (ML-KEM) - may fail on macOS/ARM due to AVX2 bug
cargo build --features post-quantum,ml-kem

# Enable everything
cargo build --features post-quantum,ml-kem
```

**Note**: On macOS/ARM (AArch64), `pqcrypto-kyber` v0.5 has a compilation bug where AVX2 functions are referenced even though the crate should use the "clean" (generic) implementation. ML-DSA and SLH-DSA signatures work fine. See [PQC_FEATURE_FLAG.md](./PQC_FEATURE_FLAG.md) for details.

#### Integration

All post-quantum algorithms are integrated into the existing API and work seamlessly with:
- **Bottles**: Encrypt and sign with PQC keys
- **IDCards**: Use PQC keys for signing and encryption
- **Keychains**: Store and use PQC keys
- **Memberships**: Sign memberships with PQC keys
- **Automatic Key Detection**: `ecdh_encrypt`/`ecdh_decrypt` automatically detect PQC key types

See [POST_QUANTUM.md](./POST_QUANTUM.md) for detailed documentation.

### RSA Support

RSA dependency is included but not yet implemented. RSA support is planned for a future release.

## Architecture

### Module Structure

- `bottle.rs`: Core Bottle and Opener types
- `ecdh.rs`: ECDH encryption and decryption implementations
- `keys.rs`: Key type implementations (ECDSA, Ed25519, X25519)
- `signing.rs`: Sign and Verify traits
- `idcard.rs`: IDCard implementation
- `keychain.rs`: Keychain implementation
- `membership.rs`: Membership implementation
- `hash.rs`: Hashing utilities
- `utils.rs`: Utility functions
- `errors.rs`: Error types

### Design Principles

1. **Trait-based Design**: Uses Rust traits (`Sign`, `Verify`, `SignerKey`) for polymorphism and flexibility
2. **Type Safety**: Strong typing prevents common cryptographic errors at compile time
3. **Memory Safety**: No unsafe code in public API, secure memory clearing for sensitive data
4. **Error Handling**: Comprehensive error types using `thiserror` for detailed error information
5. **Serialization**: Uses `bincode` for efficient binary serialization

### Key Type System

Keys implement traits based on their capabilities:

- `Sign`: Types that can sign data (ECDSA, Ed25519)
- `Verify`: Types that can verify signatures (ECDSA, Ed25519)
- `SignerKey`: Keys that can be stored in keychains (all key types)

This design allows the library to work with different key types polymorphically while maintaining type safety.

## Error Handling

The library uses a comprehensive error type system:

```rust
pub enum BottleError {
    Encryption(String),
    Decryption(String),
    VerifyFailed,
    InvalidFormat,
    InvalidKeyType,
    KeyNotFound,
    KeyUnfit,
    NoAppropriateKey,
    Serialization(String),
    Deserialization(String),
    UnsupportedAlgorithm,
}
```

All operations return `Result<T, BottleError>` for explicit error handling.

## Testing

The library includes a comprehensive test suite that matches the gobottle test structure:

```bash
cargo test
```

### Test Files

- `tests/bottle_test.rs`: Core bottle functionality (7 tests)
  - Bottle creation and manipulation
  - Encryption and decryption
  - Signing and verification
  - Layered encryption
  - Serialization
  - Metadata handling

- `tests/ecdh_test.rs`: ECDH encryption/decryption (3 tests)
  - Basic encrypt/decrypt operations
  - Integration with bottles
  - Key serialization

- `tests/aliceandbob_test.rs`: End-to-end scenarios (4 tests)
  - Alice-Bob communication
  - IDCard usage
  - Keychain usage
  - Group memberships

All tests pass and demonstrate the library's functionality.

## Security Considerations

### Memory Safety

- All sensitive data is cleared from memory using the `zeroize` crate
- No unsafe code in the public API
- Rust's ownership system prevents use-after-free and double-free errors

### Cryptographic Security

- Uses well-vetted cryptographic libraries (ring, ed25519-dalek, p256)
- AES-256-GCM for authenticated encryption
- Proper key derivation from ECDH shared secrets using SHA-256
- Deterministic ECDSA signing (RFC 6979)

### Best Practices

- Always use cryptographically secure random number generators (`OsRng` or equivalent)
- Store private keys securely (consider using keychains or hardware security modules)
- Verify signatures before trusting data
- Check key purposes and expiration dates before using keys
- Clear sensitive data from memory when no longer needed

## Performance

The library is designed for efficiency:

- Zero-cost abstractions where possible
- Efficient binary serialization with bincode
- Minimal allocations in hot paths
- Type-safe operations without runtime overhead

Performance characteristics:
- Encryption/decryption: O(n) where n is message size
- Signing/verification: O(1) for fixed key sizes
- Key generation: O(1) for all key types
- Serialization: Efficient binary format

## Limitations and Future Work

### Current Limitations

1. **ML-KEM on macOS/ARM**: `pqcrypto-kyber` v0.5 has a compilation bug preventing ML-KEM from building on AArch64. The crate should use the "clean" implementation but AVX2 functions are incorrectly referenced. ML-DSA and SLH-DSA work fine.
2. **RSA Support**: Dependency included but not implemented
3. **PKIX/PKCS#8 Serialization**: Not yet implemented (keys use custom formats)
4. **TPM/HSM Integration**: Not yet implemented
5. **Short Buffer Encryption**: Placeholder only
6. **Multi-level Hashing**: Not yet implemented
7. **PQC Key Reconstruction**: `from_private_key_bytes()` for PQC keys cannot derive public keys (limitation of underlying crates)

### Planned Enhancements

1. Monitor `pqcrypto-kyber` for fixes to AArch64 compilation issues
2. RSA key type implementation (medium priority)
3. PKIX/PKCS#8 key serialization (medium priority)
4. TPM/HSM backend support (low priority)
5. Performance benchmarking and optimization
6. Additional SLH-DSA variants (f, simple variants)
7. Hardware acceleration support for PQC algorithms

## Compatibility with gobottle

rbottle aims to match gobottle's functionality while adapting to Rust's type system:

- Same core concepts: Bottles, IDCards, Keychains, Memberships
- Similar API structure adapted for Rust idioms
- Compatible test cases demonstrating equivalent functionality
- Same error types and error handling philosophy

Note: Serialization formats differ (bincode vs custom binary), so bottles created with one library cannot be directly read by the other. The protocol semantics are equivalent.

## Contributing

Contributions are welcome. Areas that need work:

- Post-quantum cryptography implementations
- RSA support
- PKIX/PKCS#8 serialization
- Additional test cases
- Performance improvements
- Documentation improvements

## License

MIT License - see LICENSE file for details.

## References

- [gobottle](https://github.com/BottleFmt/gobottle) - Go implementation of the Bottle protocol
- [Bottle Protocol Specification](https://github.com/BottleFmt/gobottle) - Protocol documentation
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - Post-quantum standards
- [COMPARISON.md](./COMPARISON.md) - Detailed comparison with gobottle
- [IMPLEMENTATION.md](./IMPLEMENTATION.md) - Implementation details
