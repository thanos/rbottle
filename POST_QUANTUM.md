# Post-Quantum Cryptography Implementation

This document describes the comprehensive post-quantum cryptography (PQC) implementation in rust-bottle.

## Overview

rust-bottle includes full support for NIST-standardized post-quantum cryptography algorithms:

- **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism): For encryption
- **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm): For signatures
- **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm): For hash-based signatures

All PQC algorithms are integrated into the existing API and work seamlessly with Bottles, IDCards, Keychains, and Memberships.

## Feature Flags

Post-quantum cryptography is available via optional feature flags:

- **`post-quantum`**: Enables ML-DSA and SLH-DSA signatures
- **`ml-kem`**: Enables ML-KEM encryption (separate due to platform compatibility issues)

```bash
# Enable signatures only
cargo build --features post-quantum

# Enable encryption (may fail on macOS/ARM)
cargo build --features post-quantum,ml-kem
```

See [PQC_FEATURE_FLAG.md](./PQC_FEATURE_FLAG.md) for detailed information about the feature flags and platform compatibility.

## Implemented Algorithms

### ML-KEM (Encryption)

ML-KEM provides post-quantum key encapsulation for encryption. Two security levels are available:

| Variant | Security Level | Public Key Size | Secret Key Size | Ciphertext Size |
|---------|---------------|-----------------|-----------------|-----------------|
| ML-KEM-768 | 192-bit | 1184 bytes | 2400 bytes | 1088 bytes |
| ML-KEM-1024 | 256-bit | 1568 bytes | 3168 bytes | 1568 bytes |

**Implementation Details:**
- Uses `pqcrypto-kyber` v0.5.0
- On x86/x86_64: Uses AVX2-optimized implementation if available, falls back to "clean" implementation
- On AArch64: Should use "clean" (generic/portable) implementation, but compilation bug prevents building
- Key encapsulation uses AES-256-GCM for symmetric encryption

### ML-DSA (Signatures)

ML-DSA provides post-quantum digital signatures based on lattice cryptography. Three security levels are available:

| Variant | Security Level | Public Key Size | Secret Key Size | Signature Size | Implementation |
|---------|---------------|-----------------|-----------------|----------------|----------------|
| ML-DSA-44 | 128-bit | 1952 bytes | 4000 bytes | ~3363 bytes | dilithium2 |
| ML-DSA-65 | 192-bit | 2592 bytes | 4864 bytes | ~4595 bytes | dilithium3 |
| ML-DSA-87 | 256-bit | 3360 bytes | 6400 bytes | ~7776 bytes | dilithium5 |

**Implementation Details:**
- Uses `pqcrypto-dilithium` v0.5.0
- Uses "clean" (generic) implementations (dilithium2, dilithium3, dilithium5)
- Detached signatures for compatibility with existing API
- Works on all platforms including macOS/ARM

### SLH-DSA (Hash-Based Signatures)

SLH-DSA provides post-quantum signatures based on hash functions. Three security levels are available:

| Variant | Security Level | Public Key Size | Secret Key Size | Signature Size | Implementation |
|---------|---------------|-----------------|-----------------|----------------|----------------|
| SLH-DSA-128s | 128-bit | 32 bytes | 64 bytes | ~7856 bytes | sphincsshake256128srobust |
| SLH-DSA-192s | 192-bit | 48 bytes | 96 bytes | ~16224 bytes | sphincsshake256192srobust |
| SLH-DSA-256s | 256-bit | 64 bytes | 128 bytes | ~29792 bytes | sphincsshake256256srobust |

**Implementation Details:**
- Uses `pqcrypto-sphincsplus` v0.5.3
- Uses "robust" variants with SHAKE-256
- Very large signatures but simple hash-based security model
- Works on all platforms including macOS/ARM

## Key Types

### ML-KEM Keys

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::keys::MlKem768Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem768Key::generate(rng);

// Get key bytes
let pub_key = key.public_key_bytes();  // 1184 bytes
let priv_key = key.private_key_bytes(); // 2400 bytes

// Note: from_private_key_bytes() is not fully supported
// due to limitations in the underlying crate API
```

**Available Key Types:**
- `MlKem768Key`: 192-bit security
- `MlKem1024Key`: 256-bit security

### ML-DSA Keys

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::keys::MlDsa44Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlDsa44Key::generate(rng);

// Sign and verify
let message = b"Message to sign";
let signature = key.sign(rng, message).unwrap();
assert!(key.verify(message, &signature).is_ok());
```

**Available Key Types:**
- `MlDsa44Key`: 128-bit security (dilithium2)
- `MlDsa65Key`: 192-bit security (dilithium3)
- `MlDsa87Key`: 256-bit security (dilithium5)

### SLH-DSA Keys

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::keys::SlhDsa128sKey;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = SlhDsa128sKey::generate(rng);

// Sign and verify
let message = b"Message to sign";
let signature = key.sign(rng, message).unwrap();
assert!(key.verify(message, &signature).is_ok());
```

**Available Key Types:**
- `SlhDsa128sKey`: 128-bit security
- `SlhDsa192sKey`: 192-bit security
- `SlhDsa256sKey`: 256-bit security

## Encryption Functions

### ML-KEM-768 Encryption

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::ecdh::mlkem768_encrypt;
use rust_bottle::keys::MlKem768Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem768Key::generate(rng);
let plaintext = b"Secret message";

let ciphertext = mlkem768_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
```

### ML-KEM-1024 Encryption

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::ecdh::mlkem1024_encrypt;
use rust_bottle::keys::MlKem1024Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem1024Key::generate(rng);
let plaintext = b"Secret message";

let ciphertext = mlkem1024_encrypt(rng, plaintext, &key.public_key_bytes()).unwrap();
```

### Hybrid Encryption (ML-KEM + X25519)

Hybrid encryption provides both post-quantum and classical security by combining ML-KEM and X25519. This ensures security even if one algorithm is broken:

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::ecdh::hybrid_encrypt_mlkem768_x25519;
use rust_bottle::keys::{MlKem768Key, X25519Key};
use rand::rngs::OsRng;

let rng = &mut OsRng;
let mlkem_key = MlKem768Key::generate(rng);
let x25519_key = X25519Key::generate(rng);
let plaintext = b"Hybrid encrypted";

// Encrypt with both algorithms
let ciphertext = hybrid_encrypt_mlkem768_x25519(
    rng,
    plaintext,
    &mlkem_key.public_key_bytes(),
    &x25519_key.public_key_bytes(),
).unwrap();

// Decrypt (tries ML-KEM first, falls back to X25519)
#[cfg(feature = "ml-kem")]
use rust_bottle::ecdh::hybrid_decrypt_mlkem768_x25519;
let mlkem_sec = mlkem_key.private_key_bytes();
let x25519_sec: [u8; 32] = x25519_key.private_key_bytes().try_into().unwrap();
let decrypted = hybrid_decrypt_mlkem768_x25519(
    &ciphertext,
    &mlkem_sec,
    &x25519_sec,
).unwrap();

assert_eq!(decrypted, plaintext);
```

**Format:** `[mlkem_len: u32][mlkem_ciphertext][x25519_ciphertext]`

## Integration with Bottles

Post-quantum keys work seamlessly with the Bottle API:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

let mut bottle = Bottle::new(b"Post-quantum secure".to_vec());
let rng = &mut OsRng;

// Encrypt with ML-KEM (requires ml-kem feature)
#[cfg(feature = "ml-kem")]
{
    let mlkem_key = MlKem768Key::generate(rng);
    bottle.encrypt(rng, &mlkem_key.public_key_bytes()).unwrap();
}

// Sign with ML-DSA
let mldsa_key = MlDsa44Key::generate(rng);
let pub_key = mldsa_key.public_key_bytes();
bottle.sign(rng, &mldsa_key, &pub_key).unwrap();

// Decrypt
let opener = Opener::new();
#[cfg(feature = "ml-kem")]
{
    let mlkem_key = MlKem768Key::generate(rng);
    let decrypted = opener.open(&bottle, Some(&mlkem_key.private_key_bytes())).unwrap();
}
```

## Automatic Key Type Detection

The `ecdh_encrypt` and `ecdh_decrypt` functions automatically detect key types based on key size:

- **32 bytes**: X25519
- **64-65 bytes**: P-256 ECDSA
- **1184 bytes**: ML-KEM-768 public key
- **1568 bytes**: ML-KEM-1024 public key
- **2400 bytes**: ML-KEM-768 secret key
- **3168 bytes**: ML-KEM-1024 secret key

```rust
#[cfg(feature = "ml-kem")]
use rust_bottle::ecdh::ecdh_encrypt;
use rust_bottle::keys::MlKem768Key;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let key = MlKem768Key::generate(rng);

// Automatically detects ML-KEM-768 from key size
let ciphertext = ecdh_encrypt(rng, b"Message", &key.public_key_bytes()).unwrap();
```

## Keychain Integration

Post-quantum keys can be stored in keychains:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

let mut keychain = Keychain::new();
let rng = &mut OsRng;

let mldsa_key = MlDsa44Key::generate(rng);
let slhdsa_key = SlhDsa128sKey::generate(rng);

keychain.add_key(mldsa_key);
keychain.add_key(slhdsa_key);

// Sign with keys from keychain
let pub_key = mldsa_key.public_key_bytes();
let signature = keychain.sign(rng, &pub_key, b"Message").unwrap();
```

## IDCard Integration

Post-quantum keys can be used in IDCards:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

let rng = &mut OsRng;
let mldsa_key = MlDsa44Key::generate(rng);
#[cfg(feature = "ml-kem")]
let mlkem_key = MlKem768Key::generate(rng);

let mut idcard = IDCard::new(&mldsa_key.public_key_bytes());
idcard.set_key_purposes(&mldsa_key.public_key_bytes(), &["sign"]);
#[cfg(feature = "ml-kem")]
idcard.set_key_purposes(&mlkem_key.public_key_bytes(), &["decrypt"]);
```

## Performance Considerations

Post-quantum algorithms have different performance characteristics than classical algorithms:

- **ML-KEM**: Fast key generation and encryption, larger key sizes (1-3 KB)
- **ML-DSA**: Moderate signing speed, larger signatures (3-8 KB)
- **SLH-DSA**: Slower signing, very large signatures (8-30 KB), but simple hash-based security

**Performance Guidelines:**
- Use ML-KEM-768 for most applications (good balance of security and performance)
- Use ML-DSA-44 for most signing needs (smallest signatures)
- Use SLH-DSA only when hash-based security is specifically required
- Consider hybrid encryption for maximum security during transition period

## Security Recommendations

1. **Use Hybrid Encryption**: For maximum security, use hybrid encryption (ML-KEM + X25519) to provide both post-quantum and classical security. This ensures protection even if one algorithm is broken.

2. **Key Sizes**: 
   - ML-KEM-768 provides 192-bit security (suitable for most applications)
   - ML-KEM-1024 provides 256-bit security (for high-security applications)
   - Choose based on your security requirements and performance constraints

3. **Signature Algorithms**: 
   - ML-DSA is faster but has larger signatures (3-8 KB)
   - SLH-DSA has very large signatures (8-30 KB) but provides hash-based security with different mathematical assumptions
   - ML-DSA-44 is recommended for most use cases

4. **Migration Strategy**: 
   - Consider using hybrid approaches during the transition period
   - Maintain compatibility with classical systems while adding post-quantum security
   - Gradually migrate to full post-quantum as algorithms mature

5. **Platform Compatibility**:
   - ML-DSA and SLH-DSA work on all platforms
   - ML-KEM may not compile on macOS/ARM due to `pqcrypto-kyber` bug
   - Use feature flags to enable only what works on your platform

## API Compatibility

All post-quantum key types implement the same traits as classical keys:

- `Sign` trait: ML-DSA and SLH-DSA keys
- `Verify` trait: ML-DSA and SLH-DSA keys
- `SignerKey` trait: All key types (for keychain storage)

This means post-quantum keys can be used anywhere classical keys are used, providing a seamless migration path:

```rust
#[cfg(feature = "post-quantum")]
use rust_bottle::*;
use rand::rngs::OsRng;

// Works with any signer type
fn sign_message(signer: &dyn Sign, message: &[u8], rng: &mut OsRng) -> Vec<u8> {
    signer.sign(rng, message).unwrap()
}

// Can use classical or post-quantum keys
let ed25519_key = Ed25519Key::generate(rng);
let mldsa_key = MlDsa44Key::generate(rng);

let sig1 = sign_message(&ed25519_key, b"Message", rng);
let sig2 = sign_message(&mldsa_key, b"Message", rng);
```

## Dependencies

Post-quantum cryptography support requires:

```toml
[dependencies]
pqcrypto-kyber = { version = "0.5", optional = true }      # ML-KEM
pqcrypto-dilithium = { version = "0.5", optional = true }  # ML-DSA
pqcrypto-sphincsplus = { version = "0.5", optional = true } # SLH-DSA
pqcrypto-traits = { version = "0.3", optional = true }      # Traits

[features]
post-quantum = ["pqcrypto-dilithium", "pqcrypto-sphincsplus", "pqcrypto-traits"]
ml-kem = ["pqcrypto-kyber"]
```

## Platform Compatibility

### macOS/ARM (AArch64)

- **ML-DSA**: ✅ Works (uses clean dilithium2/3/5 implementations)
- **SLH-DSA**: ✅ Works (uses clean sphincsshake256 implementations)
- **ML-KEM**: ❌ Compilation fails due to `pqcrypto-kyber` v0.5 bug

**Issue**: `pqcrypto-kyber` v0.5.0 has a bug where AVX2 FFI functions are referenced even on AArch64, causing compilation failures. The crate should automatically use the "clean" (generic/portable) implementation on AArch64, but the bug prevents this.

**Workaround**: Use only the `post-quantum` feature (signatures only) on macOS/ARM, or wait for a fix in `pqcrypto-kyber`.

### x86/x86_64

- **ML-DSA**: ✅ Works
- **SLH-DSA**: ✅ Works
- **ML-KEM**: ✅ Works (uses AVX2-optimized implementation if available)

### Other Platforms

- **ML-DSA**: ✅ Should work (uses clean implementations)
- **SLH-DSA**: ✅ Should work (uses clean implementations)
- **ML-KEM**: ⚠️ May have issues depending on platform

## Known Limitations

1. **ML-KEM on AArch64**: Cannot compile due to `pqcrypto-kyber` bug
2. **Key Reconstruction**: `from_private_key_bytes()` for PQC keys cannot derive public keys (limitation of underlying crates)
3. **Large Signatures**: SLH-DSA signatures are very large (8-30 KB)
4. **Performance**: PQC algorithms are generally slower than classical algorithms

## Future Enhancements

- Monitor `pqcrypto-kyber` for fixes to AArch64 compilation issues
- Additional SLH-DSA variants (f, simple variants)
- Performance optimizations
- Hardware acceleration support
- Additional hybrid combinations
- Better key reconstruction support

## References

- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [SLH-DSA (FIPS 205)](https://csrc.nist.gov/pubs/fips/205/final)
- [PQClean Project](https://github.com/pqclean/pqclean/)
- [pqcrypto-* Rust Crates](https://crates.io/search?q=pqcrypto)
