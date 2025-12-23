# rbottle

Rust implementation of the Bottle protocol - layered message containers with encryption and signatures.

This library provides functionality similar to [gobottle](https://github.com/BottleFmt/gobottle), including support for multiple key types, IDCards, Keychains, and Memberships.

## Features

- **Bottles**: Layered message containers with encryption and signatures
- **Multiple Key Types**: Support for ECDSA (P-256, P-384, P-521), Ed25519, X25519, and more
- **IDCards**: Declare sub-keys with specific purposes and manage key lifecycles
- **Keychains**: Secure storage for private keys
- **Memberships**: Cryptographically signed group affiliations
- **ECDH Encryption**: Elliptic curve Diffie-Hellman encryption
- **Test-Driven Development**: Comprehensive test suite matching gobottle

## Usage

### Basic Bottle Operations

```rust
use rbottle::*;
use rand::rngs::OsRng;

// Create a bottle
let message = b"Hello, Bottle!";
let mut bottle = Bottle::new(message.to_vec());

// Encrypt to a public key
let rng = &mut OsRng;
let key = X25519Key::generate(rng);
bottle.encrypt(rng, &key.public_key_bytes()).unwrap();

// Open the bottle
let opener = Opener::new();
let decrypted = opener.open(&bottle, Some(&key.private_key_bytes())).unwrap();
assert_eq!(decrypted, message);
```

### Signing

```rust
use rbottle::*;
use rand::rngs::OsRng;

let message = b"Signed message";
let mut bottle = Bottle::new(message.to_vec());

// Generate signing key
let rng = &mut OsRng;
let signing_key = Ed25519Key::generate(rng);

// Sign the bottle
bottle.sign(rng, &signing_key).unwrap();

// Verify signature
let opener = Opener::new();
let info = opener.open_info(&bottle).unwrap();
assert!(info.is_signed_by(&signing_key.public_key_bytes()));
```

### IDCards

```rust
use rbottle::*;
use rand::rngs::OsRng;

// Create an IDCard
let rng = &mut OsRng;
let key = Ed25519Key::generate(rng);
let mut idcard = IDCard::new(&key.public_key_bytes());

// Add metadata
idcard.set_metadata("name", "Alice");
idcard.set_metadata("email", "alice@example.com");

// Set key purposes
idcard.set_key_purposes(&key.public_key_bytes(), &["sign", "decrypt"]);

// Sign the IDCard
let signed = idcard.sign(rng, &key).unwrap();
```

### Keychains

```rust
use rbottle::*;
use rand::rngs::OsRng;

// Create a keychain
let mut keychain = Keychain::new();

// Add keys
let rng = &mut OsRng;
let key1 = Ed25519Key::generate(rng);
let key2 = EcdsaP256Key::generate(rng);

keychain.add_key(key1);
keychain.add_key(key2);

// Sign with a specific key
let message = b"Message to sign";
let signature = keychain.sign(rng, &key1.public_key_bytes(), message).unwrap();
```

### ECDH Encryption

```rust
use rbottle::*;
use rand::rngs::OsRng;

let plaintext = b"Secret message";
let rng = &mut OsRng;

// Generate key pairs
let alice_key = X25519Key::generate(rng);
let bob_key = X25519Key::generate(rng);

// Alice encrypts to Bob
let ciphertext = ecdh_encrypt(
    rng,
    plaintext,
    &bob_key.public_key_bytes()
).unwrap();

// Bob decrypts
let decrypted = ecdh_decrypt(
    &ciphertext,
    &bob_key.private_key_bytes()
).unwrap();

assert_eq!(decrypted, plaintext);
```

## Supported Key Types

| Type                        | Signing | Encryption     | Post-Quantum |
| --------------------------- | ------- | -------------- | ------------ |
| ECDSA (P-256, P-384, P-521) | ✓       | ✓ (via ECDH)   | ✗            |
| Ed25519                     | ✓       | ✓ (via X25519) | ✗            |
| X25519                      | ✗       | ✓              | ✗            |

Post-quantum cryptography support (ML-KEM, ML-DSA, SLH-DSA) is planned for future releases.

## Testing

Run the test suite:

```bash
cargo test
```

The test suite includes:
- `bottle_test.rs`: Core bottle functionality tests
- `ecdh_test.rs`: ECDH encryption/decryption tests
- `aliceandbob_test.rs`: End-to-end communication scenarios

## License

MIT License - see LICENSE file for details.

## References

- [gobottle](https://github.com/BottleFmt/gobottle) - Go implementation of the Bottle protocol


