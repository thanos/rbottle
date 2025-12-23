use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

/// Hash data using the provided hasher type.
///
/// This is a generic function that works with any type implementing the
/// `Digest` trait from the `sha2` or `sha3` crates.
///
/// # Type Parameters
///
/// * `D` - A hasher type implementing `Digest` (e.g., `Sha256`, `Sha3_512`)
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// The hash output as a byte vector
///
/// # Example
///
/// ```rust
/// use rust_bottle::hash::hash;
/// use sha2::Sha256;
///
/// let data = b"Hello, world!";
/// let hash = hash::<Sha256>(data);
/// ```
pub fn hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Multi-level hash (hash of hash).
///
/// This function applies hashing multiple times, hashing the result of the
/// previous hash. This can be useful for certain cryptographic constructions.
///
/// # Type Parameters
///
/// * `D` - A hasher type implementing `Digest`
///
/// # Arguments
///
/// * `data` - The data to hash
/// * `levels` - The number of times to hash (0 means no hashing, 1 means hash once, etc.)
///
/// # Returns
///
/// The final hash output after applying hashing `levels` times
///
/// # Example
///
/// ```rust
/// use rust_bottle::hash::multi_hash;
/// use sha2::Sha256;
///
/// let data = b"Hello, world!";
/// let hash = multi_hash::<Sha256>(data, 3); // Hash 3 times
/// ```
pub fn multi_hash<D: Digest>(data: &[u8], levels: usize) -> Vec<u8> {
    let mut result = data.to_vec();
    for _ in 0..levels {
        result = crate::hash::hash::<D>(&result);
    }
    result
}

/// Hash data using SHA-256.
///
/// SHA-256 is a widely-used cryptographic hash function producing 256-bit
/// (32-byte) outputs. It's used throughout rust-bottle for key fingerprinting.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// SHA-256 hash as a 32-byte vector
///
/// # Example
///
/// ```rust
/// use rust_bottle::hash::sha256;
///
/// let data = b"Hello, world!";
/// let hash = sha256(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash::<Sha256>(data)
}

/// Hash data using SHA-384.
///
/// SHA-384 is a cryptographic hash function producing 384-bit (48-byte) outputs.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// SHA-384 hash as a 48-byte vector
pub fn sha384(data: &[u8]) -> Vec<u8> {
    hash::<Sha384>(data)
}

/// Hash data using SHA-512.
///
/// SHA-512 is a cryptographic hash function producing 512-bit (64-byte) outputs.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// SHA-512 hash as a 64-byte vector
pub fn sha512(data: &[u8]) -> Vec<u8> {
    hash::<Sha512>(data)
}

/// Hash data using SHA3-256.
///
/// SHA3-256 is a SHA-3 variant producing 256-bit (32-byte) outputs.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// SHA3-256 hash as a 32-byte vector
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    hash::<Sha3_256>(data)
}

/// Hash data using SHA3-384.
///
/// SHA3-384 is a SHA-3 variant producing 384-bit (48-byte) outputs.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// SHA3-384 hash as a 48-byte vector
pub fn sha3_384(data: &[u8]) -> Vec<u8> {
    hash::<Sha3_384>(data)
}

/// Hash data using SHA3-512.
///
/// SHA3-512 is a SHA-3 variant producing 512-bit (64-byte) outputs.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// SHA3-512 hash as a 64-byte vector
pub fn sha3_512(data: &[u8]) -> Vec<u8> {
    hash::<Sha3_512>(data)
}

