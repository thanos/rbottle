use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

/// Hash data using the provided hasher
pub fn hash<D: Digest>(data: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Multi-level hash (hash of hash)
pub fn multi_hash<D: Digest>(data: &[u8], levels: usize) -> Vec<u8> {
    let mut result = data.to_vec();
    for _ in 0..levels {
        result = crate::hash::hash::<D>(&result);
    }
    result
}

/// Hash using SHA-256
pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash::<Sha256>(data)
}

/// Hash using SHA-384
pub fn sha384(data: &[u8]) -> Vec<u8> {
    hash::<Sha384>(data)
}

/// Hash using SHA-512
pub fn sha512(data: &[u8]) -> Vec<u8> {
    hash::<Sha512>(data)
}

/// Hash using SHA3-256
pub fn sha3_256(data: &[u8]) -> Vec<u8> {
    hash::<Sha3_256>(data)
}

/// Hash using SHA3-384
pub fn sha3_384(data: &[u8]) -> Vec<u8> {
    hash::<Sha3_384>(data)
}

/// Hash using SHA3-512
pub fn sha3_512(data: &[u8]) -> Vec<u8> {
    hash::<Sha3_512>(data)
}

