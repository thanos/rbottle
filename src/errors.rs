use thiserror::Error;

/// Result type for Bottle operations
pub type Result<T> = std::result::Result<T, BottleError>;

/// Errors that can occur in Bottle operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum BottleError {
    #[error("No appropriate key available to decrypt")]
    NoAppropriateKey,

    #[error("Signature verification failed")]
    VerifyFailed,

    #[error("Key not found in keychain/IDCard")]
    KeyNotFound,

    #[error("Group not found in IDCard")]
    GroupNotFound,

    #[error("Key not authorized for the operation")]
    KeyUnfit,

    #[error("No valid recipient for encryption")]
    EncryptNoRecipient,

    #[error("Invalid key type")]
    InvalidKeyType,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Invalid format")]
    InvalidFormat,

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl From<std::io::Error> for BottleError {
    fn from(err: std::io::Error) -> Self {
        BottleError::Io(err.to_string())
    }
}


