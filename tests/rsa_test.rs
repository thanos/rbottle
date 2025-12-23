use rust_bottle::keys::RsaKey;
use rust_bottle::signing::{Sign, Verify};
use rust_bottle::keychain::SignerKey;
use rust_bottle::ecdh::{rsa_encrypt, rsa_decrypt};
use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;

#[test]
fn test_rsa_key_generation() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    // Note: public_key_bytes() and private_key_bytes() are placeholders
    // Use public_key() and private_key() for actual key access
    assert!(key.public_key().size() >= 256); // At least 2048 bits (256 bytes)
    assert_eq!(key.key_size(), 256); // 2048 bits / 8 = 256 bytes
}

#[test]
fn test_rsa_key_generation_4096() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 4096).unwrap();
    
    assert_eq!(key.key_size(), 512); // 4096 bits / 8 = 512 bytes
}

#[test]
fn test_rsa_key_generation_invalid_size() {
    let rng = &mut OsRng;
    assert!(RsaKey::generate(rng, 100).is_err()); // Too small
    assert!(RsaKey::generate(rng, 2047).is_err()); // Not multiple of 8
}

#[test]
fn test_rsa_encryption_decryption() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    // RSA can encrypt small messages (key_size - 42 bytes for OAEP with SHA-256)
    let plaintext = b"Hello, RSA!";
    
    let ciphertext = rsa_encrypt(rng, plaintext, key.public_key()).unwrap();
    assert_ne!(ciphertext, plaintext);
    assert_eq!(ciphertext.len(), key.key_size());
    
    let decrypted = rsa_decrypt(&ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rsa_encryption_decryption_large_key() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 4096).unwrap();
    
    // With 4096-bit key, we can encrypt larger messages
    let plaintext = b"This is a longer message that fits in a 4096-bit RSA key";
    
    let ciphertext = rsa_encrypt(rng, plaintext, key.public_key()).unwrap();
    assert_eq!(ciphertext.len(), key.key_size());
    
    let decrypted = rsa_decrypt(&ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_rsa_signing_verification() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    let message = b"Test message for RSA signing";
    
    let signature = key.sign(rng, message).unwrap();
    assert!(!signature.is_empty());
    assert_eq!(signature.len(), key.key_size());
    
    assert!(key.verify(message, &signature).is_ok());
}

#[test]
fn test_rsa_signing_verification_failure() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    let other_key = RsaKey::generate(rng, 2048).unwrap();
    
    let message = b"Test message";
    let signature = key.sign(rng, message).unwrap();
    
    // Verify with wrong key should fail
    assert!(other_key.verify(message, &signature).is_err());
    
    // Verify with wrong message should fail
    assert!(key.verify(b"Wrong message", &signature).is_err());
}

#[test]
fn test_rsa_signing_verification_different_messages() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    let message1 = b"Message 1";
    let message2 = b"Message 2";
    
    let sig1 = key.sign(rng, message1).unwrap();
    let sig2 = key.sign(rng, message2).unwrap();
    
    // Signatures should be different
    assert_ne!(sig1, sig2);
    
    // Each signature should verify for its own message
    assert!(key.verify(message1, &sig1).is_ok());
    assert!(key.verify(message2, &sig2).is_ok());
    
    // But not for the other message
    assert!(key.verify(message1, &sig2).is_err());
    assert!(key.verify(message2, &sig1).is_err());
}

#[test]
fn test_rsa_fingerprint() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    let fingerprint = key.fingerprint();
    assert_eq!(fingerprint.len(), 32); // SHA-256 hash is 32 bytes
    
    // Same key should have same fingerprint
    let fingerprint2 = key.fingerprint();
    assert_eq!(fingerprint, fingerprint2);
}

#[test]
fn test_rsa_public_key_access() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    let pub_key = key.public_key();
    assert!(pub_key.size() >= 256); // At least 2048 bits (256 bytes)
    
    // Public key should be usable for encryption
    let plaintext = b"Test";
    let ciphertext = rsa_encrypt(rng, plaintext, pub_key).unwrap();
    assert!(!ciphertext.is_empty());
}

#[test]
fn test_rsa_private_key_access() {
    let rng = &mut OsRng;
    let key = RsaKey::generate(rng, 2048).unwrap();
    
    let _priv_key = key.private_key();
    // Private key size is not directly accessible, but we can verify it works
    
    // Private key should be usable for decryption
    let plaintext = b"Test";
    let ciphertext = rsa_encrypt(rng, plaintext, key.public_key()).unwrap();
    let decrypted = key.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

