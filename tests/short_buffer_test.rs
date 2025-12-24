use rust_bottle::keys::RsaKey;
use rust_bottle::utils::{encrypt_short_buffer, decrypt_short_buffer};
use rust_bottle::ecdh::rsa_encrypt;
use rust_bottle::pkix;
use rand::rngs::OsRng;

#[test]
fn test_short_buffer_encryption_rsa() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    
    // Test with a 32-byte AES key
    let aes_key = vec![0x42u8; 32];
    
    // Encrypt using rsa_encrypt directly (since PKIX serialization for RSA is not yet implemented)
    let ciphertext = rsa_encrypt(rng, &aes_key, rsa_key.public_key()).unwrap();
    assert_eq!(ciphertext.len(), 256); // 2048-bit key = 256 bytes
    
    // Decrypt
    let decrypted = rsa_key.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, aes_key);
}

#[test]
fn test_short_buffer_encryption_small_message() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    
    // Test with a small message (16 bytes)
    let message = b"Short message!";
    
    let ciphertext = rsa_encrypt(rng, message, rsa_key.public_key()).unwrap();
    let decrypted = rsa_key.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_short_buffer_encryption_max_size() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    
    // RSA-OAEP with SHA-256 can encrypt up to key_size - 2*hash_size - 2 bytes
    // For SHA-256 (32 bytes) and 2048-bit (256 bytes): 256 - 2*32 - 2 = 190 bytes
    // However, the exact limit depends on the implementation
    // Let's use a safe size that should work: 190 bytes
    let max_size = 190;
    let message = vec![0xAAu8; max_size];
    
    let ciphertext = rsa_encrypt(rng, &message, rsa_key.public_key()).unwrap();
    let decrypted = rsa_key.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_short_buffer_encryption_too_large() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    
    // Try to encrypt a message that's too large
    // RSA-OAEP with SHA-256 can encrypt up to key_size - 2*hash_size - 2 bytes
    // For 2048-bit (256 bytes) and SHA-256 (32 bytes): 256 - 2*32 - 2 = 190 bytes
    let too_large = vec![0xAAu8; 200]; // Larger than the maximum
    
    let result = rsa_encrypt(rng, &too_large, rsa_key.public_key());
    assert!(result.is_err());
}

#[test]
fn test_short_buffer_encryption_4096_key() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 4096).unwrap();
    
    // With 4096-bit key, we can encrypt larger messages
    // 4096 bits = 512 bytes, so max is 512 - 42 = 470 bytes
    let message = vec![0xBBu8; 400];
    
    let ciphertext = rsa_encrypt(rng, &message, rsa_key.public_key()).unwrap();
    assert_eq!(ciphertext.len(), 512); // 4096-bit key = 512 bytes
    
    let decrypted = rsa_key.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_short_buffer_encryption_key_wrapping() {
    let rng = &mut OsRng;
    let rsa_key = RsaKey::generate(rng, 2048).unwrap();
    
    // Simulate key wrapping: encrypt an AES-256 key (32 bytes)
    let aes_key = vec![0xCCu8; 32];
    
    // Encrypt the AES key with RSA
    let wrapped_key = rsa_encrypt(rng, &aes_key, rsa_key.public_key()).unwrap();
    
    // Decrypt to recover the AES key
    let unwrapped_key = rsa_key.decrypt(&wrapped_key).unwrap();
    assert_eq!(unwrapped_key, aes_key);
}

#[test]
fn test_short_buffer_encryption_different_keys() {
    let rng = &mut OsRng;
    let key1 = RsaKey::generate(rng, 2048).unwrap();
    let key2 = RsaKey::generate(rng, 2048).unwrap();
    
    let message = b"Secret message";
    
    // Encrypt with key1
    let ciphertext = rsa_encrypt(rng, message, key1.public_key()).unwrap();
    
    // Try to decrypt with key2 (should fail)
    let result = key2.decrypt(&ciphertext);
    assert!(result.is_err());
    
    // Decrypt with correct key (key1)
    let decrypted = key1.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, message);
}

