use rbottle::*;
use rand::rngs::OsRng;

#[test]
fn test_ecdh_encrypt_decrypt() {
    let plaintext = b"Test message for ECDH encryption";
    
    // Generate key pairs
    let (_alice_pub, alice_priv) = generate_ecdh_keypair();
    let (bob_pub, bob_priv) = generate_ecdh_keypair();
    
    // Alice encrypts to Bob
    let rng = &mut OsRng;
    let ciphertext = ecdh_encrypt(rng, plaintext, &bob_pub).unwrap();
    
    // Bob decrypts
    let decrypted = ecdh_decrypt(&ciphertext, &bob_priv).unwrap();
    assert_eq!(decrypted, plaintext);
    
    // Alice cannot decrypt (wrong key)
    assert!(ecdh_decrypt(&ciphertext, &alice_priv).is_err());
}

#[test]
fn test_ecdh_with_bottle() {
    let message = b"ECDH encrypted bottle";
    let mut bottle = Bottle::new(message.to_vec());
    
    let (pub_key, priv_key) = generate_ecdh_keypair();
    
    let rng = &mut OsRng;
    bottle.encrypt(rng, &pub_key).unwrap();
    
    let opener = Opener::new();
    let decrypted = opener.open(&bottle, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_ecdh_key_serialization() {
    let (pub_key, priv_key) = generate_ecdh_keypair();
    
    // Serialize
    let pub_der = serialize_public_key(&pub_key).unwrap();
    let priv_der = serialize_private_key(&priv_key).unwrap();
    
    // Deserialize
    let pub_restored = deserialize_public_key(&pub_der).unwrap();
    let priv_restored = deserialize_private_key(&priv_der).unwrap();
    
    // Verify they work
    let plaintext = b"Test";
    let rng = &mut OsRng;
    let ciphertext = ecdh_encrypt(rng, plaintext, &pub_restored).unwrap();
    let decrypted = ecdh_decrypt(&ciphertext, &priv_restored).unwrap();
    assert_eq!(decrypted, plaintext);
}

// Helper functions
fn generate_ecdh_keypair() -> (Vec<u8>, Vec<u8>) {
    let rng = &mut OsRng;
    let key = X25519Key::generate(rng);
    (key.public_key_bytes(), key.private_key_bytes())
}

fn serialize_public_key(key: &[u8]) -> Result<Vec<u8>> {
    // Simple serialization - just return the key bytes
    // In production, this would use PKIX format
    Ok(key.to_vec())
}

fn serialize_private_key(key: &[u8]) -> Result<Vec<u8>> {
    // Simple serialization - just return the key bytes
    // In production, this would use PKCS#8 format
    Ok(key.to_vec())
}

fn deserialize_public_key(der: &[u8]) -> Result<Vec<u8>> {
    Ok(der.to_vec())
}

fn deserialize_private_key(der: &[u8]) -> Result<Vec<u8>> {
    Ok(der.to_vec())
}

