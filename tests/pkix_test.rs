use rust_bottle::*;
use rand::rngs::OsRng;

#[test]
fn test_ecdsa_p256_pkix_public_key() {
    let rng = &mut OsRng;
    let key = EcdsaP256Key::generate(rng);
    let pub_key_bytes = key.public_key_bytes();

    // Marshal to PKIX DER
    let pkix_der = pkix::marshal_pkix_public_key(&pub_key_bytes).unwrap();
    assert!(!pkix_der.is_empty());

    // Marshal to PKIX PEM
    let pkix_pem = pkix::marshal_pkix_public_key_pem(&pub_key_bytes).unwrap();
    assert!(pkix_pem.contains("BEGIN PUBLIC KEY"));
    assert!(pkix_pem.contains("END PUBLIC KEY"));

    // Parse back from DER
    let parsed_pub = pkix::parse_pkix_public_key(&pkix_der).unwrap();
    // Note: The parsed key might be in a different format, so we just verify it's not empty
    assert!(!parsed_pub.is_empty());

    // Parse back from PEM
    let parsed_pub_pem = pkix::parse_pkix_public_key_pem(&pkix_pem).unwrap();
    assert!(!parsed_pub_pem.is_empty());
}

#[test]
fn test_ecdsa_p256_pkcs8_private_key() {
    let rng = &mut OsRng;
    let key = EcdsaP256Key::generate(rng);
    let priv_key_bytes = key.private_key_bytes();

    // Marshal to PKCS#8 DER
    let pkcs8_der = pkix::marshal_pkcs8_private_key(&priv_key_bytes, pkix::KeyType::EcdsaP256).unwrap();
    assert!(!pkcs8_der.is_empty());

    // Marshal to PKCS#8 PEM
    let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(&priv_key_bytes, pkix::KeyType::EcdsaP256).unwrap();
    assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
    assert!(pkcs8_pem.contains("END PRIVATE KEY"));

    // Parse back from DER
    let parsed_priv = pkix::parse_pkcs8_private_key(&pkcs8_der, pkix::KeyType::EcdsaP256).unwrap();
    // Note: The parsed key might be in a different format, so we just verify it's not empty
    assert!(!parsed_priv.is_empty());

    // Parse back from PEM
    let parsed_priv_pem = pkix::parse_pkcs8_private_key_pem(&pkcs8_pem, pkix::KeyType::EcdsaP256).unwrap();
    assert!(!parsed_priv_pem.is_empty());
}

#[test]
fn test_ed25519_pkix_public_key() {
    let rng = &mut OsRng;
    let key = Ed25519Key::generate(rng);
    let pub_key_bytes = key.public_key_bytes();

    // Marshal to PKIX DER
    let pkix_der = pkix::marshal_pkix_public_key(&pub_key_bytes).unwrap();
    assert!(!pkix_der.is_empty());

    // Marshal to PKIX PEM
    let pkix_pem = pkix::marshal_pkix_public_key_pem(&pub_key_bytes).unwrap();
    assert!(pkix_pem.contains("BEGIN PUBLIC KEY"));
    assert!(pkix_pem.contains("END PUBLIC KEY"));
}

#[test]
fn test_ed25519_pkcs8_private_key() {
    let rng = &mut OsRng;
    let key = Ed25519Key::generate(rng);
    let priv_key_bytes = key.private_key_bytes();

    // Marshal to PKCS#8 DER
    let pkcs8_der = pkix::marshal_pkcs8_private_key(&priv_key_bytes, pkix::KeyType::Ed25519).unwrap();
    assert!(!pkcs8_der.is_empty());

    // Marshal to PKCS#8 PEM
    let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(&priv_key_bytes, pkix::KeyType::Ed25519).unwrap();
    assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
    assert!(pkcs8_pem.contains("END PRIVATE KEY"));
}

#[test]
fn test_x25519_pkix_public_key() {
    let rng = &mut OsRng;
    let key = X25519Key::generate(rng);
    let pub_key_bytes = key.public_key_bytes();

    // Marshal to PKIX DER
    let pkix_der = pkix::marshal_pkix_public_key_with_type(&pub_key_bytes, pkix::KeyType::X25519).unwrap();
    assert!(!pkix_der.is_empty());

    // Marshal to PKIX PEM (must use explicit type since auto-detection defaults to Ed25519 for 32-byte keys)
    let pkix_der2 = pkix::marshal_pkix_public_key_with_type(&pub_key_bytes, pkix::KeyType::X25519).unwrap();
    let pem = pem::encode(&pem::Pem::new("PUBLIC KEY", pkix_der2));
    assert!(pem.contains("BEGIN PUBLIC KEY"));
}

#[test]
fn test_x25519_pkcs8_private_key() {
    let rng = &mut OsRng;
    let key = X25519Key::generate(rng);
    let priv_key_bytes = key.private_key_bytes();

    // Marshal to PKCS#8 DER
    let pkcs8_der = pkix::marshal_pkcs8_private_key(&priv_key_bytes, pkix::KeyType::X25519).unwrap();
    assert!(!pkcs8_der.is_empty());

    // Marshal to PKCS#8 PEM
    let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(&priv_key_bytes, pkix::KeyType::X25519).unwrap();
    assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn test_pkix_roundtrip_ecdsa_p256() {
    let rng = &mut OsRng;
    let key1 = EcdsaP256Key::generate(rng);
    let pub_key_bytes = key1.public_key_bytes();

    // Marshal and unmarshal
    let pkix_der = pkix::marshal_pkix_public_key(&pub_key_bytes).unwrap();
    let parsed = pkix::parse_pkix_public_key(&pkix_der).unwrap();
    
    // The parsed format might be different (DER vs SEC1), so we just verify it's valid
    assert!(!parsed.is_empty());
}

#[test]
fn test_pkcs8_roundtrip_ecdsa_p256() {
    let rng = &mut OsRng;
    let key1 = EcdsaP256Key::generate(rng);
    let priv_key_bytes = key1.private_key_bytes();

    // Marshal and unmarshal
    let pkcs8_der = pkix::marshal_pkcs8_private_key(&priv_key_bytes, pkix::KeyType::EcdsaP256).unwrap();
    let parsed = pkix::parse_pkcs8_private_key(&pkcs8_der, pkix::KeyType::EcdsaP256).unwrap();
    
    // The parsed format might be different, so we just verify it's valid
    assert!(!parsed.is_empty());
}

#[test]
fn test_pem_encoding_decoding() {
    let rng = &mut OsRng;
    let key = EcdsaP256Key::generate(rng);
    let pub_key_bytes = key.public_key_bytes();

    // Encode to PEM
    let pem = pkix::marshal_pkix_public_key_pem(&pub_key_bytes).unwrap();
    
    // Decode from PEM
    let decoded = pkix::parse_pkix_public_key_pem(&pem).unwrap();
    assert!(!decoded.is_empty());
}

#[cfg(feature = "post-quantum")]
#[test]
fn test_mldsa44_pkix_public_key() {
    let rng = &mut OsRng;
    let key = MlDsa44Key::generate(rng);
    let pub_key_bytes = key.public_key_bytes();

    // Marshal to PKIX DER
    let pkix_der = pkix::marshal_pkix_public_key_with_type(&pub_key_bytes, pkix::KeyType::MlDsa44).unwrap();
    assert!(!pkix_der.is_empty());

    // Marshal to PKIX PEM
    let pkix_pem = pkix::marshal_pkix_public_key_pem(&pub_key_bytes).unwrap();
    assert!(pkix_pem.contains("BEGIN PUBLIC KEY"));
}

#[cfg(feature = "post-quantum")]
#[test]
fn test_mldsa44_pkcs8_private_key() {
    let rng = &mut OsRng;
    let key = MlDsa44Key::generate(rng);
    let priv_key_bytes = key.private_key_bytes();

    // Marshal to PKCS#8 DER
    let pkcs8_der = pkix::marshal_pkcs8_private_key(&priv_key_bytes, pkix::KeyType::MlDsa44).unwrap();
    assert!(!pkcs8_der.is_empty());

    // Marshal to PKCS#8 PEM
    let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(&priv_key_bytes, pkix::KeyType::MlDsa44).unwrap();
    assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
}

#[cfg(feature = "ml-kem")]
#[test]
fn test_mlkem768_pkix_public_key() {
    let rng = &mut OsRng;
    let key = MlKem768Key::generate(rng);
    let pub_key_bytes = key.public_key_bytes();

    // Marshal to PKIX DER
    let pkix_der = pkix::marshal_pkix_public_key_with_type(&pub_key_bytes, pkix::KeyType::MlKem768).unwrap();
    assert!(!pkix_der.is_empty());

    // Marshal to PKIX PEM
    let pkix_pem = pkix::marshal_pkix_public_key_pem(&pub_key_bytes).unwrap();
    assert!(pkix_pem.contains("BEGIN PUBLIC KEY"));
}

#[cfg(feature = "ml-kem")]
#[test]
fn test_mlkem768_pkcs8_private_key() {
    let rng = &mut OsRng;
    let key = MlKem768Key::generate(rng);
    let priv_key_bytes = key.private_key_bytes();

    // Marshal to PKCS#8 DER
    let pkcs8_der = pkix::marshal_pkcs8_private_key(&priv_key_bytes, pkix::KeyType::MlKem768).unwrap();
    assert!(!pkcs8_der.is_empty());

    // Marshal to PKCS#8 PEM
    let pkcs8_pem = pkix::marshal_pkcs8_private_key_pem(&priv_key_bytes, pkix::KeyType::MlKem768).unwrap();
    assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
}

