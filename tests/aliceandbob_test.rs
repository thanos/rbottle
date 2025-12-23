use rbottle::*;
use rand::rngs::OsRng;

#[test]
fn test_alice_bob_communication() {
    // Alice creates a message
    let message = b"Hello Bob, this is Alice!";
    let mut bottle = Bottle::new(message.to_vec());
    
    // Generate keys for Alice and Bob
    let (alice_sig_pub, alice_sig_priv) = generate_signing_keypair("alice");
    let (bob_enc_pub, bob_enc_priv) = generate_encryption_keypair("bob");
    
    // Alice signs and encrypts to Bob
    let rng = &mut OsRng;
    bottle.sign(rng, &*alice_sig_priv, &alice_sig_pub).unwrap();
    bottle.encrypt(rng, &bob_enc_pub).unwrap();
    
    // Bob receives and opens the bottle
    let opener = Opener::new();
    let decrypted = opener.open(&bottle, Some(&bob_enc_priv)).unwrap();
    assert_eq!(decrypted, message);
    
    // Bob verifies Alice's signature
    let info = opener.open_info(&bottle).unwrap();
    assert!(info.is_signed_by(&alice_sig_pub));
}

#[test]
fn test_alice_bob_with_idcards() {
    // Create IDCards for Alice and Bob
    let (alice_sig_pub, alice_sig_priv) = generate_signing_keypair("alice");
    let (bob_enc_pub, bob_enc_priv) = generate_encryption_keypair("bob");
    
    let mut alice_idcard = IDCard::new(&alice_sig_pub);
    alice_idcard.set_metadata("name", "Alice");
    alice_idcard.set_metadata("email", "alice@example.com");
    alice_idcard.set_key_purposes(&alice_sig_pub, &["sign"]);
    
    let mut bob_idcard = IDCard::new(&bob_enc_pub);
    bob_idcard.set_metadata("name", "Bob");
    bob_idcard.set_metadata("email", "bob@example.com");
    bob_idcard.set_key_purposes(&bob_enc_pub, &["decrypt"]);
    
    // Sign IDCards
    let rng = &mut OsRng;
    let _alice_signed = alice_idcard.sign(rng, &*alice_sig_priv).unwrap();
    let _bob_signed = bob_idcard.sign(rng, &*alice_sig_priv).unwrap(); // Alice signs both for demo
    
    // Alice creates a message for Bob
    let message = b"Secure message to Bob";
    let mut bottle = Bottle::new(message.to_vec());
    bottle.sign(rng, &*alice_sig_priv, &alice_sig_pub).unwrap();
    bottle.encrypt(rng, &bob_enc_pub).unwrap();
    
    // Bob opens and verifies
    let opener = Opener::new();
    let decrypted = opener.open(&bottle, Some(&bob_enc_priv)).unwrap();
    assert_eq!(decrypted, message);
    
    let info = opener.open_info(&bottle).unwrap();
    assert!(info.is_signed_by(&alice_sig_pub));
}

#[test]
fn test_alice_bob_with_keychain() {
    // Create keychains
    let mut alice_keychain = Keychain::new();
    let mut bob_keychain = Keychain::new();
    
    let rng = &mut OsRng;
    let alice_key = Ed25519Key::generate(rng);
    let alice_sig_pub = alice_key.public_key_bytes();
    
    let bob_enc_key = X25519Key::generate(rng);
    let bob_enc_pub = bob_enc_key.public_key_bytes();
    let bob_enc_priv = bob_enc_key.private_key_bytes();
    
    // Add keys to keychains
    alice_keychain.add_key(alice_key);
    
    // Alice creates and sends message
    let message = b"Message using keychains";
    let mut bottle = Bottle::new(message.to_vec());
    
    // Sign using the keychain's signer
    bottle.sign(rng, alice_keychain.get_signer(&alice_sig_pub).unwrap(), &alice_sig_pub).unwrap();
    bottle.encrypt(rng, &bob_enc_pub).unwrap();
    
    // Bob opens
    let opener = Opener::new();
    let decrypted = opener.open(&bottle, Some(&bob_enc_priv)).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_alice_bob_group_membership() {
    // Create group
    let (group_pub, group_priv) = generate_signing_keypair("group");
    
    // Create member IDCards
    let (alice_pub, _alice_priv) = generate_signing_keypair("alice");
    let (bob_pub, _bob_priv) = generate_signing_keypair("bob");
    
    let alice_idcard = IDCard::new(&alice_pub);
    let bob_idcard = IDCard::new(&bob_pub);
    
    // Create memberships
    let mut alice_membership = Membership::new(&alice_idcard, &group_pub);
    alice_membership.set_info("role", "admin");
    
    let mut bob_membership = Membership::new(&bob_idcard, &group_pub);
    bob_membership.set_info("role", "member");
    
    // Sign memberships
    let rng = &mut OsRng;
    alice_membership.sign(rng, &*group_priv).unwrap();
    bob_membership.sign(rng, &*group_priv).unwrap();
    
    // Verify memberships
    let group_idcard = IDCard::new(&group_pub);
    assert!(alice_membership.verify(&group_idcard).is_ok());
    assert!(bob_membership.verify(&group_idcard).is_ok());
}

// Helper functions
fn generate_signing_keypair(_name: &str) -> (Vec<u8>, Box<dyn Sign>) {
    let rng = &mut OsRng;
    let key = Ed25519Key::generate(rng);
    (key.public_key_bytes(), Box::new(key))
}

fn generate_encryption_keypair(_name: &str) -> (Vec<u8>, Vec<u8>) {
    let rng = &mut OsRng;
    let key = X25519Key::generate(rng);
    (key.public_key_bytes(), key.private_key_bytes())
}

