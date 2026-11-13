use cawide_host::{AuthError, AuthorizedKeysStore, PairingManager};
use std::time::Duration;

#[test]
fn test_authorized_keys_store_crud_and_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let store_path = temp_dir.path().join("cawide_conf").join("authorized_keys");

    let store = AuthorizedKeysStore::open_or_create(store_path.clone())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Some(parent) = store_path.parent() {
            let dir_meta = std::fs::metadata(parent)?;
            assert_eq!(
                dir_meta.mode() & 0o777,
                0o700,
                "Directory permissions must be 0700"
            );
        }
        let file_meta = std::fs::metadata(&store_path)?;
        assert_eq!(
            file_meta.mode() & 0o777,
            0o600,
            "File permissions must be 0600"
        );
    }

    let sk1 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let key_1 = sk1.verifying_key().to_bytes();

    let sk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let key_2 = sk2.verifying_key().to_bytes();

    assert!(!store.is_authorized(&key_1));
    assert!(!store.is_authorized(&key_2));

    // Valid additions (including spaces in device name)
    store.add_key(key_1, "Alice's iPad Pro 13".to_string())?;
    store.add_key(key_2, "Bob-iPhone-15".to_string())?;

    assert!(store.is_authorized(&key_1));
    assert!(store.is_authorized(&key_2));

    // Duplicate key rejection
    let dup_res = store.add_key(key_1, "Another Device".to_string());
    assert!(matches!(dup_res, Err(AuthError::KeyAlreadyAuthorized(_))));

    // Invalid curve point rejection (y=2 is not on Ed25519 curve)
    let mut invalid_curve_key = [0u8; 32];
    invalid_curve_key[0] = 2;
    assert!(matches!(
        store.add_key(invalid_curve_key, "Bad Key".to_string()),
        Err(AuthError::InvalidPublicKey(_))
    ));

    // Invalid device name rejections: newlines, empty, whitespace, control chars
    let sk3 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let key_3 = sk3.verifying_key().to_bytes();
    assert!(matches!(
        store.add_key(key_3, "Injected\nEvilKey".to_string()),
        Err(AuthError::InvalidDeviceName(_))
    ));
    assert!(matches!(
        store.add_key(key_3, "Injected\rEvilKey".to_string()),
        Err(AuthError::InvalidDeviceName(_))
    ));
    assert!(matches!(
        store.add_key(key_3, "".to_string()),
        Err(AuthError::InvalidDeviceName(_))
    ));
    assert!(matches!(
        store.add_key(key_3, "    ".to_string()),
        Err(AuthError::InvalidDeviceName(_))
    ));

    // Persistence across store reloads
    let reloaded_store = AuthorizedKeysStore::open_or_create(store_path)?;
    assert!(reloaded_store.is_authorized(&key_1));
    assert!(reloaded_store.is_authorized(&key_2));
    assert!(!reloaded_store.is_authorized(&key_3));

    let keys = reloaded_store.list_keys();
    assert_eq!(keys.len(), 2);
    let entry_1 = keys.iter().find(|e| e.public_key == key_1);
    assert!(entry_1.is_some());
    if let Some(e) = entry_1 {
        assert_eq!(e.device_name, "Alice's iPad Pro 13");
    }

    // Removal
    assert!(reloaded_store.remove_key(&key_1)?);
    assert!(!reloaded_store.is_authorized(&key_1));
    assert!(!reloaded_store.remove_key(&key_1)?);

    Ok(())
}

#[test]
fn test_pairing_manager_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = PairingManager::new(Duration::from_secs(300));
    let host_node: [u8; 32] = [42u8; 32];

    let ticket = manager.start_pairing(
        host_node,
        Some("https://relay.cawide.dev?foo=bar&baz=1".to_string()),
        Vec::new(),
    )?;
    assert_eq!(ticket.host_node_id, host_node);

    let uri = ticket.to_uri();
    assert!(uri.contains("&relay=https%3A%2F%2Frelay.cawide.dev%3Ffoo%3Dbar%26baz%3D1"));

    let qr_str = manager.render_terminal_qr()?;
    assert!(!qr_str.is_empty(), "QR code string must not be empty");
    assert!(qr_str.contains('▀') || qr_str.contains('█') || qr_str.contains('▄'));

    // Wrong secret must fail with InvalidPairingSecret without destroying active ticket
    let wrong_secret = [99u8; 32];
    let err = manager.verify_and_consume(&wrong_secret);
    assert!(matches!(err, Err(AuthError::InvalidPairingSecret)));

    // Correct secret must succeed and consume ticket
    manager.verify_and_consume(&ticket.pairing_secret)?;

    // Second call must fail with PairingExpired
    let second_res = manager.verify_and_consume(&ticket.pairing_secret);
    assert!(matches!(second_res, Err(AuthError::PairingExpired)));

    Ok(())
}

#[test]
fn test_pairing_manager_expiration() -> Result<(), Box<dyn std::error::Error>> {
    let manager = PairingManager::new(Duration::from_millis(15));
    let host_node: [u8; 32] = [7u8; 32];

    let ticket = manager.start_pairing(host_node, None, Vec::new())?;
    std::thread::sleep(Duration::from_millis(30));

    let res = manager.verify_and_consume(&ticket.pairing_secret);
    assert!(matches!(res, Err(AuthError::PairingExpired)));

    Ok(())
}
