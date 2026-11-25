use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cawide_account::{
    sign, DeviceLink, DeviceLinkBody, HostTrustSnapshot, ManagedHostSyncResponse as Resp,
    SnapshotDevice, SnapshotRevocation,
};
use cawide_host::auth::{ManagedSyncOutcome, LEASE_SECS};
use cawide_host::{AuthError, AuthorizedKeysStore, KeySource};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn gen_key() -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

fn make_link_obj(
    account_id: &str,
    issuer: &SigningKey,
    subject: &SigningKey,
    subject_name: &str,
    issued_at: u64,
) -> DeviceLink {
    let body = DeviceLinkBody::new(
        account_id.to_string(),
        issuer.verifying_key().to_bytes(),
        subject.verifying_key().to_bytes(),
        subject_name.to_string(),
        issued_at,
    );
    let msg = body.signing_message();
    let issuer_sig = sign(&issuer.to_bytes(), &msg).to_vec();
    let subject_sig = sign(&subject.to_bytes(), &msg).to_vec();
    DeviceLink {
        body,
        issuer_sig,
        subject_sig,
    }
}

fn make_link(
    account_id: &str,
    issuer: &SigningKey,
    subject: &SigningKey,
    subject_name: &str,
    issued_at: u64,
) -> String {
    hex::encode(make_link_obj(account_id, issuer, subject, subject_name, issued_at).to_bytes())
}

fn make_snapshot(
    account_id: &str,
    version: u64,
    locked: bool,
    devices: Vec<([u8; 32], &str)>,
    links: Vec<String>,
    revoked: Vec<([u8; 32], u64)>,
) -> HostTrustSnapshot {
    HostTrustSnapshot {
        version,
        account_id: account_id.to_string(),
        locked,
        devices: devices
            .into_iter()
            .map(|(pk, name)| SnapshotDevice {
                public_key: hex::encode(pk),
                name: name.to_string(),
            })
            .collect(),
        links,
        revoked: revoked
            .into_iter()
            .map(|(pk, revoked_at)| SnapshotRevocation {
                public_key: hex::encode(pk),
                revoked_at,
            })
            .collect(),
    }
}

fn link_store(store: &AuthorizedKeysStore, paired_pk: &[u8; 32], account_id: &str, now: u64) {
    assert!(store
        .begin_claim(paired_pk, account_id, false, now)
        .unwrap());
    let snap = make_snapshot(
        account_id,
        1,
        false,
        vec![(*paired_pk, "D1")],
        vec![],
        vec![],
    );
    store.apply_account_sync(&snap, now).unwrap();
}

#[test]
fn test_admit_linked_device_and_reject_wrong_account_or_tampered_sig() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let (sk3, pk3) = gen_key();
    let (sk4, pk4) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);

    let valid_link = make_link("acct-1", &sk1, &sk2, "D2", now);
    let wrong_acct_link = make_link("acct-other", &sk1, &sk3, "D3", now);
    let mut tampered = make_link_obj("acct-1", &sk1, &sk4, "D4", now);
    tampered.subject_sig[0] ^= 0xff;
    let tampered_hex = hex::encode(tampered.to_bytes());

    let snap = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2"), (pk3, "D3"), (pk4, "D4")],
        vec![valid_link, wrong_acct_link, tampered_hex],
        vec![],
    );
    let removed = store.apply_account_sync(&snap, now).unwrap();
    assert!(removed.is_empty());

    assert!(store.is_authorized(&pk1));
    assert!(store.is_authorized(&pk2));
    assert!(!store.is_authorized(&pk3));
    assert!(!store.is_authorized(&pk4));
}

#[test]
fn test_revocation_removes_paired_and_tombstone_blocks_old_links() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (_sk2, pk2) = gen_key();
    let (sk3, pk3) = gen_key();

    store.add_key(pk1, "D1".into()).unwrap();
    store.add_key(pk2, "D2".into()).unwrap();
    let t_rev = now_secs();
    link_store(&store, &pk1, "acct-1", t_rev);

    // Revoke pk2 at t_rev (added_at_ts <= t_rev) and pk3 at t_rev
    let snap1 = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk3, "D3")],
        vec![make_link("acct-1", &sk1, &sk3, "D3", t_rev - 1)],
        vec![(pk2, t_rev), (pk3, t_rev)],
    );
    let removed = store.apply_account_sync(&snap1, t_rev).unwrap();
    assert_eq!(removed, vec![pk2]);
    assert!(!store.is_authorized(&pk2));
    assert!(!store.is_authorized(&pk3));

    // Re-add pk2 via add_key after t_rev; applying snapshot with revoked_at = t_rev keeps it
    while now_secs() <= t_rev {
        std::thread::sleep(Duration::from_millis(50));
    }
    store.add_key(pk2, "D2-repaired".into()).unwrap();
    assert!(store.is_authorized(&pk2));

    let snap2 = make_snapshot(
        "acct-1",
        3,
        false,
        vec![(pk1, "D1"), (pk3, "D3")],
        vec![make_link("acct-1", &sk1, &sk3, "D3", t_rev + 1)],
        vec![(pk2, t_rev), (pk3, t_rev)],
    );
    let removed2 = store.apply_account_sync(&snap2, t_rev + 1).unwrap();
    assert!(removed2.is_empty());
    assert!(store.is_authorized(&pk2));
    assert!(store.is_authorized(&pk3));
}

#[test]
fn test_local_remove_key_persists_denied_and_blocks_new_links_until_add_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);

    let snap1 = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now)],
        vec![],
    );
    store.apply_account_sync(&snap1, now).unwrap();
    assert!(store.is_authorized(&pk2));

    assert!(store.remove_key(&pk2).unwrap());
    assert!(!store.is_authorized(&pk2));
    assert!(dir.path().join("denied_keys").exists());

    // New link with issued_at > now still does NOT admit pk2
    let snap2 = make_snapshot(
        "acct-1",
        3,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now + 100)],
        vec![],
    );
    store.apply_account_sync(&snap2, now + 100).unwrap();
    assert!(!store.is_authorized(&pk2));

    // Only add_key clears local_denied
    store.add_key(pk2, "D2-local".into()).unwrap();
    assert!(store.is_authorized(&pk2));
}

#[test]
fn test_corrupt_denied_keys_blocks_account_admission_and_is_not_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("authorized_keys");
    let denied_path = dir.path().join("denied_keys");
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let (_sk3, pk3) = gen_key();
    let (_sk4, pk4) = gen_key();
    let (sk5, pk5) = gen_key();
    let now = now_secs();

    {
        let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
        store.add_key(pk1, "D1".into()).unwrap();
        link_store(&store, &pk1, "acct-1", now);
        let snap = make_snapshot(
            "acct-1",
            2,
            false,
            vec![(pk1, "D1"), (pk2, "D2")],
            vec![make_link("acct-1", &sk1, &sk2, "D2", now)],
            vec![],
        );
        store.apply_account_sync(&snap, now).unwrap();
        assert!(store.is_authorized(&pk2));
    }

    let corrupt_content = format!(
        "{}\nnot-a-valid-line\n{}\n",
        hex::encode(pk3),
        hex::encode(pk5)
    );
    std::fs::write(&denied_path, &corrupt_content).unwrap();

    let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
    // Account keys emptied at open when denied_keys is corrupt
    assert!(!store.is_authorized(&pk2));
    assert!(store.is_authorized(&pk1));

    // apply_account_sync admits zero Account keys while denied_corrupt
    let snap = make_snapshot(
        "acct-1",
        3,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now + 1)],
        vec![],
    );
    store.apply_account_sync(&snap, now + 1).unwrap();
    assert!(!store.is_authorized(&pk2));

    // add_key of another key does not rewrite denied_keys or clear denied_corrupt
    store.add_key(pk4, "D4".into()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&denied_path).unwrap(),
        corrupt_content
    );

    // remove_key while denied_corrupt removes from paired but does not rewrite denied_keys
    assert!(store.remove_key(&pk4).unwrap());
    assert!(!store.is_authorized(&pk4));
    assert_eq!(
        std::fs::read_to_string(&denied_path).unwrap(),
        corrupt_content
    );

    // Even after add_key(pk3), denied_keys is not rewritten and denied_corrupt stays set
    store.add_key(pk3, "D3".into()).unwrap();
    assert_eq!(
        std::fs::read_to_string(&denied_path).unwrap(),
        corrupt_content
    );
    let snap2 = make_snapshot(
        "acct-1",
        4,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now + 2)],
        vec![],
    );
    store.apply_account_sync(&snap2, now + 2).unwrap();
    assert!(!store.is_authorized(&pk2));

    // Operator fixes denied_keys (removes corrupt line, keeps pk5) and restarts
    std::fs::write(&denied_path, format!("{}\n", hex::encode(pk5))).unwrap();
    let recovered = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
    let snap3 = make_snapshot(
        "acct-1",
        5,
        false,
        vec![(pk1, "D1"), (pk2, "D2"), (pk5, "D5")],
        vec![
            make_link("acct-1", &sk1, &sk2, "D2", now + 3),
            make_link("acct-1", &sk1, &sk5, "D5", now + 3),
        ],
        vec![],
    );
    recovered.apply_account_sync(&snap3, now + 3).unwrap();
    assert!(recovered.is_authorized(&pk2));
    assert!(!recovered.is_authorized(&pk5));
}

#[test]
fn test_add_key_promotes_account_to_paired_and_rejects_duplicate_paired() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);
    let snap = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now)],
        vec![],
    );
    store.apply_account_sync(&snap, now).unwrap();

    let entry = store
        .list_keys()
        .into_iter()
        .find(|e| e.public_key == pk2)
        .unwrap();
    assert!(matches!(entry.source, KeySource::Account { .. }));

    // add_key moves pk2 from account to paired
    store.add_key(pk2, "D2-paired".into()).unwrap();
    let entry = store
        .list_keys()
        .into_iter()
        .find(|e| e.public_key == pk2)
        .unwrap();
    assert_eq!(entry.source, KeySource::Paired);
    assert_eq!(entry.device_name, "D2-paired");

    // add_key of already paired key returns KeyAlreadyAuthorized
    let err = store.add_key(pk2, "D2-again".into()).unwrap_err();
    assert!(matches!(err, AuthError::KeyAlreadyAuthorized(_)));
}

#[test]
fn test_version_only_snapshot_does_not_rewrite_account_trust_json() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);
    let link = make_link("acct-1", &sk1, &sk2, "D2", now);
    let snap1 = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![link.clone()],
        vec![],
    );
    store.apply_account_sync(&snap1, now).unwrap();

    let trust_path = dir.path().join("account_trust.json");
    let meta_before = std::fs::metadata(&trust_path).unwrap();
    let content_before = std::fs::read(&trust_path).unwrap();
    std::thread::sleep(Duration::from_millis(20));

    let snap2 = make_snapshot(
        "acct-1",
        99,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![link],
        vec![],
    );
    store.apply_account_sync(&snap2, now + 5).unwrap();
    assert_eq!(store.account_version(), 99);

    let meta_after = std::fs::metadata(&trust_path).unwrap();
    let content_after = std::fs::read(&trust_path).unwrap();
    assert_eq!(content_before, content_after);
    assert_eq!(
        meta_before.modified().unwrap(),
        meta_after.modified().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(meta_before.ino(), meta_after.ino());
    }
}

#[test]
fn test_locked_dropped_device_and_mismatched_account() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let (sk3, pk3) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);
    let l12 = make_link("acct-1", &sk1, &sk2, "D2", now);
    let l13 = make_link("acct-1", &sk1, &sk3, "D3", now);
    let snap1 = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2"), (pk3, "D3")],
        vec![l12.clone(), l13.clone()],
        vec![],
    );
    store.apply_account_sync(&snap1, now).unwrap();
    assert!(store.is_authorized(&pk2));
    assert!(store.is_authorized(&pk3));

    // Mismatched account_id -> Err and no change
    let bad_snap = make_snapshot("acct-wrong", 3, false, vec![], vec![], vec![]);
    assert!(matches!(
        store.apply_account_sync(&bad_snap, now),
        Err(AuthError::AccountSync(_))
    ));
    assert!(store.is_authorized(&pk2));
    assert!(store.is_authorized(&pk3));

    // Device dropped from devices is removed and returned
    let snap_drop = make_snapshot(
        "acct-1",
        3,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![l12, l13],
        vec![],
    );
    let removed = store.apply_account_sync(&snap_drop, now).unwrap();
    assert_eq!(removed, vec![pk3]);
    assert!(store.is_authorized(&pk2));
    assert!(!store.is_authorized(&pk3));

    // locked: true removes all account keys
    let snap_locked = make_snapshot(
        "acct-1",
        4,
        true,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![],
        vec![],
    );
    let removed_locked = store.apply_account_sync(&snap_locked, now).unwrap();
    assert_eq!(removed_locked, vec![pk2]);
    assert!(store.is_authorized(&pk1));
    assert!(!store.is_authorized(&pk2));
}

#[test]
fn test_corrupt_account_trust_json_renames_and_keeps_denied_keys() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("authorized_keys");
    let trust_path = dir.path().join("account_trust.json");
    let denied_path = dir.path().join("denied_keys");
    let (_sk1, pk1) = gen_key();
    let (_sk2, pk2) = gen_key();

    {
        let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
        store.add_key(pk1, "D1".into()).unwrap();
        store.add_key(pk2, "D2".into()).unwrap();
        store.remove_key(&pk2).unwrap();
    }
    std::fs::write(&trust_path, b"{not valid json").unwrap();

    let store = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
    assert!(store.account_link().is_none());
    assert!(dir.path().join("account_trust.json.corrupt").exists());
    assert!(!trust_path.exists());
    assert!(denied_path.exists());
    assert!(std::fs::read_to_string(&denied_path)
        .unwrap()
        .contains(&hex::encode(pk2)));
}

#[test]
fn test_begin_claim_takeover_and_pending_link_keeps_old_keys_until_new_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let (sk3, pk3) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-A", now);
    let snap_a = make_snapshot(
        "acct-A",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-A", &sk1, &sk2, "D2", now)],
        vec![],
    );
    store.apply_account_sync(&snap_a, now).unwrap();
    assert!(store.is_authorized(&pk2));

    // Paired root with takeover: false fails when linked to another account
    assert_eq!(
        store.begin_claim(&pk1, "acct-B", false, now).unwrap_err(),
        "linked to another account"
    );

    // Takeover sets pending_link = B, keeps old account keys until B's 200 snapshot arrives
    assert!(store.begin_claim(&pk1, "acct-B", true, now).unwrap());
    assert!(store.is_authorized(&pk2));
    assert_eq!(store.sync_target().unwrap().0.account_id, "acct-B");
    assert!(store.sync_target().unwrap().1);

    // Takeover cannot be undone by Account client of A
    assert_eq!(
        store.begin_claim(&pk2, "acct-A", true, now).unwrap_err(),
        "linked to another account"
    );
    assert_eq!(store.sync_target().unwrap().0.account_id, "acct-B");

    // First 200 snapshot for B promotes pending_link and drops A's keys
    let snap_b = make_snapshot(
        "acct-B",
        1,
        false,
        vec![(pk1, "D1"), (pk3, "D3")],
        vec![make_link("acct-B", &sk1, &sk3, "D3", now)],
        vec![],
    );
    let removed = store.apply_account_sync(&snap_b, now).unwrap();
    assert_eq!(removed, vec![pk2]);
    assert!(!store.is_authorized(&pk2));
    assert!(store.is_authorized(&pk3));
    assert_eq!(store.account_link().unwrap().account_id, "acct-B");

    // mark_unlinked_local disables claims; takeover: false fails with disabled
    let (was_linked, removed_unlink) = store.mark_unlinked_local(true).unwrap();
    assert!(was_linked);
    assert_eq!(removed_unlink, vec![pk3]);
    assert!(store.claims_disabled());
    assert!(store.pending_unlink());
    assert_eq!(
        store.begin_claim(&pk1, "acct-C", false, now).unwrap_err(),
        "disabled on this computer"
    );
}

#[test]
fn test_mark_unlinked_local_never_linked_and_expired_pending() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (_sk1, pk1) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();

    // Never-linked store
    let (was_linked, removed) = store.mark_unlinked_local(true).unwrap();
    assert!(!was_linked);
    assert!(removed.is_empty());
    assert!(!store.claims_disabled());
    assert!(!store.pending_unlink());

    // Expired pending, no link
    assert!(store.begin_claim(&pk1, "acct-A", false, now - 601).unwrap());
    let (was_linked2, removed2) = store.mark_unlinked_local(true).unwrap();
    assert!(!was_linked2);
    assert!(removed2.is_empty());
    assert!(!store.claims_disabled());
    assert!(!store.pending_unlink());

    let trust_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("account_trust.json")).unwrap())
            .unwrap();
    assert!(trust_json["pending_link"].is_null());

    // Following Paired begin_claim(A, false, now) returns Ok(true)
    assert!(store.begin_claim(&pk1, "acct-A", false, now).unwrap());
}

#[test]
fn test_begin_claim_idempotency_same_account_no_write_and_unknown_client() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (_sk1, pk1) = gen_key();
    let (_sk_unknown, pk_unknown) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();

    // Unknown client -> Err("not permitted")
    assert_eq!(
        store
            .begin_claim(&pk_unknown, "acct-A", false, now)
            .unwrap_err(),
        "not permitted"
    );

    // First pending claim returns Ok(true), 100 repeated identical calls return Ok(false)
    assert!(store.begin_claim(&pk1, "acct-A", false, now).unwrap());
    for _ in 0..100 {
        assert!(!store.begin_claim(&pk1, "acct-A", false, now).unwrap());
    }

    // Promote to link
    let snap = make_snapshot("acct-A", 1, false, vec![(pk1, "D1")], vec![], vec![]);
    store.apply_account_sync(&snap, now).unwrap();
    let claimed_at = store.account_link().unwrap().claimed_at;
    assert_eq!(claimed_at, now);

    let trust_path = dir.path().join("account_trust.json");
    let content_before = std::fs::read(&trust_path).unwrap();
    #[cfg(unix)]
    let ino_before = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(&trust_path).unwrap().ino()
    };

    // Same-account takeover: false leaves claimed_at unchanged and writes nothing
    assert!(!store.begin_claim(&pk1, "acct-A", false, now + 100).unwrap());
    assert_eq!(store.account_link().unwrap().claimed_at, claimed_at);
    assert_eq!(std::fs::read(&trust_path).unwrap(), content_before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&trust_path).unwrap().ino(), ino_before);
    }

    // clear_account_link before 600s returns (false, [])
    let (cleared_early, _) = store
        .clear_account_link("acct-A", claimed_at + 599)
        .unwrap();
    assert!(!cleared_early);
    assert!(store.account_link().is_some());

    // clear_account_link at claimed_at + 600 returns (true, []) and clears link
    let (cleared, removed) = store
        .clear_account_link("acct-A", claimed_at + 600)
        .unwrap();
    assert!(cleared);
    assert!(removed.is_empty());
    assert!(store.account_link().is_none());
}

#[test]
fn test_state_survives_reopen_with_identical_is_authorized() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("authorized_keys");
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let (_sk3, pk3) = gen_key();
    let now = now_secs();

    {
        let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
        store.add_key(pk1, "D1".into()).unwrap();
        link_store(&store, &pk1, "acct-1", now);
        let snap = make_snapshot(
            "acct-1",
            5,
            false,
            vec![(pk1, "D1"), (pk2, "D2")],
            vec![make_link("acct-1", &sk1, &sk2, "D2", now)],
            vec![],
        );
        store.apply_account_sync(&snap, now).unwrap();
        assert!(store.is_authorized(&pk1));
        assert!(store.is_authorized(&pk2));
        assert!(!store.is_authorized(&pk3));
    }

    let reopened = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
    assert!(reopened.is_authorized(&pk1));
    assert!(reopened.is_authorized(&pk2));
    assert!(!reopened.is_authorized(&pk3));
    assert_eq!(reopened.account_link().unwrap().account_id, "acct-1");
    assert_eq!(reopened.account_version(), 5);
}

#[test]
fn test_devices_list_with_source_and_revoke_account_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);
    let snap = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now)],
        vec![],
    );
    store.apply_account_sync(&snap, now).unwrap();

    match cawide_host::devices::list_with_source(&store) {
        cawide_host::net::IpcResponse::DevicesWithSource(devs) => {
            assert_eq!(devs.len(), 2);
            let d1 = devs.iter().find(|d| d.node_id == hex::encode(pk1)).unwrap();
            let d2 = devs.iter().find(|d| d.node_id == hex::encode(pk2)).unwrap();
            assert_eq!(d1.source, "paired");
            assert_eq!(d2.source, "account");
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let conns = cawide_host::net::connections::ConnectionTracker::new();
    match cawide_host::devices::revoke(&store, &conns, "D2") {
        cawide_host::net::IpcResponse::Revoked { node_id, .. } => {
            assert_eq!(node_id, hex::encode(pk2));
        }
        other => panic!("unexpected revoke response: {other:?}"),
    }
    assert!(!store.is_authorized(&pk2));
    assert!(dir.path().join("denied_keys").exists());
}

#[test]
fn test_account_key_takeover_cannot_extend_claimed_at_grace_window() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let t0 = 1_700_000_000u64;

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", t0);
    let snap = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", t0)],
        vec![],
    );
    store.apply_account_sync(&snap, t0).unwrap();
    assert!(store.is_authorized(&pk2));

    // Account-sourced key calling begin_claim with takeover=true must not refresh claimed_at.
    let res = store.begin_claim(&pk2, "acct-1", true, t0 + 500).unwrap();
    assert!(!res);
    assert_eq!(store.account_link().unwrap().claimed_at, t0);

    let (cleared, removed) = store.clear_account_link("acct-1", t0 + 600).unwrap();
    assert!(cleared);
    assert_eq!(removed, vec![pk2]);
    assert!(!store.is_authorized(&pk2));
}

#[test]
fn test_open_filters_local_denied_and_unlinked_account_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authorized_keys");
    let store = AuthorizedKeysStore::open_or_create(path.clone()).unwrap();
    let (sk1, pk1) = gen_key();
    let (sk2, pk2) = gen_key();
    let now = now_secs();

    store.add_key(pk1, "D1".into()).unwrap();
    link_store(&store, &pk1, "acct-1", now);
    let snap = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(pk1, "D1"), (pk2, "D2")],
        vec![make_link("acct-1", &sk1, &sk2, "D2", now)],
        vec![],
    );
    store.apply_account_sync(&snap, now).unwrap();
    assert!(store.is_authorized(&pk2));

    // Simulate a crash where denied_keys recorded pk2 while account_trust.json still lists pk2.
    std::fs::write(
        dir.path().join("denied_keys"),
        format!("{}\n", hex::encode(pk2)),
    )
    .unwrap();
    let reopened = AuthorizedKeysStore::open_or_create(path.clone()).unwrap();
    assert!(!reopened.is_authorized(&pk2));
    assert!(reopened.is_authorized(&pk1));

    // Simulate account_trust.json with account_id: null but stray keys.
    std::fs::remove_file(dir.path().join("denied_keys")).unwrap();
    let trust_path = dir.path().join("account_trust.json");
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&trust_path).unwrap()).unwrap();
    json["account_id"] = serde_json::Value::Null;
    std::fs::write(&trust_path, serde_json::to_vec(&json).unwrap()).unwrap();
    let reopened2 = AuthorizedKeysStore::open_or_create(path).unwrap();
    assert!(!reopened2.is_authorized(&pk2));
}

// ---------------------------------------------------------------------------
// Managed binding (§1.1-§1.6)
// ---------------------------------------------------------------------------

fn future_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(LEASE_SECS)
}

/// Enrolls `client` as a managed device of `account_id` at `epoch`. Returns whether the
/// binding was replaced (the caller must close existing connections).
fn managed_enroll(
    store: &AuthorizedKeysStore,
    client: [u8; 32],
    account_id: &str,
    epoch: u64,
) -> bool {
    store
        .begin_managed_pair(client, "Phone".into(), account_id, epoch, now_secs())
        .unwrap()
}

#[tokio::test]
async fn managed_pending_response_grants_no_lease_and_exact_epoch_gates_sync() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (_sk, pk) = gen_key();
    assert!(managed_enroll(&store, pk, "acct-1", 3));
    assert_eq!(store.managed_sync_target(), Some(("acct-1".into(), 3)));

    // A response for a different epoch or account is stale and never renews anything.
    let stale = store
        .apply_managed_sync("acct-1", 2, Resp::Pending, future_deadline(), now_secs())
        .unwrap();
    assert!(matches!(stale, ManagedSyncOutcome::Stale));
    let wrong_account = store
        .apply_managed_sync("acct-9", 3, Resp::Pending, future_deadline(), now_secs())
        .unwrap();
    assert!(matches!(wrong_account, ManagedSyncOutcome::Stale));

    let pending = store
        .apply_managed_sync("acct-1", 3, Resp::Pending, future_deadline(), now_secs())
        .unwrap();
    assert!(matches!(pending, ManagedSyncOutcome::Pending));
    assert!(store.lease_until().is_none());
    assert!(!store.is_session_authorized(&pk));
}

#[tokio::test]
async fn managed_committed_revocation_is_durable_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("authorized_keys");
    let (_sk, pk) = gen_key();
    {
        let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
        managed_enroll(&store, pk, "acct-1", 3);
        let outcome = store
            .apply_managed_sync("acct-1", 3, Resp::Removed, future_deadline(), now_secs())
            .unwrap();
        match outcome {
            ManagedSyncOutcome::Removed {
                removed,
                persist_failed,
            } => {
                assert_eq!(removed, vec![pk]);
                assert!(!persist_failed);
            }
            _ => panic!("expected Removed"),
        }
        assert!(store.managed_binding().unwrap().revoked);
        assert!(!store.is_session_authorized(&pk));
    }
    let reopened = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
    assert!(reopened.managed_binding().unwrap().revoked);
    assert!(!reopened.is_authorized(&pk));
    assert!(reopened.managed_sync_target().is_none());
}

#[tokio::test]
async fn managed_revocation_write_failure_fails_closed_and_retries() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("authorized_keys");
    let trust_path = dir.path().join("account_trust.json");
    let (_sk, pk) = gen_key();
    let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
    managed_enroll(&store, pk, "acct-1", 3);

    // Replacing the trust file with a directory makes the atomic rename fail deterministically.
    std::fs::remove_file(&trust_path).ok();
    std::fs::create_dir(&trust_path).unwrap();

    let outcome = store
        .apply_managed_sync("acct-1", 3, Resp::Removed, future_deadline(), now_secs())
        .unwrap();
    let persist_failed = match outcome {
        ManagedSyncOutcome::Removed { persist_failed, .. } => persist_failed,
        _ => panic!("expected Removed"),
    };
    assert!(
        persist_failed,
        "write failure must be reported, not swallowed"
    );
    // Denial is in memory even though the write failed: revoked keys are not admitted.
    assert!(store.has_pending_revocation_persist());
    assert!(!store.is_session_authorized(&pk));
    assert!(store.managed_binding().unwrap().revoked);

    // Retry still fails while the path is blocked...
    assert!(store.retry_persist_trust().is_err());
    assert!(store.has_pending_revocation_persist());

    // ...and succeeds once the path is clear.
    std::fs::remove_dir(&trust_path).unwrap();
    store.retry_persist_trust().unwrap();
    assert!(!store.has_pending_revocation_persist());
    drop(store);
    let reopened = AuthorizedKeysStore::open_or_create(auth_path).unwrap();
    assert!(reopened.managed_binding().unwrap().revoked);
    assert!(!reopened.is_authorized(&pk));
}

#[tokio::test]
async fn managed_newer_epoch_enrollment_keeps_only_the_new_seed() {
    let dir = tempfile::tempdir().unwrap();
    let store = AuthorizedKeysStore::open_or_create(dir.path().join("authorized_keys")).unwrap();
    let (_sk_old, old) = gen_key();
    let (_sk_new, new) = gen_key();

    assert!(managed_enroll(&store, old, "acct-1", 3));
    // Make the old binding active so the old seed is admitted under it.
    let snap = make_snapshot("acct-1", 1, false, vec![(old, "Old")], vec![], vec![]);
    store
        .apply_managed_sync(
            "acct-1",
            3,
            Resp::Active { snapshot: snap },
            future_deadline(),
            now_secs(),
        )
        .unwrap();
    assert!(store.is_session_authorized(&old));

    // A newer epoch replaces the binding: close-old is signalled and only the new seed remains.
    assert!(managed_enroll(&store, new, "acct-1", 4));
    assert_eq!(store.managed_binding().unwrap().epoch, 4);
    assert!(
        !store.is_authorized(&old),
        "old seed must not survive a newer epoch"
    );
    assert!(store.lease_until().is_none());
    assert!(
        !store.is_session_authorized(&new),
        "new seed is not admitted until a snapshot"
    );
}

#[tokio::test]
async fn managed_linked_epoch0_migration_carries_roots_and_admits_only_snapshot_devices() {
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("authorized_keys");
    let (_sk_root, root) = gen_key();
    let (_sk_other, other) = gen_key();
    let (_sk_new, new) = gen_key();
    let now = now_secs();

    let store = AuthorizedKeysStore::open_or_create(auth_path.clone()).unwrap();
    store.add_key(root, "Root".into()).unwrap();
    link_store(&store, &root, "acct-1", now);
    store.add_key(other, "Other".into()).unwrap();
    assert!(store.managed_binding().is_none());

    // Existing linked epoch-0 migration: local roots are carried into the binding.
    assert!(managed_enroll(&store, new, "acct-1", 0));
    assert_eq!(store.managed_binding().unwrap().epoch, 0);
    assert!(
        !store.is_session_authorized(&root),
        "carried roots are not admitted yet"
    );
    assert!(!store.is_session_authorized(&new));

    // Only devices present in the verified active snapshot are admitted.
    let snap = make_snapshot(
        "acct-1",
        2,
        false,
        vec![(root, "Root"), (new, "Phone")],
        vec![],
        vec![],
    );
    store
        .apply_managed_sync(
            "acct-1",
            0,
            Resp::Active { snapshot: snap },
            future_deadline(),
            now,
        )
        .unwrap();
    assert!(store.is_session_authorized(&root));
    assert!(store.is_session_authorized(&new));
    assert!(
        !store.is_session_authorized(&other),
        "device absent from snapshot stays denied"
    );
}
