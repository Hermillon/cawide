use super::*;

const ACCOUNT: &str = "user-1";

fn secret(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn link(issuer: u8, subject: u8, issued_at: u64) -> DeviceLink {
    let body = DeviceLinkBody::new(
        ACCOUNT.into(),
        public_key_of(&secret(issuer)),
        public_key_of(&secret(subject)),
        format!("device {subject}"),
        issued_at,
    );
    let msg = body.signing_message();
    DeviceLink {
        issuer_sig: sign(&secret(issuer), &msg).to_vec(),
        subject_sig: sign(&secret(subject), &msg).to_vec(),
        body,
    }
}

fn claim() -> MachineClaim {
    let body = MachineClaimBody {
        account_id: ACCOUNT.into(),
        host: public_key_of(&secret(1)),
        claimer: public_key_of(&secret(2)),
        issued_at: 1_700_000_000,
    };
    MachineClaim {
        host_sig: sign(&secret(1), &body.host_signing_message()).to_vec(),
        claimer_sig: sign(&secret(2), &body.claimer_signing_message()).to_vec(),
        body,
    }
}

#[test]
fn registration_round_trip_verifies() {
    let reg = DeviceRegistration {
        account_id: ACCOUNT.into(),
        public_key: public_key_of(&secret(3)),
        name: "iPhone".into(),
        platform: "iphone".into(),
        issued_at: 42,
    };
    reg.validate().unwrap();
    let sig = sign(&secret(3), &reg.signing_message());
    let decoded = DeviceRegistration::from_bytes(&reg.to_bytes()).unwrap();
    assert_eq!(decoded, reg);
    verify(&decoded.public_key, &decoded.signing_message(), &sig).unwrap();
}

#[test]
fn link_round_trip_verifies_and_tampering_fails() {
    let original = link(1, 2, 10);
    let decoded = DeviceLink::from_bytes(&original.to_bytes()).unwrap();
    decoded.verify().unwrap();

    let body_bytes = original.body.to_bytes();
    for i in 0..body_bytes.len() {
        let mut tampered = body_bytes.clone();
        tampered[i] ^= 0x01;
        let Ok(body) = DeviceLinkBody::from_bytes(&tampered) else {
            continue;
        };
        let candidate = DeviceLink {
            body,
            ..original.clone()
        };
        assert!(candidate.verify().is_err(), "byte {i} flip accepted");
    }

    for which in 0..2 {
        let mut tampered = original.clone();
        let sig = if which == 0 {
            &mut tampered.issuer_sig
        } else {
            &mut tampered.subject_sig
        };
        sig[0] ^= 0x01;
        assert_eq!(tampered.verify(), Err(AccountError::BadSignature));
    }
}

#[test]
fn self_link_rejected() {
    let mut l = link(1, 2, 10);
    l.body.subject = l.body.issuer;
    assert_eq!(l.body.validate(), Err(AccountError::Invalid("link")));
    assert!(l.verify().is_err());
}

#[test]
fn claim_round_trip_and_halves_verify() {
    let c = claim();
    let decoded = MachineClaim::from_bytes(&c.to_bytes()).unwrap();
    decoded.verify().unwrap();
    let proof = HostClaimProof {
        body: c.body.clone(),
        host_sig: c.host_sig.clone(),
    };
    HostClaimProof::from_bytes(&proof.to_bytes())
        .unwrap()
        .verify()
        .unwrap();

    let mut bad = c.clone();
    bad.claimer_sig[5] ^= 0x80;
    assert_eq!(bad.verify(), Err(AccountError::BadSignature));
    let mut bad = c.clone();
    bad.body.issued_at += 1;
    assert_eq!(bad.verify(), Err(AccountError::BadSignature));
    // Host and claimer contexts are distinct: the host signature does not
    // stand in for the claimer's.
    let mut swapped = c;
    swapped.body.claimer = swapped.body.host;
    swapped.claimer_sig = swapped.host_sig.clone();
    assert_eq!(swapped.verify(), Err(AccountError::BadSignature));
}

#[test]
fn revocation_and_removal_round_trip() {
    let target = public_key_of(&secret(4));
    let signer = public_key_of(&secret(5));
    let rev = DeviceRevocation {
        account_id: ACCOUNT.into(),
        target,
        issued_at: 7,
    };
    let rev = DeviceRevocation::from_bytes(&rev.to_bytes()).unwrap();
    rev.verify(&signer).unwrap();
    assert_eq!(rev.verify(&target), Err(AccountError::Invalid("signer")));
    let sig = sign(&secret(5), &rev.signing_message());
    verify(&signer, &rev.signing_message(), &sig).unwrap();
    assert_eq!(
        verify(&target, &rev.signing_message(), &sig),
        Err(AccountError::BadSignature)
    );

    let removal = DeviceRemoval {
        account_id: ACCOUNT.into(),
        target,
        issued_at: 8,
    };
    let removal = DeviceRemoval::from_bytes(&removal.to_bytes()).unwrap();
    removal.validate().unwrap();
    let sig = sign(&secret(4), &removal.signing_message());
    verify(&target, &removal.signing_message(), &sig).unwrap();
    // Removal and revocation contexts never collide.
    assert_ne!(removal.signing_message(), rev.signing_message());
}

#[test]
fn oversize_and_trailing_bytes_rejected() {
    let big = vec![0u8; MAX_STATEMENT_BYTES + 1];
    assert_eq!(DeviceLink::from_bytes(&big), Err(AccountError::Malformed));
    let mut bytes = link(1, 2, 3).to_bytes();
    bytes.push(0);
    assert_eq!(DeviceLink::from_bytes(&bytes), Err(AccountError::Malformed));
}

#[test]
fn signature_length_enforced() {
    let pk = public_key_of(&secret(1));
    assert_eq!(
        verify(&pk, b"m", &[0u8; 63]),
        Err(AccountError::BadSignature)
    );
}

#[test]
fn sas_vector_is_stable() {
    let zero = [0u8; 32];
    let sas = approval_sas(&zero, &zero, &zero, &zero);
    assert_eq!(sas.len(), 12);
    assert!(sas.bytes().all(|b| b.is_ascii_digit()));
    // Independently computed with Python hashlib over the same input.
    assert_eq!(sas, "446187664265");
    // Order of keys matters.
    let a = public_key_of(&secret(1));
    let b = public_key_of(&secret(2));
    assert_ne!(
        approval_sas(&a, &b, &zero, &zero),
        approval_sas(&b, &a, &zero, &zero)
    );
}

#[test]
fn commit_binds_nonce() {
    assert_ne!(approval_commit(&[0u8; 32]), approval_commit(&[1u8; 32]));
}

#[test]
fn truncate_utf8_handles_multibyte_and_controls() {
    let input = format!("  {}\u{009b}\u{0007}{}  ", "漢字".repeat(20), "x");
    let out = truncate_utf8(&input, MAX_NAME_LEN);
    assert!(out.len() <= MAX_NAME_LEN);
    assert!(!out.chars().any(char::is_control));
    validate_name(&out).unwrap();
    assert_eq!(truncate_utf8("a\u{009b}b", 64), "ab");
}

#[test]
fn validators() {
    validate_account_id("abc-123").unwrap();
    assert!(validate_account_id("").is_err());
    assert!(validate_account_id("a_b").is_err());
    assert!(validate_account_id(&"a".repeat(65)).is_err());
    assert!(validate_name("  ").is_err());
    assert!(validate_name("a\u{009b}").is_err());
    assert!(validate_name(&"a".repeat(65)).is_err());
    validate_platform("ipad").unwrap();
    assert!(validate_platform("mac").is_err());
    let pk = public_key_of(&secret(9));
    assert_eq!(parse_public_key_hex(&hex::encode(pk)).unwrap(), pk);
    assert!(parse_public_key_hex("zz").is_err());
}

#[test]
fn host_request_message_binds_every_field() {
    let base = host_request_message("POST", HOST_SYNC_PATH, 1, b"{}");
    assert_ne!(
        base,
        host_request_message("POST", HOST_UNLINK_PATH, 1, b"{}")
    );
    assert_ne!(base, host_request_message("POST", HOST_SYNC_PATH, 2, b"{}"));
    assert_ne!(
        base,
        host_request_message("POST", HOST_SYNC_PATH, 1, b"{ }")
    );
    assert!(base.starts_with(CONTEXT_HOST_REQUEST));
}

#[test]
fn expand_trust_chain_admits_transitively() {
    let (a, b, c) = (
        public_key_of(&secret(1)),
        public_key_of(&secret(2)),
        public_key_of(&secret(3)),
    );
    // Links listed in reverse so a second pass is required.
    let links = vec![link(3, 2, 1), link(1, 2, 1)];
    let mut trusted = HashSet::from([a]);
    let admitted = expand_trust(&mut trusted, &links, |_, _| true);
    assert_eq!(admitted, vec![(b, 1), (c, 0)]);
    assert!(trusted.contains(&c));
}

#[test]
fn expand_trust_admit_false_blocks_transit() {
    let c = public_key_of(&secret(3));
    let b = public_key_of(&secret(2));
    let links = vec![link(1, 2, 1), link(2, 3, 1)];
    let mut trusted = HashSet::from([public_key_of(&secret(1))]);
    let admitted = expand_trust(&mut trusted, &links, |k, _| *k != b);
    assert!(admitted.is_empty());
    assert!(!trusted.contains(&c));
}

#[test]
fn expand_trust_ignores_unconnected_links() {
    let links = vec![link(2, 3, 1)];
    let mut trusted = HashSet::from([public_key_of(&secret(1))]);
    assert!(expand_trust(&mut trusted, &links, |_, _| true).is_empty());
    assert_eq!(trusted.len(), 1);
}

#[test]
fn managed_claim_round_trip_and_halves_verify() {
    let body = ManagedClaimBody {
        account_id: ACCOUNT.into(),
        host: public_key_of(&secret(1)),
        claimer: public_key_of(&secret(2)),
        epoch: 3,
        nonce: [0x5au8; 32],
        fresh_pair: true,
    };
    let host_sig = sign(&secret(1), &body.host_signing_message()).to_vec();
    let claimer_sig = sign(&secret(2), &body.claimer_signing_message()).to_vec();

    let proof = ManagedHostProof {
        body: body.clone(),
        host_sig: host_sig.clone(),
    };
    let decoded_proof = ManagedHostProof::from_bytes(&proof.to_bytes()).unwrap();
    decoded_proof.verify().unwrap();
    assert_eq!(decoded_proof, proof);

    let claim = ManagedClaim {
        body: body.clone(),
        host_sig: host_sig.clone(),
        claimer_sig: claimer_sig.clone(),
    };
    let decoded_claim = ManagedClaim::from_bytes(&claim.to_bytes()).unwrap();
    decoded_claim.verify().unwrap();
    assert_eq!(decoded_claim, claim);

    // Tamper with epoch
    let mut bad_epoch = claim.clone();
    bad_epoch.body.epoch += 1;
    assert_eq!(bad_epoch.verify(), Err(AccountError::BadSignature));

    // Tamper with nonce
    let mut bad_nonce = claim.clone();
    bad_nonce.body.nonce[0] ^= 0x01;
    assert_eq!(bad_nonce.verify(), Err(AccountError::BadSignature));

    // Tamper with fresh_pair
    let mut bad_fresh = claim.clone();
    bad_fresh.body.fresh_pair = !bad_fresh.body.fresh_pair;
    assert_eq!(bad_fresh.verify(), Err(AccountError::BadSignature));

    // Tamper with signature
    let mut bad_sig = claim.clone();
    bad_sig.claimer_sig[0] ^= 0x01;
    assert_eq!(bad_sig.verify(), Err(AccountError::BadSignature));

    // Distinct signing contexts
    let mut swapped = claim;
    swapped.body.claimer = swapped.body.host;
    swapped.claimer_sig = swapped.host_sig.clone();
    assert_eq!(swapped.verify(), Err(AccountError::BadSignature));
}

fn session_registration() -> DeviceSessionRegistration {
    DeviceSessionRegistration {
        account_id: ACCOUNT.into(),
        public_key: public_key_of(&secret(4)),
        name: "Phone".into(),
        platform: "iphone".into(),
        issued_at: 1_700_000_100,
        session_id: "sess-abc".into(),
    }
}

#[test]
fn device_session_registration_round_trip_and_signature() {
    let reg = session_registration();
    reg.validate().unwrap();
    let decoded = DeviceSessionRegistration::from_bytes(&reg.to_bytes()).unwrap();
    assert_eq!(decoded, reg);

    // Signed by the device itself; the signature binds every field, including the session id.
    let sig = sign(&secret(4), &reg.signing_message());
    verify(&reg.public_key, &reg.signing_message(), &sig).unwrap();

    let mut other_session = reg.clone();
    other_session.session_id = "sess-xyz".into();
    assert_eq!(
        verify(&reg.public_key, &other_session.signing_message(), &sig),
        Err(AccountError::BadSignature)
    );
}

#[test]
fn device_session_registration_validation_is_strict() {
    let mut bad_platform = session_registration();
    bad_platform.platform = "windows".into();
    assert_eq!(
        bad_platform.validate(),
        Err(AccountError::Invalid("platform"))
    );

    let mut empty_session = session_registration();
    empty_session.session_id.clear();
    assert_eq!(
        empty_session.validate(),
        Err(AccountError::Invalid("session id"))
    );

    let mut long_session = session_registration();
    long_session.session_id = "s".repeat(129);
    assert_eq!(
        long_session.validate(),
        Err(AccountError::Invalid("session id"))
    );

    let mut bad_account = session_registration();
    bad_account.account_id = "bad account".into();
    assert_eq!(
        bad_account.validate(),
        Err(AccountError::Invalid("account id"))
    );

    let mut bad_name = session_registration();
    bad_name.name = "  ".into();
    assert_eq!(bad_name.validate(), Err(AccountError::Invalid("name")));

    let mut ws_session = session_registration();
    ws_session.session_id = "   ".into();
    assert_eq!(
        ws_session.validate(),
        Err(AccountError::Invalid("session id"))
    );

    let mut ctrl_session = session_registration();
    ctrl_session.session_id = "sess\n1".into();
    assert_eq!(
        ctrl_session.validate(),
        Err(AccountError::Invalid("session id"))
    );
}

#[test]
fn managed_claim_body_is_context_separated_from_host_proof() {
    let body = ManagedClaimBody {
        account_id: ACCOUNT.into(),
        host: public_key_of(&secret(1)),
        claimer: public_key_of(&secret(2)),
        epoch: 0,
        nonce: [0x11u8; 32],
        fresh_pair: false,
    };
    // A host signature over the claimer context must not verify as a host proof.
    let claimer_sig = sign(&secret(2), &body.claimer_signing_message());
    let forged = ManagedHostProof {
        body: body.clone(),
        host_sig: claimer_sig.to_vec(),
    };
    assert_eq!(forged.verify(), Err(AccountError::BadSignature));

    // Wrong-length signature bytes are rejected as malformed signatures.
    let short = ManagedHostProof {
        body,
        host_sig: vec![0u8; 63],
    };
    assert_eq!(short.verify(), Err(AccountError::BadSignature));

    // Self-claim (host == claimer) is rejected even with valid signatures.
    let self_body = ManagedClaimBody {
        account_id: ACCOUNT.into(),
        host: public_key_of(&secret(1)),
        claimer: public_key_of(&secret(1)),
        epoch: 0,
        nonce: [0x22u8; 32],
        fresh_pair: false,
    };
    let self_proof = ManagedHostProof {
        body: self_body.clone(),
        host_sig: sign(&secret(1), &self_body.host_signing_message()).to_vec(),
    };
    assert_eq!(self_proof.verify(), Err(AccountError::Invalid("claim")));
    let self_claim = ManagedClaim {
        body: self_body.clone(),
        host_sig: self_proof.host_sig,
        claimer_sig: sign(&secret(1), &self_body.claimer_signing_message()).to_vec(),
    };
    assert_eq!(self_claim.verify(), Err(AccountError::Invalid("claim")));
}

#[test]
fn managed_host_proof_rejects_bad_account_id_and_trailing_bytes() {
    let body = ManagedClaimBody {
        account_id: "bad account".into(),
        host: public_key_of(&secret(1)),
        claimer: public_key_of(&secret(2)),
        epoch: 1,
        nonce: [0x22u8; 32],
        fresh_pair: true,
    };
    let proof = ManagedHostProof {
        body: body.clone(),
        host_sig: sign(&secret(1), &body.host_signing_message()).to_vec(),
    };
    assert_eq!(proof.verify(), Err(AccountError::Invalid("account id")));

    let good_body = ManagedClaimBody {
        account_id: ACCOUNT.into(),
        ..body
    };
    let good = ManagedHostProof {
        host_sig: sign(&secret(1), &good_body.host_signing_message()).to_vec(),
        body: good_body,
    };
    let mut bytes = good.to_bytes();
    bytes.push(0);
    assert_eq!(
        ManagedHostProof::from_bytes(&bytes),
        Err(AccountError::Malformed)
    );
}

#[test]
fn managed_host_unlink_request_json_round_trip() {
    let req = ManagedHostUnlinkRequest {
        account_id: ACCOUNT.into(),
        epoch: 7,
    };
    let json = serde_json::to_string(&req).unwrap();
    let decoded: ManagedHostUnlinkRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, req);
}
#[test]
fn managed_host_sync_response_serde_tagged_json() {
    let active = ManagedHostSyncResponse::Active {
        snapshot: HostTrustSnapshot {
            version: 42,
            account_id: "acct-1".into(),
            locked: false,
            devices: vec![],
            links: vec![],
            revoked: vec![],
        },
    };
    let json_active = serde_json::to_string(&active).unwrap();
    assert!(json_active.contains("\"status\":\"active\""));
    let decoded_active: ManagedHostSyncResponse = serde_json::from_str(&json_active).unwrap();
    assert_eq!(active, decoded_active);

    let pending = ManagedHostSyncResponse::Pending;
    let json_pending = serde_json::to_string(&pending).unwrap();
    assert_eq!(json_pending, "{\"status\":\"pending\"}");
    let decoded_pending: ManagedHostSyncResponse = serde_json::from_str(&json_pending).unwrap();
    assert_eq!(pending, decoded_pending);

    let removed = ManagedHostSyncResponse::Removed;
    let json_removed = serde_json::to_string(&removed).unwrap();
    assert_eq!(json_removed, "{\"status\":\"removed\"}");
    let decoded_removed: ManagedHostSyncResponse = serde_json::from_str(&json_removed).unwrap();
    assert_eq!(removed, decoded_removed);
}
