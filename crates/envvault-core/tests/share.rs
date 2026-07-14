//! Secure Share suite (spec F8): bundle round-trips under every protection
//! mode, expiry enforcement, wrong-key and corrupted-bundle behavior, and
//! the apply-to-vault semantics. Low scrypt work factor keeps it fast.

use chrono::{Duration, Utc};
use envvault_core::secrecy::SecretString;
use envvault_core::secret::SecretValue;
use envvault_core::share::{
    apply_bundle, bundle_from_environment, inspect_bundle, open_bundle_with_identity,
    open_bundle_with_passphrase, seal_bundle_with_work_factor, BundleKind, ShareProtection,
};
use envvault_core::vault::Vault;
use envvault_core::CoreError;

const TEST_WORK_FACTOR: u8 = 10;

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// A vault with one project and a dev environment holding two secrets.
fn seeded_vault() -> (Vault, uuid::Uuid, uuid::Uuid) {
    let mut vault = Vault::default();
    let pid = vault
        .add_project("acme-api".into(), "/tmp/acme".into())
        .unwrap();
    let dev = vault.project(pid).unwrap().environments[0].id;
    vault
        .add_secret(
            pid,
            dev,
            "STRIPE_SECRET_KEY".into(),
            SecretValue::new(format!("sk_live_{}", "q".repeat(24))),
            Some("payments".into()),
        )
        .unwrap();
    vault
        .add_secret(
            pid,
            dev,
            "DATABASE_URL".into(),
            SecretValue::new("postgres://localhost/acme".into()),
            None,
        )
        .unwrap();
    (vault, pid, dev)
}

fn seal_with_passphrase(passphrase: &str) -> Vec<u8> {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, Some(24), Utc::now()).unwrap();
    seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::Passphrase(pw(passphrase)),
        TEST_WORK_FACTOR,
    )
    .unwrap()
    .into_bytes()
}

// ---------------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------------

#[test]
fn passphrase_round_trip() {
    let sealed = seal_with_passphrase("glacier otter meadow 42");

    assert_eq!(inspect_bundle(&sealed).unwrap(), BundleKind::Passphrase);

    let opened =
        open_bundle_with_passphrase(&sealed, &pw("glacier otter meadow 42"), Utc::now()).unwrap();
    assert_eq!(opened.project_name, "acme-api");
    assert_eq!(opened.environment_name, "development");
    assert!(!opened.is_production);
    assert_eq!(opened.secrets.len(), 2);
    let stripe = opened
        .secrets
        .iter()
        .find(|s| s.key == "STRIPE_SECRET_KEY")
        .unwrap();
    assert_eq!(stripe.value.expose(), format!("sk_live_{}", "q".repeat(24)));
    assert_eq!(stripe.note.as_deref(), Some("payments"));
}

#[test]
fn x25519_recipient_round_trip() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();

    let identity = envvault_core::crypto::generate_identity();
    let sealed = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::RecipientKeys(vec![identity.to_public().to_string()]),
        TEST_WORK_FACTOR,
    )
    .unwrap();

    assert_eq!(
        inspect_bundle(sealed.as_bytes()).unwrap(),
        BundleKind::RecipientKeys
    );

    let opened = open_bundle_with_identity(sealed.as_bytes(), &identity, Utc::now()).unwrap();
    assert_eq!(opened.secrets.len(), 2);
    assert!(opened.expires_at.is_none());
}

/// The mainline F8 flow: the sender encrypts to the recipient's **vault share
/// key** (the vault's X25519 public key), and the recipient decrypts with the
/// vault identity unwrapped by their master password.
#[test]
fn vault_share_key_round_trip() {
    use envvault_core::vault::{create_vault_with_work_factor, unwrap_vault_identity};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    let created =
        create_vault_with_work_factor(&path, pw("recipient master pw"), false, TEST_WORK_FACTOR)
            .unwrap();
    let share_key = created.unlocked.recipient().to_string();
    assert!(share_key.starts_with("age1"));

    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, Some(48), Utc::now()).unwrap();
    let sealed = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::RecipientKeys(vec![share_key]),
        TEST_WORK_FACTOR,
    )
    .unwrap();

    let identity = unwrap_vault_identity(&path, &pw("recipient master pw")).unwrap();
    let opened = open_bundle_with_identity(sealed.as_bytes(), &identity, Utc::now()).unwrap();
    assert_eq!(opened.secrets.len(), 2);

    // The wrong master password unwraps nothing.
    match unwrap_vault_identity(&path, &pw("wrong")) {
        Err(CoreError::WrongPassword { .. }) => {}
        Err(other) => panic!("expected WrongPassword, got {other:?}"),
        Ok(_) => panic!("wrong password must not unwrap the identity"),
    }
}

/// Bundles encrypted to an SSH public key must decrypt with that SSH private
/// key — the "recipient doesn't use EnvVault" path (they use the stock age
/// CLI). Runs a real ssh-keygen; unix-only, but the code path under test is
/// pure Rust and platform-independent.
#[cfg(unix)]
#[test]
fn ssh_ed25519_recipient_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("id_ed25519");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(&key_path)
        .status()
        .expect("ssh-keygen must be available on unix CI");
    assert!(status.success(), "ssh-keygen failed");
    let public_line = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();

    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    let sealed = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::RecipientKeys(vec![public_line]),
        TEST_WORK_FACTOR,
    )
    .unwrap();

    let private_pem = std::fs::read(&key_path).unwrap();
    let identity = envvault_core::age::ssh::Identity::from_buffer(
        std::io::BufReader::new(private_pem.as_slice()),
        None,
    )
    .unwrap();
    let opened = open_bundle_with_identity(sealed.as_bytes(), &identity, Utc::now()).unwrap();
    assert_eq!(opened.secrets.len(), 2);
}

// ---------------------------------------------------------------------------
// Expiry — enforced on open, honestly documented as a courtesy guardrail
// ---------------------------------------------------------------------------

#[test]
fn expired_bundle_is_refused() {
    let sealed = seal_with_passphrase("glacier otter meadow 42");
    let later = Utc::now() + Duration::hours(25); // sealed with 24h expiry
    let err =
        open_bundle_with_passphrase(&sealed, &pw("glacier otter meadow 42"), later).unwrap_err();
    assert!(matches!(err, CoreError::BundleExpired { .. }));
}

#[test]
fn unexpired_bundle_opens() {
    let sealed = seal_with_passphrase("glacier otter meadow 42");
    let soon = Utc::now() + Duration::hours(23);
    assert!(open_bundle_with_passphrase(&sealed, &pw("glacier otter meadow 42"), soon).is_ok());
}

// ---------------------------------------------------------------------------
// Fail closed: wrong keys, corruption, malformed input
// ---------------------------------------------------------------------------

#[test]
fn wrong_passphrase_is_wrong_key_never_partial_plaintext() {
    let sealed = seal_with_passphrase("glacier otter meadow 42");
    let err =
        open_bundle_with_passphrase(&sealed, &pw("not the passphrase"), Utc::now()).unwrap_err();
    assert!(matches!(err, CoreError::BundleWrongKey));
}

#[test]
fn wrong_identity_is_wrong_key() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    let right = envvault_core::crypto::generate_identity();
    let wrong = envvault_core::crypto::generate_identity();
    let sealed = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::RecipientKeys(vec![right.to_public().to_string()]),
        TEST_WORK_FACTOR,
    )
    .unwrap();
    let err = open_bundle_with_identity(sealed.as_bytes(), &wrong, Utc::now()).unwrap_err();
    assert!(matches!(err, CoreError::BundleWrongKey));
}

#[test]
fn corrupted_truncated_and_garbage_bundles_fail_cleanly() {
    let sealed = seal_with_passphrase("glacier otter meadow 42");

    // Flip a byte mid-body.
    let mut corrupted = sealed.clone();
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0x41;
    let err = open_bundle_with_passphrase(&corrupted, &pw("glacier otter meadow 42"), Utc::now())
        .unwrap_err();
    assert!(
        matches!(err, CoreError::BundleInvalid(_) | CoreError::BundleWrongKey),
        "got {err:?}"
    );

    // Truncated.
    let truncated = &sealed[..sealed.len() / 2];
    assert!(
        open_bundle_with_passphrase(truncated, &pw("glacier otter meadow 42"), Utc::now()).is_err()
    );

    // Garbage and empty.
    assert!(matches!(
        inspect_bundle(b"not an age file at all"),
        Err(CoreError::BundleInvalid(_))
    ));
    assert!(matches!(
        inspect_bundle(b""),
        Err(CoreError::BundleInvalid(_))
    ));
    assert!(
        open_bundle_with_passphrase(b"junk", &pw("glacier otter meadow 42"), Utc::now()).is_err()
    );
}

/// A well-encrypted file whose plaintext is not a share bundle is refused —
/// e.g. someone feeding a random age file to the importer.
#[test]
fn non_bundle_age_file_is_refused() {
    let sealed = envvault_core::crypto::encrypt_with_passphrase(
        b"{\"format\":\"something-else\",\"version\":1}",
        &pw("glacier otter meadow 42"),
        TEST_WORK_FACTOR,
    )
    .unwrap();
    let err = open_bundle_with_passphrase(
        sealed.as_bytes(),
        &pw("glacier otter meadow 42"),
        Utc::now(),
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::BundleInvalid(_)));
}

#[test]
fn future_bundle_version_is_refused() {
    let json = format!(
        "{{\"format\":\"envvault-share\",\"version\":999,\"project_name\":\"x\",\
         \"environment_name\":\"y\",\"is_production\":false,\
         \"created_at\":\"{}\",\"expires_at\":null,\"secrets\":[]}}",
        Utc::now().to_rfc3339()
    );
    let sealed = envvault_core::crypto::encrypt_with_passphrase(
        json.as_bytes(),
        &pw("glacier otter meadow 42"),
        TEST_WORK_FACTOR,
    )
    .unwrap();
    let err = open_bundle_with_passphrase(
        sealed.as_bytes(),
        &pw("glacier otter meadow 42"),
        Utc::now(),
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::BundleInvalid(msg) if msg.contains("newer")));
}

// ---------------------------------------------------------------------------
// Export-side validation
// ---------------------------------------------------------------------------

#[test]
fn short_share_passphrase_is_rejected_at_export() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    let err = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::Passphrase(pw("short")),
        TEST_WORK_FACTOR,
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn invalid_recipient_key_is_rejected() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    for bad in ["garbage", "ssh-ecdsa AAAA...", "age1notakey"] {
        let err = seal_bundle_with_work_factor(
            &bundle,
            &ShareProtection::RecipientKeys(vec![bad.into()]),
            TEST_WORK_FACTOR,
        )
        .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidRecipientKey(_)),
            "{bad}: {err:?}"
        );
    }
    // No keys at all.
    let err = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::RecipientKeys(vec!["  ".into()]),
        TEST_WORK_FACTOR,
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn empty_environment_is_refused() {
    let mut vault = Vault::default();
    let pid = vault
        .add_project("empty".into(), "/tmp/empty".into())
        .unwrap();
    let dev = vault.project(pid).unwrap().environments[0].id;
    let err = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

// ---------------------------------------------------------------------------
// Applying a bundle to a vault
// ---------------------------------------------------------------------------

#[test]
fn apply_adds_updates_and_skips() {
    // Recipient vault: has DATABASE_URL with the SAME value as the bundle,
    // and STRIPE_SECRET_KEY with a DIFFERENT value. Bundle also brings a new
    // key the recipient doesn't have.
    let (mut sender, spid, sdev) = seeded_vault();
    sender
        .add_secret(
            spid,
            sdev,
            "NEW_ONLY_IN_BUNDLE".into(),
            SecretValue::new("fresh-value".into()),
            None,
        )
        .unwrap();
    let bundle = bundle_from_environment(&sender, spid, sdev, None, Utc::now()).unwrap();

    let mut recipient = Vault::default();
    let rpid = recipient
        .add_project("acme-api".into(), "/home/other/acme".into())
        .unwrap();
    let rdev = recipient.project(rpid).unwrap().environments[0].id;
    recipient
        .add_secret(
            rpid,
            rdev,
            "DATABASE_URL".into(),
            SecretValue::new("postgres://localhost/acme".into()),
            None,
        )
        .unwrap();
    recipient
        .add_secret(
            rpid,
            rdev,
            "STRIPE_SECRET_KEY".into(),
            SecretValue::new("sk_test_old_value".into()),
            None,
        )
        .unwrap();
    let old_rotated = recipient.project(rpid).unwrap().environments[0].secrets[1].rotated_at;

    let report = apply_bundle(&mut recipient, rpid, rdev, &bundle).unwrap();
    assert_eq!(report.added, vec!["NEW_ONLY_IN_BUNDLE".to_string()]);
    assert_eq!(report.updated, vec!["STRIPE_SECRET_KEY".to_string()]);
    assert_eq!(report.unchanged, vec!["DATABASE_URL".to_string()]);

    let env = &recipient.project(rpid).unwrap().environments[0];
    let stripe = env
        .secrets
        .iter()
        .find(|s| s.key == "STRIPE_SECRET_KEY")
        .unwrap();
    assert_eq!(stripe.value.expose(), format!("sk_live_{}", "q".repeat(24)));
    // An updated value counts as a rotation.
    assert!(stripe.rotated_at >= old_rotated);
    assert!(env.secrets.iter().any(|s| s.key == "NEW_ONLY_IN_BUNDLE"));
}

#[test]
fn apply_to_missing_environment_is_stale_id() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    let mut other = Vault::default();
    let opid = other.add_project("p".into(), "/tmp/p".into()).unwrap();
    let err = apply_bundle(&mut other, opid, uuid::Uuid::new_v4(), &bundle).unwrap_err();
    assert!(matches!(err, CoreError::StaleId));
}

/// The production-work-factor `seal_bundle` entry point — key recipients
/// use X25519 only (no scrypt), so this is fast even at the real settings.
#[test]
fn production_seal_bundle_round_trips_with_key_recipients() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    let identity = envvault_core::crypto::generate_identity();
    let sealed = envvault_core::share::seal_bundle(
        &bundle,
        &ShareProtection::RecipientKeys(vec![identity.to_public().to_string()]),
    )
    .unwrap();
    let opened = open_bundle_with_identity(sealed.as_bytes(), &identity, Utc::now()).unwrap();
    assert_eq!(opened.secrets.len(), 2);
}

/// Header-inspection edge cases: broken armor, and an age-version line with
/// no recipient stanzas at all. Both must fail closed as invalid bundles.
#[test]
fn inspect_rejects_broken_armor_and_stanzaless_headers() {
    let broken_armor = b"-----BEGIN AGE ENCRYPTED FILE-----\n!!!not base64!!!\n";
    assert!(matches!(
        inspect_bundle(broken_armor),
        Err(CoreError::BundleInvalid(_))
    ));

    let no_stanzas = b"age-encryption.org/v1\n--- MAC\nciphertext";
    assert!(matches!(
        inspect_bundle(no_stanzas),
        Err(CoreError::BundleInvalid(_))
    ));
}

/// The bundle's Debug output must never leak a secret value.
#[test]
fn bundle_debug_is_redacted() {
    let (vault, pid, dev) = seeded_vault();
    let bundle = bundle_from_environment(&vault, pid, dev, None, Utc::now()).unwrap();
    let printed = format!("{bundle:?}");
    assert!(printed.contains("[REDACTED]"));
    assert!(!printed.contains("sk_live"));
}
