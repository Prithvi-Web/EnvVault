//! Crypto + vault round-trip suite (spec §10.1 "Crypto").
//!
//! Uses a low scrypt work factor so the suite runs in seconds; the real
//! work factor's timing is measured by `measure_unlock_time` (run with
//! `cargo test -- --ignored --nocapture`).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use envvault_core::secrecy::SecretString;
use envvault_core::secret::{Secret, SecretValue};
use envvault_core::vault::{
    create_vault, create_vault_with_work_factor, unlock_vault, CreatedVault,
};
use envvault_core::CoreError;

const TEST_WORK_FACTOR: u8 = 10;

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// Create a vault with one project ("acme-api") holding one dev secret.
fn seeded_vault(dir: &Path, with_recovery: bool) -> (PathBuf, CreatedVault) {
    let path = dir.join("vault.age");
    let mut created = create_vault_with_work_factor(
        &path,
        pw("correct horse battery staple"),
        with_recovery,
        TEST_WORK_FACTOR,
    )
    .expect("create vault");
    let mut project = envvault_core::project::Project::new("acme-api".into(), dir.join("acme"));
    project.environments[0].secrets.push(Secret::new(
        "STRIPE_SECRET_KEY".into(),
        SecretValue::new("sk_live_hunter2hunter2".into()),
    ));
    created.unlocked.vault_mut().projects.push(project);
    created.unlocked.save().expect("save");
    (path, created)
}

#[test]
fn round_trip_identical_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let (path, created) = seeded_vault(dir.path(), false);

    let unlocked = unlock_vault(&path, pw("correct horse battery staple")).expect("unlock");
    assert_eq!(unlocked.vault(), created.unlocked.vault());
    assert!(!unlocked.via_recovery);

    let secret = &unlocked.vault().projects[0].environments[0].secrets[0];
    assert_eq!(secret.key, "STRIPE_SECRET_KEY");
    assert_eq!(secret.value.expose(), "sk_live_hunter2hunter2");
}

#[test]
fn unicode_and_multiline_secrets_survive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    let mut created =
        create_vault_with_work_factor(&path, pw("pass"), false, TEST_WORK_FACTOR).unwrap();
    let mut project = envvault_core::project::Project::new("p".into(), dir.path().into());
    let tricky = "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----\nümlaut=✓";
    project.environments[0]
        .secrets
        .push(Secret::new("PEM".into(), SecretValue::new(tricky.into())));
    created.unlocked.vault_mut().projects.push(project);
    created.unlocked.save().unwrap();

    let unlocked = unlock_vault(&path, pw("pass")).unwrap();
    assert_eq!(
        unlocked.vault().projects[0].environments[0].secrets[0]
            .value
            .expose(),
        tricky
    );
}

#[test]
fn wrong_password_is_typed_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded_vault(dir.path(), false);

    let err = unlock_vault(&path, pw("wrong password")).unwrap_err();
    assert!(
        matches!(err, CoreError::WrongPassword { .. }),
        "got: {err:?}"
    );
}

#[test]
fn empty_file_is_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    fs::write(&path, b"").unwrap();
    let err = unlock_vault(&path, pw("x")).unwrap_err();
    assert!(
        matches!(err, CoreError::VaultCorrupted { .. }),
        "got: {err:?}"
    );
}

#[test]
fn garbage_file_is_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    fs::write(&path, [0u8, 159, 146, 150, 255, 1, 2, 3]).unwrap();
    let err = unlock_vault(&path, pw("x")).unwrap_err();
    assert!(
        matches!(err, CoreError::VaultCorrupted { .. }),
        "got: {err:?}"
    );
}

#[test]
fn truncated_file_is_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded_vault(dir.path(), false);
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    let err = unlock_vault(&path, pw("correct horse battery staple")).unwrap_err();
    assert!(
        matches!(err, CoreError::VaultCorrupted { .. }),
        "got: {err:?}"
    );
}

#[test]
fn missing_file_is_vault_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let err = unlock_vault(&dir.path().join("nope.age"), pw("x")).unwrap_err();
    assert!(matches!(err, CoreError::VaultNotFound(_)), "got: {err:?}");
}

/// Flip one base64 character inside the armored payload at the given
/// relative position (0.0 = header region, 0.5 = body, ~1.0 = auth tag).
fn corrupt_payload_at(path: &Path, fraction: f64) {
    let mut envelope: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let payload = envelope["payload"].as_str().unwrap().to_owned();

    // Only touch base64 body lines (skip the BEGIN/END armor lines).
    let flippable: Vec<usize> = payload
        .char_indices()
        .filter(|(i, c)| {
            c.is_ascii_alphanumeric()
                && !payload[..*i].ends_with("-----")
                && *i > payload.find('\n').unwrap_or(0)
                && *i < payload.rfind("-----END").unwrap_or(payload.len())
        })
        .map(|(i, _)| i)
        .collect();
    let idx = flippable[((flippable.len() - 1) as f64 * fraction) as usize];

    let mut bytes = payload.into_bytes();
    bytes[idx] = if bytes[idx] == b'A' { b'B' } else { b'A' };
    envelope["payload"] = serde_json::Value::String(String::from_utf8(bytes).unwrap());
    fs::write(path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
}

#[test]
fn corrupted_payload_header_body_and_tag_are_clean_errors() {
    for fraction in [0.02, 0.5, 0.98] {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = seeded_vault(dir.path(), false);
        corrupt_payload_at(&path, fraction);
        let result = unlock_vault(&path, pw("correct horse battery staple"));
        match result {
            Err(CoreError::VaultCorrupted { .. }) => {}
            Err(other) => panic!("flip at {fraction}: expected VaultCorrupted, got {other:?}"),
            Ok(_) => panic!("flip at {fraction}: corrupted vault must never unlock"),
        }
    }
}

#[test]
fn corrupted_wrapped_identity_never_unlocks_and_never_panics() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded_vault(dir.path(), false);

    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let wrapped = envelope["wrapped_identity"].as_str().unwrap().to_owned();
    let mid = wrapped.len() / 2;
    let mut bytes = wrapped.into_bytes();
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    envelope["wrapped_identity"] = serde_json::Value::String(String::from_utf8(bytes).unwrap());
    fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let result = unlock_vault(&path, pw("correct horse battery staple"));
    // AEAD makes tampering indistinguishable from a wrong passphrase; either
    // typed error is acceptable. Success or panic is not.
    match result {
        Err(CoreError::WrongPassword { .. }) | Err(CoreError::VaultCorrupted { .. }) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("tampered wrapped identity must never unlock"),
    }
}

#[test]
fn recovery_key_unlocks_and_password_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let (path, created) = seeded_vault(dir.path(), true);
    let recovery = created.recovery_key.expect("recovery key requested");

    // Recovery key unlocks, flagged as via_recovery.
    let unlocked = unlock_vault(&path, recovery.clone()).expect("recovery unlock");
    assert!(unlocked.via_recovery);
    assert_eq!(unlocked.vault().projects[0].name, "acme-api");

    // The master password still works afterwards.
    let unlocked = unlock_vault(&path, pw("correct horse battery staple")).expect("pw unlock");
    assert!(!unlocked.via_recovery);
}

#[test]
fn saving_after_recovery_unlock_keeps_both_credentials_valid() {
    let dir = tempfile::tempdir().unwrap();
    let (path, created) = seeded_vault(dir.path(), true);
    let recovery = created.recovery_key.unwrap();

    let mut unlocked = unlock_vault(&path, recovery.clone()).unwrap();
    unlocked
        .vault_mut()
        .projects
        .push(envvault_core::project::Project::new(
            "added-via-recovery".into(),
            dir.path().join("x"),
        ));
    unlocked.save().unwrap();

    let via_pw = unlock_vault(&path, pw("correct horse battery staple")).unwrap();
    assert_eq!(via_pw.vault().projects.len(), 2);
    let via_rk = unlock_vault(&path, recovery).unwrap();
    assert_eq!(via_rk.vault().projects.len(), 2);
}

/// The anti-lock-in proof (F9): the payload decrypts with the age crate's
/// standard APIs and the recovery key alone — no EnvVault code involved.
#[test]
fn payload_decrypts_with_standalone_age_and_recovery_key() {
    use envvault_core::age::armor::ArmoredReader;
    use envvault_core::age::x25519;
    use envvault_core::age::Decryptor;
    use envvault_core::secrecy::ExposeSecret;

    let dir = tempfile::tempdir().unwrap();
    let (path, created) = seeded_vault(dir.path(), true);
    let recovery = created.recovery_key.unwrap();

    let envelope: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let payload = envelope["payload"].as_str().unwrap();

    let identity: x25519::Identity = recovery.expose_secret().parse().unwrap();
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(payload.as_bytes())).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(
            &identity as &dyn envvault_core::age::Identity,
        ))
        .unwrap();
    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext).unwrap();

    assert!(plaintext.contains("acme-api"));
    assert!(plaintext.contains("STRIPE_SECRET_KEY"));
}

#[test]
fn change_password_rotates_credential() {
    let dir = tempfile::tempdir().unwrap();
    let (path, created) = seeded_vault(dir.path(), false);
    let mut unlocked = created.unlocked;

    unlocked
        .change_password_with_work_factor(
            &pw("correct horse battery staple"),
            pw("new password entirely"),
            TEST_WORK_FACTOR,
        )
        .expect("change password");

    let err = unlock_vault(&path, pw("correct horse battery staple")).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword { .. }));
    let ok = unlock_vault(&path, pw("new password entirely")).unwrap();
    assert_eq!(ok.vault().projects[0].name, "acme-api");
}

#[test]
fn change_password_requires_current_password() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, created) = seeded_vault(dir.path(), false);
    let mut unlocked = created.unlocked;

    let err = unlocked
        .change_password_with_work_factor(&pw("not the password"), pw("new"), TEST_WORK_FACTOR)
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword { .. }));
}

/// The "forgot password" completion: unlock with the recovery key, set a new
/// master password without knowing the old one. Old password dies, new
/// password works, recovery key keeps working.
#[test]
fn rekey_after_recovery_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let (path, created) = seeded_vault(dir.path(), true);
    let recovery = created.recovery_key.unwrap();

    let mut unlocked = unlock_vault(&path, recovery.clone()).unwrap();
    assert!(unlocked.via_recovery);
    unlocked
        .rekey_with_work_factor(pw("brand new password"), TEST_WORK_FACTOR)
        .unwrap();
    assert!(!unlocked.via_recovery);

    let err = unlock_vault(&path, pw("correct horse battery staple")).unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword { .. }));
    let ok = unlock_vault(&path, pw("brand new password")).unwrap();
    assert_eq!(ok.vault().projects[0].name, "acme-api");
    let via_rk = unlock_vault(&path, recovery).unwrap();
    assert!(via_rk.via_recovery);
}

#[test]
fn creating_over_existing_vault_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded_vault(dir.path(), false);
    let err =
        create_vault_with_work_factor(&path, pw("other"), false, TEST_WORK_FACTOR).unwrap_err();
    assert!(matches!(err, CoreError::VaultAlreadyExists(_)));
}

/// §4.1: the file on disk leaks no plaintext — no project names, no secret
/// keys, no secret values, anywhere in the raw bytes.
#[test]
fn vault_file_leaks_no_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _) = seeded_vault(dir.path(), true);
    let raw = fs::read_to_string(&path).unwrap();

    for needle in [
        "acme-api",
        "STRIPE_SECRET_KEY",
        "sk_live_hunter2hunter2",
        "development",
        "production",
    ] {
        assert!(
            !raw.contains(needle),
            "vault file must not contain plaintext {needle:?}"
        );
    }
}

/// `CreatedVault`'s Debug must never print the recovery key.
#[test]
fn created_vault_debug_redacts_the_recovery_key() {
    use envvault_core::secrecy::ExposeSecret;
    let dir = tempfile::tempdir().unwrap();
    let (_path, created) = seeded_vault(dir.path(), true);
    let printed = format!("{created:?}");
    assert!(printed.contains("[REDACTED]"));
    let key = created.recovery_key.as_ref().unwrap().expose_secret();
    assert!(!printed.contains(key), "Debug leaked the recovery key");
}

/// The dev-only vault-dir override works, and without it the vault resolves
/// into the OS app-data directory — never a relative or project path.
#[test]
fn default_vault_dir_honors_dev_override_and_falls_back_to_app_data() {
    use envvault_core::vault::{default_vault_dir, default_vault_path};

    std::env::set_var("ENVVAULT_DEV_VAULT_DIR", "/tmp/envvault-cov-test");
    assert_eq!(
        default_vault_path().unwrap(),
        Path::new("/tmp/envvault-cov-test").join("vault.age")
    );

    std::env::remove_var("ENVVAULT_DEV_VAULT_DIR");
    let dir = default_vault_dir().unwrap();
    assert!(dir.is_absolute());
    assert!(dir.ends_with("EnvVault"));
}

/// The production-work-factor entry point (`create_vault`, scrypt N=2^18):
/// creates a loadable vault and `lock()` consumes the session. Slow by
/// design (~0.5–1s) — that cost IS the spec'd KDF budget.
#[test]
fn production_work_factor_create_and_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    let created = create_vault(&path, pw("production factor pw"), false).unwrap();
    envvault_core::vault::validate_vault_file(&path).unwrap();
    created.unlocked.lock(); // consumes; every value zeroizes on drop
}

/// An envelope stitched together from two vaults (someone swapped the
/// `recipient` field) must be rejected even with the correct password.
#[test]
fn stitched_envelope_is_rejected_as_corrupted() {
    let dir = tempfile::tempdir().unwrap();
    let (path_a, _a) = seeded_vault(dir.path(), false);
    let path_b = dir.path().join("other/vault.age");
    fs::create_dir_all(path_b.parent().unwrap()).unwrap();
    let created_b =
        create_vault_with_work_factor(&path_b, pw("other pw"), false, TEST_WORK_FACTOR).unwrap();
    let recipient_b = created_b.unlocked.recipient().to_string();

    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&path_a).unwrap()).unwrap();
    envelope["recipient"] = serde_json::Value::String(recipient_b);
    fs::write(&path_a, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let err = unlock_vault(&path_a, pw("correct horse battery staple")).unwrap_err();
    assert!(
        matches!(err, CoreError::VaultCorrupted { .. }),
        "stitched envelope must fail closed, got {err:?}"
    );
}

/// Run manually for the phase gate:
/// `cargo test --release -p envvault-core measure_unlock_time -- --ignored --nocapture`
/// Production work factor, 100 secrets — the exact §9 scenario (<1s, and
/// §4.1 wants the KDF to dominate at ~500ms–1s by design).
#[test]
#[ignore]
fn measure_unlock_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    let mut created = create_vault(&path, pw("timing test password"), false).unwrap();

    // 100 secrets across 5 projects × 2 environments, spec §9's scenario.
    for p in 0..5 {
        let pid = created
            .unlocked
            .vault_mut()
            .add_project(
                format!("timing-project-{p}"),
                dir.path().join(format!("p{p}")),
            )
            .unwrap();
        let (dev, prod) = {
            let proj = created.unlocked.vault().project(pid).unwrap();
            (proj.environments[0].id, proj.environments[1].id)
        };
        for i in 0..10 {
            for (env, tag) in [(dev, "dev"), (prod, "prod")] {
                created
                    .unlocked
                    .vault_mut()
                    .add_secret(
                        pid,
                        env,
                        format!("TIMING_{tag}_{i}").to_uppercase(),
                        SecretValue::new(format!("value-{p}-{tag}-{i}-{}", "x".repeat(40))),
                        None,
                    )
                    .unwrap();
            }
        }
    }
    created.unlocked.save().unwrap();
    let total: usize = created
        .unlocked
        .vault()
        .projects
        .iter()
        .flat_map(|p| &p.environments)
        .map(|e| e.secrets.len())
        .sum();
    assert_eq!(total, 100);
    drop(created);

    let start = std::time::Instant::now();
    let unlocked = unlock_vault(&path, pw("timing test password")).unwrap();
    let elapsed = start.elapsed();
    println!("unlock (scrypt N=2^18, 100 secrets) took {elapsed:?}");
    drop(unlocked);
    assert!(
        elapsed.as_millis() >= 100,
        "unlock suspiciously fast — is the work factor applied?"
    );
}
