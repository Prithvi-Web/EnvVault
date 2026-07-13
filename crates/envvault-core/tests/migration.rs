//! Schema-migration suite (spec §10.1 "Migrations").
//!
//! `tests/fixtures/` holds one vault file per schema version that ever
//! shipped, kept forever. Every current build must open every one of them.
//! When VAULT_SCHEMA_VERSION is bumped, a new fixture is generated and the
//! old ones keep guarding the upgrade path.

use std::path::PathBuf;

use envvault_core::secrecy::SecretString;
use envvault_core::vault::{unlock_vault, VAULT_SCHEMA_VERSION};

const FIXTURE_PASSWORD: &str = "fixture-password-v1";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn v1_fixture_loads_with_current_code() {
    let path = fixture_dir().join("vault-v1.age");
    assert!(
        path.exists(),
        "fixture missing — run: cargo test -p envvault-core generate_v1_fixture -- --ignored"
    );

    let unlocked = unlock_vault(&path, SecretString::from(FIXTURE_PASSWORD.to_owned()))
        .expect("v1 fixture must always load");

    assert_eq!(unlocked.vault().version, VAULT_SCHEMA_VERSION);
    let project = &unlocked.vault().projects[0];
    assert_eq!(project.name, "fixture-project");
    let secret = &project.environments[0].secrets[0];
    assert_eq!(secret.key, "FIXTURE_KEY");
    assert_eq!(secret.value.expose(), "fixture-value-42");
    assert_eq!(secret.note.as_deref(), Some("kept forever"));
}

/// A vault claiming a schema version newer than this build must refuse to
/// open (fail closed) rather than guess.
#[test]
fn future_schema_version_is_refused() {
    use envvault_core::vault::create_vault_with_work_factor;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.age");
    let created =
        create_vault_with_work_factor(&path, SecretString::from("pw".to_owned()), false, 10)
            .unwrap();
    let mut unlocked = created.unlocked;
    unlocked.vault_mut().version = VAULT_SCHEMA_VERSION + 1;
    unlocked.save().unwrap();

    let err = unlock_vault(&path, SecretString::from("pw".to_owned())).unwrap_err();
    assert!(
        matches!(err, envvault_core::CoreError::VaultCorrupted { .. }),
        "got: {err:?}"
    );
}

/// One-time fixture generator (committed output, never rerun for v1):
/// `cargo test -p envvault-core generate_v1_fixture -- --ignored`
#[test]
#[ignore]
fn generate_v1_fixture() {
    use envvault_core::project::Project;
    use envvault_core::secret::{Secret, SecretValue};
    use envvault_core::vault::create_vault_with_work_factor;

    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault-v1.age");
    assert!(
        !path.exists(),
        "fixture already exists; never regenerate shipped fixtures"
    );

    let mut created = create_vault_with_work_factor(
        &path,
        SecretString::from(FIXTURE_PASSWORD.to_owned()),
        false,
        10,
    )
    .unwrap();
    let mut project = Project::new("fixture-project".into(), "/tmp/fixture".into());
    let mut secret = Secret::new(
        "FIXTURE_KEY".into(),
        SecretValue::new("fixture-value-42".into()),
    );
    secret.note = Some("kept forever".into());
    project.environments[0].secrets.push(secret);
    created.unlocked.vault_mut().projects.push(project);
    created.unlocked.save().unwrap();
    println!("wrote {}", path.display());
}
