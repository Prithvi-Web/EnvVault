//! Backup & portability suite (spec F9): vault export, import-replace,
//! import-merge, and the transactional `update_vault_try`.

use std::path::{Path, PathBuf};

use envvault_core::secrecy::SecretString;
use envvault_core::secret::SecretValue;
use envvault_core::vault::{
    create_vault_with_work_factor, export_vault_copy, replace_vault_file, unlock_vault,
    update_vault_try, validate_vault_file, Vault,
};
use envvault_core::CoreError;

const TEST_WORK_FACTOR: u8 = 10;

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// Create a vault file at `dir/name` with one project/secret; returns path.
fn vault_file(dir: &Path, name: &str, password: &str, project: &str) -> PathBuf {
    let path = dir.join(name);
    let mut created =
        create_vault_with_work_factor(&path, pw(password), false, TEST_WORK_FACTOR).unwrap();
    let vault = created.unlocked.vault_mut();
    let pid = vault
        .add_project(project.into(), dir.join(project))
        .unwrap();
    let dev = vault.project(pid).unwrap().environments[0].id;
    vault
        .add_secret(
            pid,
            dev,
            "API_KEY".into(),
            SecretValue::new(format!("value-of-{project}")),
            None,
        )
        .unwrap();
    created.unlocked.save().unwrap();
    path
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

#[test]
fn exported_copy_is_a_working_vault() {
    let dir = tempfile::tempdir().unwrap();
    let src = vault_file(dir.path(), "vault.age", "master pw one", "acme");
    let dest = dir.path().join("backup-copy.age");

    export_vault_copy(&src, &dest).unwrap();

    assert!(validate_vault_file(&dest).is_ok());
    let unlocked = unlock_vault(&dest, pw("master pw one")).unwrap();
    assert_eq!(unlocked.vault().projects[0].name, "acme");
}

#[test]
fn export_refuses_a_corrupted_source() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("vault.age");
    std::fs::write(&src, b"not a vault").unwrap();
    let dest = dir.path().join("backup.age");
    let err = export_vault_copy(&src, &dest).unwrap_err();
    assert!(matches!(err, CoreError::VaultCorrupted { .. }));
    assert!(!dest.exists());
}

// ---------------------------------------------------------------------------
// Import-replace
// ---------------------------------------------------------------------------

#[test]
fn replace_swaps_vault_and_keeps_old_one_in_backups() {
    let dir = tempfile::tempdir().unwrap();
    let live = vault_file(dir.path(), "vault.age", "old password", "old-project");
    let incoming = vault_file(dir.path(), "incoming.age", "new password", "new-project");

    replace_vault_file(&live, &incoming).unwrap();

    // The live path now opens with the imported file's password only.
    let unlocked = unlock_vault(&live, pw("new password")).unwrap();
    assert_eq!(unlocked.vault().projects[0].name, "new-project");
    assert!(matches!(
        unlock_vault(&live, pw("old password")).unwrap_err(),
        CoreError::WrongPassword { .. }
    ));

    // A mistaken replace is recoverable: bak.1 is the pre-replace vault.
    let bak1 = envvault_core::vault::backup_path(&live, 1);
    let old = unlock_vault(&bak1, pw("old password")).unwrap();
    assert_eq!(old.vault().projects[0].name, "old-project");
}

#[test]
fn replace_refuses_invalid_source_and_leaves_vault_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let live = vault_file(dir.path(), "vault.age", "the password", "acme");
    let junk = dir.path().join("junk.age");
    std::fs::write(&junk, b"garbage").unwrap();

    let err = replace_vault_file(&live, &junk).unwrap_err();
    assert!(matches!(err, CoreError::VaultCorrupted { .. }));

    let unlocked = unlock_vault(&live, pw("the password")).unwrap();
    assert_eq!(unlocked.vault().projects[0].name, "acme");
}

// ---------------------------------------------------------------------------
// Merge policy — deterministic, incoming wins on conflicts
// ---------------------------------------------------------------------------

fn small_vault(project: &str, path: &str, key: &str, value: &str) -> Vault {
    let mut vault = Vault::default();
    let pid = vault.add_project(project.into(), path.into()).unwrap();
    let dev = vault.project(pid).unwrap().environments[0].id;
    vault
        .add_secret(pid, dev, key.into(), SecretValue::new(value.into()), None)
        .unwrap();
    vault
}

#[test]
fn merge_into_empty_vault_adds_everything() {
    let mut dst = Vault::default();
    let src = small_vault("acme", "/tmp/acme", "API_KEY", "v1");

    let report = dst.merge_from(src);
    assert_eq!(report.projects_added, 1);
    assert_eq!(report.secrets_added, 1);
    assert_eq!(report.environments_added, 0);
    assert_eq!(report.secrets_updated, 0);
    assert_eq!(dst.projects.len(), 1);
}

#[test]
fn merging_identical_vaults_changes_nothing() {
    let mut dst = small_vault("acme", "/tmp/acme", "API_KEY", "v1");
    let src = dst.clone();
    let before = dst.clone();

    let report = dst.merge_from(src);
    assert_eq!(report, Default::default());
    assert_eq!(dst, before);
}

#[test]
fn projects_match_by_path_then_name() {
    // Same path, different name: merges into the existing project.
    let mut dst = small_vault("frontend", "/tmp/app", "A", "1");
    let src = small_vault("renamed-frontend", "/tmp/app", "B", "2");
    let report = dst.merge_from(src);
    assert_eq!(report.projects_added, 0);
    assert_eq!(report.secrets_added, 1);
    assert_eq!(dst.projects.len(), 1);
    assert_eq!(dst.projects[0].name, "frontend"); // ours kept

    // Different path, same name (case-insensitive): also merges.
    let mut dst = small_vault("backend", "/home/a/backend", "A", "1");
    let src = small_vault("Backend", "/home/b/backend", "B", "2");
    let report = dst.merge_from(src);
    assert_eq!(report.projects_added, 0);
    assert_eq!(dst.projects.len(), 1);

    // Neither matches: added as a new project.
    let mut dst = small_vault("one", "/tmp/one", "A", "1");
    let src = small_vault("two", "/tmp/two", "B", "2");
    let report = dst.merge_from(src);
    assert_eq!(report.projects_added, 1);
    assert_eq!(dst.projects.len(), 2);
}

#[test]
fn conflicting_secret_takes_imported_value_but_keeps_identity() {
    let mut dst = small_vault("acme", "/tmp/acme", "API_KEY", "ours");
    let dst_secret = dst.projects[0].environments[0].secrets[0].clone();

    let src = small_vault("acme", "/tmp/acme", "API_KEY", "theirs");
    let report = dst.merge_from(src);

    assert_eq!(report.secrets_updated, 1);
    assert_eq!(report.secrets_added, 0);
    let merged = &dst.projects[0].environments[0].secrets[0];
    assert_eq!(merged.value.expose(), "theirs");
    assert_eq!(merged.id, dst_secret.id); // stable identity
    assert_eq!(merged.created_at, dst_secret.created_at);
}

#[test]
fn matching_secret_value_is_left_untouched() {
    let mut dst = small_vault("acme", "/tmp/acme", "API_KEY", "same");
    let before = dst.projects[0].environments[0].secrets[0].clone();
    let src = small_vault("acme", "/tmp/acme", "API_KEY", "same");

    let report = dst.merge_from(src);
    assert_eq!(report.secrets_updated, 0);
    assert_eq!(dst.projects[0].environments[0].secrets[0], before);
}

#[test]
fn new_environment_is_added_whole_and_settings_are_kept() {
    let mut dst = small_vault("acme", "/tmp/acme", "A", "1");
    dst.settings.auto_lock_minutes = Some(30);

    let mut src = small_vault("acme", "/tmp/acme", "A", "1");
    src.settings.auto_lock_minutes = None; // must NOT be taken
    let pid = src.projects[0].id;
    let staging = src.add_environment(pid, "staging".into(), false).unwrap();
    src.add_secret(
        pid,
        staging,
        "STAGING_KEY".into(),
        SecretValue::new("s1".into()),
        None,
    )
    .unwrap();

    let report = dst.merge_from(src);
    assert_eq!(report.environments_added, 1);
    assert_eq!(report.secrets_added, 1);
    assert_eq!(dst.settings.auto_lock_minutes, Some(30));
    assert!(dst.projects[0]
        .environments
        .iter()
        .any(|e| e.name == "staging"));
}

// ---------------------------------------------------------------------------
// update_vault_try — transactional read-modify-write
// ---------------------------------------------------------------------------

#[test]
fn update_vault_try_persists_on_ok_and_returns_the_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_file(dir.path(), "vault.age", "the password", "acme");

    let count = update_vault_try(&path, pw("the password"), |vault| {
        let pid = vault.projects[0].id;
        let dev = vault.projects[0].environments[0].id;
        vault.add_secret(
            pid,
            dev,
            "ADDED".into(),
            SecretValue::new("later".into()),
            None,
        )?;
        Ok(vault.projects[0].environments[0].secrets.len())
    })
    .unwrap();
    assert_eq!(count, 2);

    let unlocked = unlock_vault(&path, pw("the password")).unwrap();
    assert_eq!(
        unlocked.vault().projects[0].environments[0].secrets.len(),
        2
    );
}

#[test]
fn update_vault_try_writes_nothing_on_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = vault_file(dir.path(), "vault.age", "the password", "acme");
    let before = std::fs::read(&path).unwrap();

    let err = update_vault_try(&path, pw("the password"), |vault| {
        vault.projects.clear(); // mutate, then fail —
        Err::<(), _>(CoreError::InvalidInput("abort".into()))
    })
    .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));

    // — and the file is byte-identical: the mutation never hit disk.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let unlocked = unlock_vault(&path, pw("the password")).unwrap();
    assert_eq!(unlocked.vault().projects.len(), 1);
}
