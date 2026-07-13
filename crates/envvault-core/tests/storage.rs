//! Atomic-write, backup, crash-safety, and cross-process concurrency suite
//! (spec §10.1 "Atomic writes").
//!
//! Crash tests spawn *real child processes* (this same test binary in helper
//! mode) and abort them at injected failpoints inside the write sequence;
//! the parent then asserts the vault survived. The concurrency test runs two
//! processes hammering read-modify-write simultaneously.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use envvault_core::secrecy::SecretString;
use envvault_core::vault::{
    backup_path, create_vault_with_work_factor, unlock_vault, update_vault,
};

const TEST_WORK_FACTOR: u8 = 10;
const PASSWORD: &str = "storage-suite-password";

fn pw() -> SecretString {
    SecretString::from(PASSWORD.to_owned())
}

fn new_vault(dir: &Path) -> PathBuf {
    let path = dir.join("vault.age");
    create_vault_with_work_factor(&path, pw(), false, TEST_WORK_FACTOR).expect("create");
    path
}

fn project_count(path: &Path) -> usize {
    unlock_vault(path, pw())
        .expect("vault must be loadable")
        .vault()
        .projects
        .len()
}

fn add_project(path: &Path, name: &str) {
    update_vault(path, pw(), |vault| {
        vault.projects.push(envvault_core::project::Project::new(
            name.into(),
            "/tmp/x".into(),
        ));
    })
    .expect("update");
}

/// Spawn this test binary in child-helper mode. The child performs one
/// `add_project` save with the given failpoint env var set.
fn spawn_child_save(path: &Path, failpoint_var: &str, stage: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "helper_child_save", "--nocapture"])
        .env("ENVVAULT_CHILD_VAULT", path)
        .env(failpoint_var, stage)
        .output()
        .expect("spawn child")
}

/// Not a real test: the child-process entry point. No-op unless the parent
/// set ENVVAULT_CHILD_VAULT.
#[test]
fn helper_child_save() {
    let Ok(vault) = std::env::var("ENVVAULT_CHILD_VAULT") else {
        return;
    };
    add_project(Path::new(&vault), "from-child");
    // Only reached when no abort failpoint fired.
}

/// Not a real test: hammer-mode child. Performs N read-modify-write cycles.
#[test]
fn helper_child_hammer() {
    let Ok(vault) = std::env::var("ENVVAULT_HAMMER_VAULT") else {
        return;
    };
    let label = std::env::var("ENVVAULT_HAMMER_LABEL").unwrap();
    let count: usize = std::env::var("ENVVAULT_HAMMER_COUNT")
        .unwrap()
        .parse()
        .unwrap();
    for i in 0..count {
        add_project(Path::new(&vault), &format!("{label}-{i}"));
    }
}

// ---------------------------------------------------------------------------
// Backups
// ---------------------------------------------------------------------------

#[test]
fn backups_rotate_and_keep_exactly_three() {
    let dir = tempfile::tempdir().unwrap();
    let path = new_vault(dir.path());

    // Saves producing 1, 2, 3, 4 projects.
    for i in 1..=4 {
        add_project(&path, &format!("p{i}"));
    }

    assert_eq!(project_count(&path), 4);

    // bak.1 = state before last save (3 projects), bak.2 = 2, bak.3 = 1.
    for (n, expected) in [(1u32, 3usize), (2, 2), (3, 1)] {
        let bak = backup_path(&path, n);
        assert!(bak.exists(), "backup {n} must exist");
        let unlocked = unlock_vault(&bak, pw()).expect("backup must be loadable");
        assert_eq!(
            unlocked.vault().projects.len(),
            expected,
            "backup {n} content"
        );
    }
    assert!(
        !backup_path(&path, 4).exists(),
        "only 3 backups may be kept"
    );
}

// ---------------------------------------------------------------------------
// Crash safety (real process aborts at injected failpoints)
// ---------------------------------------------------------------------------

#[test]
fn kill_after_temp_write_before_rename_leaves_vault_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = new_vault(dir.path());
    add_project(&path, "baseline");

    let out = spawn_child_save(&path, "ENVVAULT_TEST_ABORT_AT", "after-temp-write");
    assert!(
        !out.status.success(),
        "child was supposed to abort mid-write"
    );

    // Original vault intact, old content, still loadable.
    assert_eq!(project_count(&path), 1);

    // The next save cleans the orphaned temp file and succeeds.
    add_project(&path, "after-crash");
    assert_eq!(project_count(&path), 2);
    let stale: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(stale.is_empty(), "stale temp files must be cleaned up");
}

#[test]
fn kill_during_partial_temp_write_leaves_vault_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = new_vault(dir.path());
    add_project(&path, "baseline");

    let out = spawn_child_save(&path, "ENVVAULT_TEST_ABORT_AT", "during-temp-write");
    assert!(!out.status.success());
    assert_eq!(project_count(&path), 1);
}

#[test]
fn kill_before_temp_write_leaves_vault_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = new_vault(dir.path());
    add_project(&path, "baseline");

    let out = spawn_child_save(&path, "ENVVAULT_TEST_ABORT_AT", "before-temp-write");
    assert!(!out.status.success());
    assert_eq!(project_count(&path), 1);
}

#[test]
fn disk_full_during_write_returns_error_and_preserves_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = new_vault(dir.path());
    add_project(&path, "baseline");

    let out = spawn_child_save(&path, "ENVVAULT_TEST_FAIL_AT", "during-temp-write");
    // The child gets a typed error (not a crash): update_vault returns Err,
    // the helper's expect() panics the test harness → non-zero exit, and the
    // error message names the cause.
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("disk-full") || stderr.contains("StorageFull"),
        "error should be surfaced clearly, got:\n{stderr}"
    );

    assert_eq!(project_count(&path), 1, "vault must survive disk-full");
}

// ---------------------------------------------------------------------------
// Cross-process concurrency
// ---------------------------------------------------------------------------

#[test]
fn two_processes_hammering_writes_never_corrupt_or_lose_updates() {
    let dir = tempfile::tempdir().unwrap();
    let path = new_vault(dir.path());
    const PER_CHILD: usize = 12;

    let spawn = |label: &str| {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "helper_child_hammer", "--nocapture"])
            .env("ENVVAULT_HAMMER_VAULT", &path)
            .env("ENVVAULT_HAMMER_LABEL", label)
            .env("ENVVAULT_HAMMER_COUNT", PER_CHILD.to_string())
            .spawn()
            .expect("spawn hammer child")
    };

    let mut a = spawn("alpha");
    let mut b = spawn("beta");
    assert!(a.wait().unwrap().success(), "child alpha failed");
    assert!(b.wait().unwrap().success(), "child beta failed");

    // Every single update from both processes must be present (no lost
    // writes, no interleaving) and the vault must load cleanly.
    let unlocked = unlock_vault(&path, pw()).expect("vault must not be corrupt");
    let names: Vec<&str> = unlocked
        .vault()
        .projects
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names.len(), PER_CHILD * 2, "all updates must survive");
    for label in ["alpha", "beta"] {
        for i in 0..PER_CHILD {
            assert!(
                names.contains(&format!("{label}-{i}").as_str()),
                "missing update {label}-{i}"
            );
        }
    }
}
