//! Import & Secure suite (spec F4): parser fuzzing, the secure-flow file
//! operations, git-history exposure against a real repository, and the
//! end-to-end orchestration.

use std::fs;
use std::path::Path;
use std::process::Command;

use envvault_core::envfile;
use envvault_core::scanner::{
    cleanup_old_backups, ensure_gitignored, find_env_files, git_history_exposure,
    import_and_secure, is_secret_env_file, secure_remove_with_backup, write_env_example,
    ImportOptions,
};
use envvault_core::vault::Vault;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Fuzzing (spec §10.1: "generate random byte sequences and assert the parser
// never panics and never hangs")
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary unicode garbage: parse must return, never panic.
    #[test]
    fn parser_never_panics_on_arbitrary_strings(input in ".*") {
        let _ = envfile::parse(&input);
    }

    /// Arbitrary bytes (lossy-decoded, as the importer does with real files).
    #[test]
    fn parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let text = String::from_utf8_lossy(&bytes);
        let _ = envfile::parse(&text);
    }

    /// Round trip: any well-formed key/value written as KEY="escaped value"
    /// parses back to exactly the same value. Literal CR is excluded: the
    /// parser normalizes CRLF line endings (so Windows-authored files parse
    /// sanely), which makes a bare `\r` inside a value unrepresentable in
    /// the unescaped multi-line form — write `\r` as the `\\r` escape instead.
    /// (Found by this very fuzzer.)
    #[test]
    fn quoted_values_round_trip(
        key in "[A-Z_][A-Z0-9_]{0,24}",
        value in "[^\\\\\"\\r]{0,64}",  // no backslash, quote, or literal CR
    ) {
        let file = format!("{key}=\"{value}\"\n");
        let parsed = envfile::parse(&file);
        let entry = parsed.effective_entries().find(|e| e.key == key).expect("entry");
        prop_assert_eq!(entry.value.expose(), value.as_str());
    }
}

// ---------------------------------------------------------------------------
// File-name classification + discovery
// ---------------------------------------------------------------------------

#[test]
fn env_file_classification() {
    for secret in [".env", ".env.local", ".env.production", ".env.staging"] {
        assert!(is_secret_env_file(secret), "{secret} should count");
    }
    for safe in [
        ".env.example",
        ".env.sample",
        ".env.template",
        "env",
        "notes.txt",
    ] {
        assert!(!is_secret_env_file(safe), "{safe} should not count");
    }
}

#[test]
fn find_env_files_scans_root_only() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env"), "A=1").unwrap();
    fs::write(dir.path().join(".env.local"), "B=2").unwrap();
    fs::write(dir.path().join(".env.example"), "A=").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/.env"), "C=3").unwrap();

    let names: Vec<String> = find_env_files(dir.path())
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(names, vec![".env", ".env.local"]);
}

// ---------------------------------------------------------------------------
// The "secure" file operations
// ---------------------------------------------------------------------------

#[test]
fn example_file_has_keys_but_no_values() {
    let dir = tempfile::tempdir().unwrap();
    let path =
        write_env_example(dir.path(), ".env", &["STRIPE_KEY".into(), "DB_URL".into()]).unwrap();
    let content = fs::read_to_string(&path).unwrap();
    assert!(path.file_name().unwrap() == ".env.example");
    assert!(content.contains("STRIPE_KEY=\n"));
    assert!(content.contains("DB_URL=\n"));
    assert!(!content.contains("sk_"));
}

#[test]
fn gitignore_created_appended_and_never_duplicated() {
    let dir = tempfile::tempdir().unwrap();

    // No .gitignore yet: created.
    assert!(ensure_gitignored(dir.path(), ".env").unwrap());
    let gi = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(gi.lines().any(|l| l == ".env"));

    // Second call: no duplicate line added.
    assert!(!ensure_gitignored(dir.path(), ".env").unwrap());
    let gi2 = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert_eq!(gi2.matches("\n.env\n").count(), 1);
}

#[test]
fn gitignore_respects_existing_rules_in_a_real_repo() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join(".gitignore"), ".env*\n").unwrap();

    // Already covered by the glob: nothing to do.
    assert!(!ensure_gitignored(dir.path(), ".env.local").unwrap());
}

#[test]
fn secure_remove_backs_up_then_destroys() {
    let dir = tempfile::tempdir().unwrap();
    let backups = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env");
    fs::write(&env, "SECRET=value123").unwrap();

    let backup = secure_remove_with_backup(&env, backups.path()).unwrap();

    assert!(!env.exists(), "original must be gone");
    assert_eq!(fs::read_to_string(&backup).unwrap(), "SECRET=value123");
}

#[test]
fn old_backups_are_cleaned_up() {
    let backups = tempfile::tempdir().unwrap();
    let old = backups.path().join(".env.12345.aaa");
    fs::write(&old, "x").unwrap();
    // Age the file by 8 days.
    let eight_days_ago =
        std::time::SystemTime::now() - std::time::Duration::from_secs(8 * 24 * 3600);
    let ft = filetime::FileTime::from_system_time(eight_days_ago);
    filetime::set_file_mtime(&old, ft).unwrap();
    let fresh = backups.path().join(".env.99999.bbb");
    fs::write(&fresh, "y").unwrap();

    let removed = cleanup_old_backups(backups.path(), 7).unwrap();
    assert_eq!(removed, 1);
    assert!(!old.exists());
    assert!(fresh.exists());
}

// ---------------------------------------------------------------------------
// Git history exposure (real repository)
// ---------------------------------------------------------------------------

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .expect("git runs");
    assert!(status.status.success(), "git {args:?} failed");
}

#[test]
fn git_exposure_counts_commits_that_touched_the_file() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);

    fs::write(dir.path().join(".env"), "A=1").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "one"]);

    fs::write(dir.path().join(".env"), "A=2").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "two"]);

    // A commit that does NOT touch .env must not count.
    fs::write(dir.path().join("readme.md"), "hi").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "three"]);

    let exposure = git_history_exposure(dir.path(), ".env")
        .unwrap()
        .expect("exposure found");
    assert_eq!(exposure.commit_count, 2);
    assert!(exposure.first_commit.is_some());
    assert!(exposure.last_commit >= exposure.first_commit);
}

#[test]
fn git_exposure_none_for_untracked_file_and_non_repo() {
    let dir = tempfile::tempdir().unwrap();
    // Not a repo at all:
    assert!(git_history_exposure(dir.path(), ".env").unwrap().is_none());

    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join("other.txt"), "x").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "no env"]);
    fs::write(dir.path().join(".env"), "A=1").unwrap(); // present but never committed

    assert!(git_history_exposure(dir.path(), ".env").unwrap().is_none());
}

// ---------------------------------------------------------------------------
// End-to-end Import & Secure
// ---------------------------------------------------------------------------

#[test]
fn import_and_secure_full_flow() {
    let dir = tempfile::tempdir().unwrap();
    let backups = tempfile::tempdir().unwrap();

    // A messy .env with history in git.
    let messy = concat!(
        "\u{feff}# app config\r\n",
        "export STRIPE_KEY=sk_live_abc123\r\n",
        "DB_URL='postgres://u:p@h/db'\r\n",
        "MULTI=\"line1\\nline2\"\r\n",
        "DUPE=first\r\n",
        "DUPE=second\r\n",
        "EMPTY=\r\n",
        "broken line without equals\r\n",
        "TAIL=ok",
    );
    git(dir.path(), &["init", "-q"]);
    fs::write(dir.path().join(".env"), messy).unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "oops, committed secrets"]);

    let mut vault = Vault::default();
    let pid = vault
        .add_project("p".into(), dir.path().to_path_buf())
        .unwrap();
    let dev = vault.project(pid).unwrap().environments[0].id;

    // Pre-existing secret with the same key: import should update it.
    vault
        .add_secret(
            pid,
            dev,
            "TAIL".into(),
            envvault_core::secret::SecretValue::new("old".into()),
            None,
        )
        .unwrap();

    let outcome = import_and_secure(
        &mut vault,
        pid,
        dev,
        &dir.path().join(".env"),
        backups.path(),
        ImportOptions::default(),
    )
    .unwrap();

    // Vault contents.
    let env = vault.environment_mut(pid, dev).unwrap();
    let get = |k: &str| env.secrets.iter().find(|s| s.key == k).unwrap();
    assert_eq!(get("STRIPE_KEY").value.expose(), "sk_live_abc123");
    assert_eq!(get("DB_URL").value.expose(), "postgres://u:p@h/db");
    assert_eq!(get("MULTI").value.expose(), "line1\nline2");
    assert_eq!(get("DUPE").value.expose(), "second");
    assert_eq!(get("EMPTY").value.expose(), "");
    assert_eq!(get("TAIL").value.expose(), "ok");

    // Outcome bookkeeping.
    assert_eq!(outcome.updated, vec!["TAIL".to_string()]);
    assert_eq!(outcome.imported.len(), 5);
    assert_eq!(outcome.warnings.len(), 1, "the broken line");

    // Exposure recorded and stamped onto secrets.
    let exposure = outcome.exposure.expect("committed file must be flagged");
    assert_eq!(exposure.commit_count, 1);
    assert!(get("STRIPE_KEY").exposed_in_git_at.is_some());

    // The secure part: original gone, example written, gitignore updated.
    assert!(!dir.path().join(".env").exists());
    let example = fs::read_to_string(dir.path().join(".env.example")).unwrap();
    assert!(example.contains("STRIPE_KEY=\n"));
    assert!(!example.contains("sk_live"));
    assert!(outcome.gitignore_updated);
    let gi = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
    assert!(gi.lines().any(|l| l == ".env"));
    let backup = outcome.backup_path.expect("backup exists");
    assert!(fs::read_to_string(backup)
        .unwrap()
        .contains("sk_live_abc123"));
}
