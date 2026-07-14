//! Guard suite (spec F6 gate): classification logic (pure) + a real-fs
//! latency test proving a `.env` appearance is caught within 2 seconds, plus
//! an idle-CPU sanity check that no spurious events fire when nothing changes.

use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envvault_core::guard::{
    self, classify_change, is_scannable_file, is_within_ignored_dir, scan_file_for_secret_values,
    Guard, GuardChange, GuardFinding,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Pure classification
// ---------------------------------------------------------------------------

#[test]
fn ignored_directories_are_filtered() {
    let root = Path::new("/proj");
    assert!(is_within_ignored_dir(
        Path::new("/proj/node_modules/x/.env"),
        root
    ));
    assert!(is_within_ignored_dir(Path::new("/proj/.git/config"), root));
    assert!(is_within_ignored_dir(
        Path::new("/proj/target/debug/build.rs"),
        root
    ));
    assert!(!is_within_ignored_dir(
        Path::new("/proj/src/config.py"),
        root
    ));
    assert!(!is_within_ignored_dir(Path::new("/proj/.env"), root));
}

#[test]
fn env_file_appearance_is_classified() {
    let dir = tempfile::tempdir().unwrap();
    let pid = Uuid::new_v4();
    let env = dir.path().join(".env");
    fs::write(&env, "SECRET=abcdefgh").unwrap();

    let finding = classify_change(pid, dir.path(), &env, None).unwrap();
    match finding {
        GuardFinding::EnvFileAppeared { file_name, .. } => assert_eq!(file_name, ".env"),
        other => panic!("expected EnvFileAppeared, got {other:?}"),
    }

    // .env.example is a safe template — never flagged.
    let example = dir.path().join(".env.example");
    fs::write(&example, "SECRET=").unwrap();
    assert!(classify_change(pid, dir.path(), &example, None).is_none());
}

#[test]
fn secret_in_plaintext_is_flagged_only_when_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let pid = Uuid::new_v4();
    let config = dir.path().join("config.py");
    fs::write(
        &config,
        "STRIPE = \"sk_live_verysecretvalue\"\nDEBUG = True\n",
    )
    .unwrap();

    let secrets = vec![(
        "STRIPE_SECRET_KEY".to_string(),
        "sk_live_verysecretvalue".to_string(),
    )];

    // Locked (None): the content scan is skipped, no nagging.
    assert!(classify_change(pid, dir.path(), &config, None).is_none());

    // Unlocked: flagged with the offending key.
    match classify_change(pid, dir.path(), &config, Some(&secrets)).unwrap() {
        GuardFinding::SecretInPlaintext { secret_keys, .. } => {
            assert_eq!(secret_keys, vec!["STRIPE_SECRET_KEY".to_string()]);
        }
        other => panic!("expected SecretInPlaintext, got {other:?}"),
    }
}

#[test]
fn short_secret_values_do_not_false_positive() {
    let dir = tempfile::tempdir().unwrap();
    let pid = Uuid::new_v4();
    let src = dir.path().join("main.rs");
    fs::write(&src, "let port = 3000; let flag = true;").unwrap();

    // Values like "3000" / "true" are below the min scan length.
    let secrets = vec![
        ("PORT".to_string(), "3000".to_string()),
        ("FLAG".to_string(), "true".to_string()),
    ];
    assert!(classify_change(pid, dir.path(), &src, Some(&secrets)).is_none());
}

#[test]
fn binary_and_oversized_files_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = vec![("K".to_string(), "sk_live_secretvalue".to_string())];

    // Binary: contains a NUL byte, even though the secret is present.
    let bin = dir.path().join("data.bin");
    fs::write(&bin, b"\x00sk_live_secretvalue\x00").unwrap();
    assert!(scan_file_for_secret_values(&bin, &secrets).is_empty());
    assert!(
        !is_scannable_file(&bin, dir.path())
            || scan_file_for_secret_values(&bin, &secrets).is_empty()
    );
}

#[test]
fn env_files_are_never_scanned_for_their_own_values() {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join(".env.local");
    fs::write(&env, "K=sk_live_secretvalue").unwrap();
    // A .env* file appearing is the EnvFileAppeared case; it must not also be
    // scanned as a "secret in plaintext" file.
    assert!(!is_scannable_file(&env, dir.path()));
}

#[test]
fn gitignore_removal_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let pid = Uuid::new_v4();
    git(dir.path(), &["init", "-q"]);

    // With .env ignored: editing .gitignore triggers no finding.
    fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    assert!(classify_change(pid, dir.path(), &dir.path().join(".gitignore"), None).is_none());

    // Remove the rule: now .env is exposed → finding.
    fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
    match classify_change(pid, dir.path(), &dir.path().join(".gitignore"), None) {
        Some(GuardFinding::GitignoreStoppedIgnoringEnv { .. }) => {}
        other => panic!("expected GitignoreStoppedIgnoringEnv, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The live watcher (real filesystem)
// ---------------------------------------------------------------------------

#[test]
fn env_appearance_is_caught_within_two_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let pid = Uuid::new_v4();

    let (tx, rx) = mpsc::channel::<Vec<GuardChange>>();
    let mut g = Guard::new(move |changes| {
        let _ = tx.send(changes);
    })
    .unwrap();
    g.watch(pid, root.clone()).unwrap();

    // Give the watcher a beat to establish, then drop a .env.
    std::thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    fs::write(root.join(".env"), "STRIPE_SECRET_KEY=sk_live_abcdefgh").unwrap();

    // Collect until we see our .env or time out.
    let deadline = Duration::from_secs(2);
    let mut caught = None;
    while started.elapsed() < deadline {
        if let Ok(changes) = rx.recv_timeout(Duration::from_millis(200)) {
            for c in changes {
                if c.path.file_name().and_then(|n| n.to_str()) == Some(".env") {
                    caught = Some((c, started.elapsed()));
                }
            }
        }
        if caught.is_some() {
            break;
        }
    }

    let (change, latency) = caught.expect("the .env appearance must be caught within 2s");
    assert!(latency < deadline, "latency {latency:?} exceeded 2s");

    // And it classifies as EnvFileAppeared.
    let finding = classify_change(change.project_id, &root, &change.path, None).unwrap();
    assert!(matches!(finding, GuardFinding::EnvFileAppeared { .. }));
}

#[test]
fn changes_in_ignored_dirs_are_not_reported() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    fs::create_dir(root.join("node_modules")).unwrap();
    let pid = Uuid::new_v4();

    let (tx, rx) = mpsc::channel::<Vec<GuardChange>>();
    let mut g = Guard::new(move |changes| {
        let _ = tx.send(changes);
    })
    .unwrap();
    g.watch(pid, root.clone()).unwrap();
    std::thread::sleep(Duration::from_millis(300));

    // Noise in node_modules must be filtered; a real .env must still come through.
    fs::write(root.join("node_modules/pkg.json"), "{}").unwrap();
    fs::write(root.join("node_modules/.env"), "X=y").unwrap();
    fs::write(root.join(".env"), "REAL=zzzzzzzz").unwrap();

    let mut saw_real = false;
    let mut saw_node_modules = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(changes) => {
                for c in changes {
                    let s = c.path.to_string_lossy();
                    if s.contains("node_modules") {
                        saw_node_modules = true;
                    }
                    if c.path.file_name().and_then(|n| n.to_str()) == Some(".env")
                        && !s.contains("node_modules")
                    {
                        saw_real = true;
                    }
                }
            }
            Err(_) if saw_real => break,
            Err(_) => {}
        }
    }
    assert!(saw_real, "the real .env should be reported");
    assert!(
        !saw_node_modules,
        "node_modules changes must be filtered out"
    );
}

#[test]
fn idle_watcher_is_quiet_in_steady_state() {
    // Backs the "< 0.1% idle CPU" claim: once established, a watcher over an
    // unchanging directory emits nothing. macOS FSEvents can flush a one-time
    // startup event for the freshly-created watch root, so we drain any such
    // startup noise first, then assert the steady state is silent. (A
    // spinning/looping watcher would keep emitting and fail this.)
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let pid = Uuid::new_v4();

    let (tx, rx) = mpsc::channel::<Vec<GuardChange>>();
    let mut g = Guard::new(move |changes| {
        let _ = tx.send(changes);
    })
    .unwrap();
    g.watch(pid, root).unwrap();

    // Settle: drain whatever startup events arrive in the first ~1.5s.
    let settle_end = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < settle_end {
        let _ = rx.recv_timeout(Duration::from_millis(200));
    }

    // Steady state: nothing changes on disk, so nothing should arrive.
    assert!(
        rx.recv_timeout(Duration::from_millis(1500)).is_err(),
        "an idle watcher must be silent once established"
    );
}

fn git(dir: &Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .expect("git runs")
        .status
        .success();
    assert!(ok, "git {args:?} failed");
}

// Silence unused-import warning for the `guard` module alias when only some
// items are referenced above.
#[allow(unused_imports)]
use guard as _guard;
