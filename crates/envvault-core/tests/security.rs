//! The security test suite (spec §10.3) — executable proofs of the §4
//! invariants, not assertions in prose.
//!
//! Mapping to §10.3, with honest notes on interpretation:
//!
//! 1. "Zero plaintext secret values on disk after a full workflow": secret
//!    values are generated at **runtime** (random UUIDs), so they cannot
//!    exist in any source file or built binary by construction; the test
//!    then exercises every write path (create, save, backups, password
//!    change, rekey, share export, vault export) and scans every byte of
//!    every file produced, plus any file that appeared in the OS temp
//!    directory, for the plaintext values.
//! 2. "No HTTP client in the dependency graph" is enforced by
//!    `scripts/check-no-http.sh` in CI, which resolves the real dependency
//!    graph per shipped target (stronger than grepping Cargo.lock — see the
//!    comment in that script).
//! 3. "A logged secret prints as [REDACTED]": proven via `Debug` formatting
//!    at every nesting depth, plus a compile-time proof that `SecretValue`
//!    has no `Display`/`ToString` at all — the leak the spec worries about
//!    does not merely fail a test, it fails to compile.
//! 4. "`envvault run` writes no `.env` anywhere" lives in the CLI crate's
//!    integration suite (it needs the real binary).
//! 5. "The vault file is ciphertext": no plaintext names/keys/values in the
//!    file, and the encrypted payload measures ≥ 7.0 bits/byte of Shannon
//!    entropy.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use envvault_core::secrecy::SecretString;
use envvault_core::secret::SecretValue;
use envvault_core::share::{
    bundle_from_environment, open_bundle_with_passphrase, seal_bundle_with_work_factor,
    ShareProtection,
};
use envvault_core::vault::{create_vault_with_work_factor, export_vault_copy};

const TEST_WORK_FACTOR: u8 = 10;

fn pw(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// A secret value that provably exists nowhere but in this process's memory.
fn runtime_secret() -> String {
    format!(
        "rtv-{}-{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Every file under `root`, recursively.
fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// §10.3.1 — a full workflow leaves zero plaintext secret bytes on disk
// ---------------------------------------------------------------------------

#[test]
fn full_workflow_leaves_zero_plaintext_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let appdata = dir.path().join("appdata");
    fs::create_dir_all(&appdata).unwrap();

    // Top-level temp entries before, so anything NEW can be scanned too.
    let temp_root = std::env::temp_dir();
    let temp_before: std::collections::BTreeSet<_> = fs::read_dir(&temp_root)
        .map(|es| es.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();

    let secrets: Vec<String> = (0..4).map(|_| runtime_secret()).collect();
    let vault_path = appdata.join("vault.age");

    // The full write-path workout: create → add data → save (rotating
    // backups) → change password → rekey → share export (both protections)
    // → vault backup export → import the bundle into a second vault.
    let created = create_vault_with_work_factor(
        &vault_path,
        pw("workflow master password"),
        true, // recovery key: exercises the second recipient path
        TEST_WORK_FACTOR,
    )
    .unwrap();
    let mut unlocked = created.unlocked;

    let pid = unlocked
        .vault_mut()
        .add_project("workflow-project".into(), dir.path().join("proj"))
        .unwrap();
    let (dev, prod) = {
        let p = unlocked.vault().project(pid).unwrap();
        (p.environments[0].id, p.environments[1].id)
    };
    for (i, value) in secrets.iter().enumerate() {
        let env = if i % 2 == 0 { dev } else { prod };
        unlocked
            .vault_mut()
            .add_secret(
                pid,
                env,
                format!("RUNTIME_SECRET_{i}"),
                SecretValue::new(value.clone()),
                Some("note".into()),
            )
            .unwrap();
    }
    unlocked.save().unwrap();
    unlocked.save().unwrap(); // rotate a backup
    unlocked.save().unwrap(); // and another
    unlocked
        .change_password_with_work_factor(
            &pw("workflow master password"),
            pw("changed master password"),
            TEST_WORK_FACTOR,
        )
        .unwrap();
    unlocked
        .rekey_with_work_factor(pw("rekeyed master password"), TEST_WORK_FACTOR)
        .unwrap();

    // Share exports, one per protection mode.
    let bundle =
        bundle_from_environment(unlocked.vault(), pid, dev, Some(24), chrono::Utc::now()).unwrap();
    let sealed_pass = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::Passphrase(pw("bundle passphrase 42")),
        TEST_WORK_FACTOR,
    )
    .unwrap();
    fs::write(appdata.join("share-pass.age"), &sealed_pass).unwrap();
    let recipient = envvault_core::crypto::generate_identity();
    let sealed_key = seal_bundle_with_work_factor(
        &bundle,
        &ShareProtection::RecipientKeys(vec![recipient.to_public().to_string()]),
        TEST_WORK_FACTOR,
    )
    .unwrap();
    fs::write(appdata.join("share-key.age"), &sealed_key).unwrap();

    // Vault backup export.
    export_vault_copy(&vault_path, &appdata.join("backup.age")).unwrap();

    // Import the bundle into a SECOND vault (the recipient side writes too).
    let second_path = appdata.join("vault-two.age");
    let mut second = create_vault_with_work_factor(
        &second_path,
        pw("second vault password"),
        false,
        TEST_WORK_FACTOR,
    )
    .unwrap()
    .unlocked;
    let spid = second
        .vault_mut()
        .add_project("second-project".into(), dir.path().join("proj2"))
        .unwrap();
    let sdev = second.vault().project(spid).unwrap().environments[0].id;
    let opened = open_bundle_with_passphrase(
        sealed_pass.as_bytes(),
        &pw("bundle passphrase 42"),
        chrono::Utc::now(),
    )
    .unwrap();
    envvault_core::share::apply_bundle(second.vault_mut(), spid, sdev, &opened).unwrap();
    second.save().unwrap();

    // Lock everything (drop → zeroize) before scanning.
    drop(unlocked);
    drop(second);

    // THE ASSERTION: no file we produced — vault, backups, lock files,
    // shares, exports — contains any plaintext secret value.
    let produced = files_under(dir.path());
    assert!(
        produced.len() >= 8,
        "expected a rich file set to scan, got {produced:?}"
    );
    for file in &produced {
        let bytes = fs::read(file).unwrap();
        for value in &secrets {
            assert!(
                !contains_bytes(&bytes, value.as_bytes()),
                "plaintext secret found in {}",
                file.display()
            );
        }
    }

    // And nothing new in the OS temp dir contains them either. (Other
    // processes create temp files concurrently, so only files that appeared
    // during the test are scanned — and only readable ones.)
    if let Ok(entries) = fs::read_dir(&temp_root) {
        for entry in entries.flatten() {
            if temp_before.contains(&entry.file_name()) {
                continue;
            }
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            for value in &secrets {
                assert!(
                    !contains_bytes(&bytes, value.as_bytes()),
                    "plaintext secret leaked into temp file {}",
                    path.display()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// §10.3.5 — the vault file is ciphertext: no names, high entropy
// ---------------------------------------------------------------------------

#[test]
fn vault_file_reveals_no_names_and_payload_is_high_entropy() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = dir.path().join("vault.age");

    let mut unlocked = create_vault_with_work_factor(
        &vault_path,
        pw("entropy test password"),
        false,
        TEST_WORK_FACTOR,
    )
    .unwrap()
    .unlocked;

    // Distinctive markers that must never appear in the file, plus a large
    // random value so ciphertext dominates the entropy measurement.
    let project_name = "zebra-quartz-heliotrope";
    let env_marker = "development"; // default env name — also must not leak
    let key_name = "XYLOPHONE_MARKER_KEY";
    let big_value = (0..128)
        .map(|_| uuid::Uuid::new_v4().simple().to_string())
        .collect::<String>(); // ~4 KB

    let pid = unlocked
        .vault_mut()
        .add_project(project_name.into(), dir.path().join("zq"))
        .unwrap();
    let dev = unlocked.vault().project(pid).unwrap().environments[0].id;
    unlocked
        .vault_mut()
        .add_secret(
            pid,
            dev,
            key_name.into(),
            SecretValue::new(big_value.clone()),
            None,
        )
        .unwrap();
    unlocked.save().unwrap();
    drop(unlocked);

    let raw = fs::read(&vault_path).unwrap();
    for marker in [project_name, key_name, &big_value as &str] {
        assert!(
            !contains_bytes(&raw, marker.as_bytes()),
            "vault file leaks {marker:?} in plaintext"
        );
    }
    // "development"/"production" appear ONLY inside ciphertext.
    let envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let payload = envelope["payload"].as_str().unwrap();
    assert!(!payload.contains(env_marker));

    // Decode the armor to the binary age file and measure Shannon entropy.
    // Random (encrypted) bytes approach 8 bits/byte; ~4 KB of ciphertext
    // plus a small textual age header lands well above 7.0. Structured or
    // plaintext data would sit far below.
    let mut binary = Vec::new();
    envvault_core::age::armor::ArmoredReader::new(payload.as_bytes())
        .read_to_end(&mut binary)
        .unwrap();
    assert!(binary.len() > 4000, "payload unexpectedly small");
    let entropy = shannon_entropy_bits_per_byte(&binary);
    assert!(
        entropy > 7.0,
        "payload entropy {entropy:.2} bits/byte — not ciphertext-like"
    );
}

fn shannon_entropy_bits_per_byte(data: &[u8]) -> f64 {
    let mut counts: BTreeMap<u8, u64> = BTreeMap::new();
    for b in data {
        *counts.entry(*b).or_default() += 1;
    }
    let n = data.len() as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

// ---------------------------------------------------------------------------
// §10.3.3 — a "logged" secret is [REDACTED] at every formatting depth,
// and the compiler refuses the paths that could print it at all
// ---------------------------------------------------------------------------

#[test]
fn debug_formatting_redacts_at_every_depth() {
    let value = runtime_secret();
    let mut vault = envvault_core::vault::Vault::default();
    let pid = vault
        .add_project("redaction-project".into(), "/tmp/redact".into())
        .unwrap();
    let dev = vault.project(pid).unwrap().environments[0].id;
    vault
        .add_secret(
            pid,
            dev,
            "REDACT_ME".into(),
            SecretValue::new(value.clone()),
            None,
        )
        .unwrap();

    // The deliberate "log a secret" from the spec — via the whole model,
    // a single secret, and pretty-printing.
    for formatted in [
        format!("{vault:?}"),
        format!("{vault:#?}"),
        format!(
            "{:?}",
            vault.project(pid).unwrap().environments[0].secrets[0]
        ),
    ] {
        assert!(formatted.contains("[REDACTED]"), "missing redaction marker");
        assert!(
            !formatted.contains(&value),
            "a Debug path printed the plaintext value"
        );
    }
}

// Compile-time proofs: there is no `Display` (and therefore no `ToString`,
// no `format!("{}")`, no accidental `println!`) for secret material. If a
// future change adds one, this test file stops compiling.
static_assertions::assert_not_impl_any!(SecretValue: std::fmt::Display);
static_assertions::assert_not_impl_any!(envvault_core::secret::Secret: std::fmt::Display);
static_assertions::assert_not_impl_any!(envvault_core::vault::Vault: std::fmt::Display);
// The unlocked session cannot be cloned into places the lock cannot reach.
static_assertions::assert_not_impl_any!(envvault_core::vault::UnlockedVault: Clone);
