//! Git-safety scanning and the Import & Secure flow (spec F4).
//!
//! Everything here operates on the local filesystem and local git data only.
//! git2 is built with default-features off: no network transports exist in
//! this binary, so none of this can ever fetch or push.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::envfile;
use crate::error::CoreError;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Is this filename a plaintext secrets file we should worry about?
/// `.env.example` and friends are templates — safe by design.
pub fn is_secret_env_file(name: &str) -> bool {
    if !(name == ".env" || name.starts_with(".env.")) {
        return false;
    }
    !matches!(
        name.trim_start_matches(".env."),
        "example" | "sample" | "template" | "dist" | "defaults"
    ) || name == ".env"
}

/// Root-level `.env*` files in a project directory.
pub fn find_env_files(project_root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(project_root) else {
        return Vec::new();
    };
    let mut hits: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter(|e| is_secret_env_file(&e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    hits.sort();
    hits
}

// ---------------------------------------------------------------------------
// Git history exposure (the honest bad news, spec F4.5)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GitExposure {
    /// Commits that introduced or changed the file, across all refs.
    pub commit_count: usize,
    pub first_commit: Option<DateTime<Utc>>,
    pub last_commit: Option<DateTime<Utc>>,
}

/// Equivalent of `git log --all -- <file>`: commits (capped at 20k walked)
/// where the file was added or modified. `Ok(None)` = not a git repo, or the
/// file never appears in history.
pub fn git_history_exposure(
    project_root: &Path,
    file_name: &str,
) -> Result<Option<GitExposure>, CoreError> {
    let repo = match git2::Repository::open(project_root) {
        Ok(r) => r,
        Err(_) => return Ok(None), // not a repo — nothing to report
    };

    let mut walk = repo.revwalk().map_err(git_err)?;
    walk.push_glob("*").map_err(git_err)?;
    if walk.push_head().is_err() {
        // Empty repo (no commits yet).
        return Ok(None);
    }

    let target = Path::new(file_name);
    let mut count = 0usize;
    let mut first: Option<i64> = None;
    let mut last: Option<i64> = None;

    for (walked, oid) in walk.enumerate() {
        if walked >= 20_000 {
            break; // enormous repo: a capped answer is still an honest one
        }
        let oid = oid.map_err(git_err)?;
        let commit = repo.find_commit(oid).map_err(git_err)?;
        let tree = commit.tree().map_err(git_err)?;
        let Ok(entry) = tree.get_path(target) else {
            continue;
        };

        // Count only commits that introduced/changed the blob vs parents.
        let changed = if commit.parent_count() == 0 {
            true
        } else {
            commit.parents().all(|parent| {
                parent
                    .tree()
                    .ok()
                    .and_then(|t| t.get_path(target).ok())
                    .map(|pe| pe.id() != entry.id())
                    .unwrap_or(true)
            })
        };
        if changed {
            count += 1;
            let t = commit.time().seconds();
            first = Some(first.map_or(t, |f: i64| f.min(t)));
            last = Some(last.map_or(t, |l: i64| l.max(t)));
        }
    }

    if count == 0 {
        return Ok(None);
    }
    Ok(Some(GitExposure {
        commit_count: count,
        first_commit: first.and_then(|t| Utc.timestamp_opt(t, 0).single()),
        last_commit: last.and_then(|t| Utc.timestamp_opt(t, 0).single()),
    }))
}

fn git_err(e: git2::Error) -> CoreError {
    CoreError::Git(e.message().to_string())
}

// ---------------------------------------------------------------------------
// The "secure" half: example file, .gitignore, shredded original
// ---------------------------------------------------------------------------

/// Write `<name>.example` with the same keys and empty values — safe to
/// commit. Returns the path written.
pub fn write_env_example(
    project_root: &Path,
    source_name: &str,
    keys: &[String],
) -> Result<PathBuf, CoreError> {
    let example_name = if source_name == ".env" {
        ".env.example".to_string()
    } else {
        format!("{source_name}.example")
    };
    let path = project_root.join(example_name);
    let mut out = String::from(
        "# Written by EnvVault: same keys as the real file, no values.\n# Safe to commit.\n",
    );
    for key in keys {
        out.push_str(key);
        out.push_str("=\n");
    }
    fs::write(&path, out)?;
    Ok(path)
}

/// Ensure `.gitignore` covers `file_name`. Uses git's own semantics when the
/// project is a repo (an already-ignored file gets no duplicate entry).
/// Returns true if `.gitignore` was modified.
pub fn ensure_gitignored(project_root: &Path, file_name: &str) -> Result<bool, CoreError> {
    // Already ignored by any existing rule? Then leave everything alone.
    if let Ok(repo) = git2::Repository::open(project_root) {
        if repo
            .is_path_ignored(Path::new(file_name))
            .map_err(git_err)?
        {
            return Ok(false);
        }
    } else {
        // No repo: fall back to a plain line check.
        let gi = project_root.join(".gitignore");
        if let Ok(existing) = fs::read_to_string(&gi) {
            if existing.lines().any(|l| l.trim() == file_name) {
                return Ok(false);
            }
        }
    }

    let gi = project_root.join(".gitignore");
    let mut content = fs::read_to_string(&gi).unwrap_or_default();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&format!(
        "\n# EnvVault: plaintext secrets never belong in git\n{file_name}\n"
    ));
    fs::write(&gi, content)?;
    Ok(true)
}

/// Where shredded originals are parked for 7 days (outside any repo).
pub fn env_backup_root() -> Result<PathBuf, CoreError> {
    Ok(crate::vault::default_vault_dir()?.join("env-backups"))
}

/// Copy the file to the backup area, overwrite the original's bytes, then
/// unlink it. Returns the backup path.
///
/// Honesty note (for LIMITATIONS.md): on SSDs and copy-on-write filesystems
/// (APFS), overwriting cannot guarantee the old blocks are physically gone —
/// wear leveling may keep them. The unrecoverable-deletion guarantee comes
/// from FileVault/BitLocker-style disk encryption; this overwrite is defense
/// in depth, not magic.
pub fn secure_remove_with_backup(
    file_path: &Path,
    backup_dir: &Path,
) -> Result<PathBuf, CoreError> {
    fs::create_dir_all(backup_dir)?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "env".into());
    let backup_path = backup_dir.join(format!("{name}.{ts}.{}", Uuid::new_v4().simple()));
    fs::copy(file_path, &backup_path)?;

    // Overwrite in place with zeros, flush, then unlink.
    let len = fs::metadata(file_path)?.len();
    {
        let mut f = OpenOptions::new().write(true).open(file_path)?;
        let zeros = vec![0u8; len.min(1 << 20) as usize];
        let mut written = 0u64;
        while written < len {
            let chunk = zeros.len().min((len - written) as usize);
            f.write_all(&zeros[..chunk])?;
            written += chunk as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(file_path)?;
    Ok(backup_path)
}

/// Delete parked backups older than `max_age_days`. Called on app start and
/// after every import.
pub fn cleanup_old_backups(backup_root: &Path, max_age_days: u64) -> Result<usize, CoreError> {
    let Ok(entries) = fs::read_dir(backup_root) else {
        return Ok(0);
    };
    let cutoff =
        SystemTime::now().checked_sub(std::time::Duration::from_secs(max_age_days * 24 * 3600));
    let Some(cutoff) = cutoff else { return Ok(0) };

    let mut removed = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if modified < cutoff && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Import & Secure orchestration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ImportOptions {
    pub write_example: bool,
    pub update_gitignore: bool,
    pub remove_original: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            write_example: true,
            update_gitignore: true,
            remove_original: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct ImportOutcome {
    pub imported: Vec<String>,
    pub updated: Vec<String>,
    pub example_path: Option<PathBuf>,
    pub gitignore_updated: bool,
    pub backup_path: Option<PathBuf>,
    pub exposure: Option<GitExposure>,
    pub warnings: Vec<String>,
}

/// The ten-second rescue (spec F4): parse, import into the vault (in
/// memory — the caller persists), write the example, fix .gitignore, shred
/// the original, and check git history for exposure.
pub fn import_and_secure(
    vault: &mut Vault,
    project_id: Uuid,
    env_id: Uuid,
    env_path: &Path,
    backup_dir: &Path,
    opts: ImportOptions,
) -> Result<ImportOutcome, CoreError> {
    let project_root = env_path
        .parent()
        .ok_or_else(|| CoreError::InvalidInput("env file has no parent directory".into()))?
        .to_path_buf();
    let file_name = env_path
        .file_name()
        .ok_or_else(|| CoreError::InvalidInput("env file has no name".into()))?
        .to_string_lossy()
        .to_string();

    let content = Zeroizing::new(fs::read_to_string(env_path)?);
    let parsed = envfile::parse(&content);

    let mut outcome = ImportOutcome {
        warnings: parsed.warnings.clone(),
        ..Default::default()
    };

    // Exposure check first: the imported secrets get stamped with it.
    outcome.exposure = match git_history_exposure(&project_root, &file_name) {
        Ok(e) => e,
        Err(err) => {
            outcome
                .warnings
                .push(format!("git history could not be checked: {err}"));
            None
        }
    };
    let exposed_at = outcome.exposure.as_ref().and_then(|e| e.last_commit);

    // Upsert every effective entry.
    let mut keys: Vec<String> = Vec::new();
    for entry in parsed.effective_entries() {
        keys.push(entry.key.clone());
        let existing_id = {
            let env = vault.environment_mut(project_id, env_id)?;
            env.secrets
                .iter()
                .find(|s| s.key == entry.key)
                .map(|s| s.id)
        };
        match existing_id {
            Some(secret_id) => {
                vault.update_secret(
                    project_id,
                    env_id,
                    secret_id,
                    crate::vault::SecretUpdate {
                        value: Some(entry.value.clone()),
                        ..Default::default()
                    },
                )?;
                outcome.updated.push(entry.key.clone());
            }
            None => {
                vault.add_secret(
                    project_id,
                    env_id,
                    entry.key.clone(),
                    entry.value.clone(),
                    None,
                )?;
                outcome.imported.push(entry.key.clone());
            }
        }
        if let Some(when) = exposed_at {
            let env = vault.environment_mut(project_id, env_id)?;
            if let Some(s) = env.secrets.iter_mut().find(|s| s.key == entry.key) {
                s.exposed_in_git_at = Some(when);
            }
        }
    }

    if opts.write_example {
        outcome.example_path = Some(write_env_example(&project_root, &file_name, &keys)?);
    }
    if opts.update_gitignore {
        outcome.gitignore_updated = ensure_gitignored(&project_root, &file_name)?;
    }
    if opts.remove_original {
        outcome.backup_path = Some(secure_remove_with_backup(env_path, backup_dir)?);
        let _ = cleanup_old_backups(backup_dir, 7);
    }

    Ok(outcome)
}
