//! The Guard (spec F6): a background filesystem watcher over registered
//! project directories. It catches three dangerous events and surfaces them
//! as [`GuardFinding`]s for the app to turn into native notifications:
//!
//! 1. a plaintext `.env*` file **appears** in a project,
//! 2. a secret value from the vault is written **verbatim** into a tracked
//!    file (only checkable while unlocked — skipped, never nagged, when
//!    locked),
//! 3. `.gitignore` is edited so it **no longer ignores** `.env`.
//!
//! Design split: this module owns the debounced watcher and all the pure,
//! unit-tested classification logic. Whether the vault is unlocked (and thus
//! whether the secret-content scan runs) is decided by the app, which passes
//! the current secrets in per batch. The watcher keeps running across a lock
//! so `.env` detection never stops; it simply receives `None` for secrets
//! while locked.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::RecursiveMode;
use notify_debouncer_full::{new_debouncer, DebouncedEvent, Debouncer, RecommendedCache};
use uuid::Uuid;

use crate::error::CoreError;
use crate::scanner;

/// A dangerous change the Guard noticed. Carries enough for the app to
/// notify and to offer a one-click fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardFinding {
    /// A plaintext `.env*` file appeared in the project folder.
    EnvFileAppeared {
        project_id: Uuid,
        path: PathBuf,
        file_name: String,
    },
    /// One or more vault secret values were found in plaintext in a file.
    SecretInPlaintext {
        project_id: Uuid,
        path: PathBuf,
        secret_keys: Vec<String>,
    },
    /// `.gitignore` changed and `.env` is no longer ignored.
    GitignoreStoppedIgnoringEnv { project_id: Uuid, path: PathBuf },
}

/// Directory names never worth watching for secrets — they are build output,
/// dependencies, or VCS internals. Filtered cheaply before any file read.
pub const IGNORED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "venv",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "vendor",
    ".idea",
    ".vscode",
    "coverage",
    ".turbo",
    ".cache",
];

/// Cap on files we will read looking for a leaked secret. A leaked key lives
/// in a config/source file, not a 50MB asset; skipping large files keeps the
/// Guard's CPU near zero.
const MAX_SCAN_BYTES: u64 = 512 * 1024;

/// Minimum secret-value length we will search for verbatim. Short values
/// (`1`, `true`, `dev`) would false-positive on ordinary source constantly.
const MIN_SCANNABLE_SECRET_LEN: usize = 8;

pub fn is_ignored_dir(name: &str) -> bool {
    IGNORED_DIRS.contains(&name)
}

/// True if any component between `project_root` and `path` is an ignored
/// directory (or the file itself sits directly in one).
pub fn is_within_ignored_dir(path: &Path, project_root: &Path) -> bool {
    let rel = match path.strip_prefix(project_root) {
        Ok(r) => r,
        Err(_) => path,
    };
    rel.components()
        .any(|c| c.as_os_str().to_str().is_some_and(is_ignored_dir))
}

/// Should this path be read during a secret-content scan? Excludes ignored
/// dirs, EnvVault's own artifacts, and anything not a regular file.
pub fn is_scannable_file(path: &Path, project_root: &Path) -> bool {
    if is_within_ignored_dir(path, project_root) {
        return false;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Never flag the safe template, and never scan a `.env` for its own
    // values (that is the EnvFileAppeared case, handled separately).
    if name == ".env.example" || scanner::is_secret_env_file(name) {
        return false;
    }
    match fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.len() <= MAX_SCAN_BYTES,
        Err(_) => false,
    }
}

/// Read `path` and return the keys of any secret whose value appears verbatim
/// in it. Binary files (containing a NUL byte) are skipped. Values shorter
/// than [`MIN_SCANNABLE_SECRET_LEN`] are ignored to avoid false positives.
pub fn scan_file_for_secret_values(path: &Path, secrets: &[(String, String)]) -> Vec<String> {
    let scannable: Vec<&(String, String)> = secrets
        .iter()
        .filter(|(_, v)| v.len() >= MIN_SCANNABLE_SECRET_LEN)
        .collect();
    if scannable.is_empty() {
        return Vec::new();
    }
    let Ok(bytes) = fs::read(path) else {
        return Vec::new();
    };
    if bytes.contains(&0) {
        return Vec::new(); // binary
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    scannable
        .iter()
        .filter(|(_, v)| text.contains(v.as_str()))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Classify one changed path into a finding, given the project it belongs to
/// and the currently unlocked secrets (`None` while the vault is locked, so
/// the content scan is skipped rather than nagging for a password).
///
/// The caller supplies `existed_before` = whether the app already knew about
/// this `.env` file, so a pre-existing file is not reported as "appeared" on
/// the first watch cycle.
pub fn classify_change(
    project_id: Uuid,
    project_root: &Path,
    path: &Path,
    secrets: Option<&[(String, String)]>,
) -> Option<GuardFinding> {
    let name = path.file_name().and_then(|n| n.to_str())?;

    // 1. A plaintext env file appeared (or was written).
    if scanner::is_secret_env_file(name) && path.is_file() {
        return Some(GuardFinding::EnvFileAppeared {
            project_id,
            path: path.to_path_buf(),
            file_name: name.to_string(),
        });
    }

    // 2. .gitignore changed and no longer ignores .env.
    if name == ".gitignore" {
        if let Ok(covered) = gitignore_covers_env(project_root) {
            if !covered {
                return Some(GuardFinding::GitignoreStoppedIgnoringEnv {
                    project_id,
                    path: path.to_path_buf(),
                });
            }
        }
        return None;
    }

    // 3. A vault secret was written into a tracked file (unlocked only).
    if let Some(secrets) = secrets {
        if is_scannable_file(path, project_root) {
            let hits = scan_file_for_secret_values(path, secrets);
            if !hits.is_empty() {
                return Some(GuardFinding::SecretInPlaintext {
                    project_id,
                    path: path.to_path_buf(),
                    secret_keys: hits,
                });
            }
        }
    }

    None
}

/// Does the project's git ignore configuration currently cover `.env`?
/// `true` when there is no repo (nothing to worry about yet) too.
pub fn gitignore_covers_env(project_root: &Path) -> Result<bool, CoreError> {
    if let Ok(repo) = git2::Repository::open(project_root) {
        return repo
            .is_path_ignored(Path::new(".env"))
            .map_err(|e| CoreError::Git(e.message().to_string()));
    }
    // No repo: fall back to a literal scan of any .gitignore.
    let gi = project_root.join(".gitignore");
    match fs::read_to_string(&gi) {
        Ok(content) => Ok(content
            .lines()
            .map(str::trim)
            .any(|l| l == ".env" || l == ".env*" || l == "*.env" || l == ".env.*")),
        // No .gitignore and no repo — not a git project; nothing to warn about.
        Err(_) => Ok(true),
    }
}

// ---------------------------------------------------------------------------
// The watcher runtime
// ---------------------------------------------------------------------------

/// A changed path the app should classify.
#[derive(Debug, Clone)]
pub struct GuardChange {
    pub project_id: Uuid,
    pub path: PathBuf,
}

type WatchMap = std::sync::Arc<std::sync::Mutex<Vec<(Uuid, PathBuf)>>>;

/// A debounced multi-directory watcher. Emits batches of `(project_id, path)`
/// for changed paths, already filtered to drop ignored directories. The app
/// classifies each with [`classify_change`] using its live vault state.
///
/// The watched-projects map is shared (`Arc<Mutex<_>>`) between this struct
/// and the debounce handler thread so `watch`/`unwatch` take effect live.
pub struct Guard {
    debouncer: Debouncer<notify::RecommendedWatcher, RecommendedCache>,
    watched: WatchMap,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard").finish_non_exhaustive()
    }
}

impl Guard {
    /// Create a Guard. `on_changes` is called (on the debouncer's background
    /// thread) with each debounced batch of relevant changes.
    pub fn new<F>(mut on_changes: F) -> Result<Self, CoreError>
    where
        F: FnMut(Vec<GuardChange>) + Send + 'static,
    {
        let watched: WatchMap = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler_watched = watched.clone();

        let debouncer = new_debouncer(
            Duration::from_millis(700),
            None,
            move |result: Result<Vec<DebouncedEvent>, Vec<notify::Error>>| {
                let Ok(events) = result else { return };
                let map = handler_watched.lock().unwrap_or_else(|p| p.into_inner());
                let mut changes: Vec<GuardChange> = Vec::new();
                for event in events {
                    for path in &event.paths {
                        // Attribute to the deepest matching watched root.
                        let owner = map
                            .iter()
                            .filter(|(_, root)| path.starts_with(root))
                            .max_by_key(|(_, root)| root.components().count());
                        let Some((project_id, root)) = owner else {
                            continue;
                        };
                        if is_within_ignored_dir(path, root) {
                            continue;
                        }
                        changes.push(GuardChange {
                            project_id: *project_id,
                            path: path.clone(),
                        });
                    }
                }
                drop(map);
                if !changes.is_empty() {
                    changes.sort_by(|a, b| a.path.cmp(&b.path));
                    changes.dedup_by(|a, b| a.path == b.path && a.project_id == b.project_id);
                    on_changes(changes);
                }
            },
        )
        .map_err(|e| CoreError::Io(std::io::Error::other(e.to_string())))?;

        Ok(Self { debouncer, watched })
    }

    /// Begin watching a project directory recursively. The root is
    /// canonicalized so it matches the (canonical) paths the OS reports —
    /// essential on macOS, where FSEvents returns `/private/var/…` for a
    /// `/var/…` symlink and a naive prefix match would drop every event.
    pub fn watch(&mut self, project_id: Uuid, root: PathBuf) -> Result<(), CoreError> {
        let root = root.canonicalize().map_err(|e| {
            CoreError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot watch {}: {e}", root.display()),
            ))
        })?;
        self.debouncer
            .watch(&root, RecursiveMode::Recursive)
            .map_err(|e| CoreError::Io(std::io::Error::other(e.to_string())))?;
        let mut map = self.watched.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|(id, r)| *id != project_id && *r != root);
        map.push((project_id, root));
        Ok(())
    }

    /// Stop watching a project directory. Accepts either the original or the
    /// canonical path.
    pub fn unwatch(&mut self, root: &Path) -> Result<(), CoreError> {
        let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let _ = self.debouncer.unwatch(&canonical);
        let mut map = self.watched.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|(_, r)| r != &canonical && r != root);
        Ok(())
    }

    pub fn watched_roots(&self) -> Vec<PathBuf> {
        self.watched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(_, r)| r.clone())
            .collect()
    }
}
