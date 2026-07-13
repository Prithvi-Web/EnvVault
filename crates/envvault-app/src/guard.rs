//! App-side Guard manager (spec F6). Owns the core [`Guard`] watcher, wires
//! its debounced changes through the classifier with the app's live vault
//! state, and turns findings into native notifications + a typed event the
//! UI listens on.
//!
//! Lifecycle: the Guard is (re)synced whenever the vault is unlocked or a
//! toggle changes. It keeps watching across a lock so `.env` detection never
//! stops — while locked it passes `None` for secrets, so the content scan is
//! silently skipped rather than nagging for a password.

use std::path::PathBuf;
use std::sync::Mutex;

use envvault_core::guard::{self, Guard, GuardChange, GuardFinding};
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::events::GuardFindingEvent;
use crate::state::AppState;
use tauri_specta::Event;

/// Holds the running watcher. `None` until the first unlock arms it.
#[derive(Default)]
pub struct GuardManager {
    guard: Mutex<Option<Guard>>,
}

impl std::fmt::Debug for GuardManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardManager")
    }
}

impl GuardManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of directories currently watched (0 when disarmed or locked
    /// before first unlock).
    pub fn watched_count(&self) -> u32 {
        self.guard
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|g| g.watched_roots().len() as u32)
            .unwrap_or(0)
    }
}

/// Rebuild the set of watched directories from the current (unlocked) vault
/// and its Guard toggles. Safe to call repeatedly; it diffs against what is
/// already watched. No-op when locked (we cannot read the project list).
pub fn resync(app: &AppHandle) {
    let state = app.state::<AppState>();
    let manager = app.state::<GuardManager>();

    // Desired watch set: projects with the Guard enabled, when the global
    // switch is on. Requires the vault unlocked to read the list.
    let desired: Vec<(uuid::Uuid, PathBuf)> = {
        let session = state.session();
        match session.as_ref() {
            Some(s) if s.vault().settings.guard_enabled => s
                .vault()
                .projects
                .iter()
                .filter(|p| p.guard_enabled)
                .map(|p| (p.id, p.path.clone()))
                .collect(),
            // Global switch off, or vault locked with no cached list: watch
            // nothing new (existing watchers below are torn down).
            Some(_) => Vec::new(),
            None => return, // locked: leave existing watchers running
        }
    };

    let mut slot = manager.guard.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_none() {
        match build_guard(app.clone()) {
            Ok(g) => *slot = Some(g),
            Err(e) => {
                eprintln!("guard: could not start watcher: {e}");
                return;
            }
        }
    }
    let Some(guard) = slot.as_mut() else { return };

    let current: Vec<PathBuf> = guard.watched_roots();
    let desired_roots: Vec<PathBuf> = desired
        .iter()
        .filter_map(|(_, p)| p.canonicalize().ok())
        .collect();

    // Drop watchers no longer desired.
    for root in &current {
        if !desired_roots.contains(root) {
            let _ = guard.unwatch(root);
        }
    }
    // Add newly desired watchers (watch() is idempotent per canonical root).
    for (id, path) in &desired {
        let _ = guard.watch(*id, path.clone());
    }
}

fn build_guard(app: AppHandle) -> Result<Guard, envvault_core::CoreError> {
    Guard::new(move |changes| handle_changes(&app, changes))
}

fn handle_changes(app: &AppHandle, changes: Vec<GuardChange>) {
    let state = app.state::<AppState>();

    // Snapshot secrets per project only while unlocked; the plaintext lives
    // in this short-lived Vec and is dropped at the end of the call.
    for change in changes {
        let (project_root, secrets): (Option<PathBuf>, Option<Vec<(String, String)>>) = {
            let session = state.session();
            match session.as_ref() {
                Some(s) => {
                    let project = s.vault().project(change.project_id).ok();
                    let root = project.map(|p| p.path.clone());
                    let secrets = project.map(|p| {
                        p.environments
                            .iter()
                            .flat_map(|e| &e.secrets)
                            .map(|sec| (sec.key.clone(), sec.value.expose().to_string()))
                            .collect::<Vec<_>>()
                    });
                    (root, secrets)
                }
                None => (None, None),
            }
        };

        // We need a project root to classify; if the vault is locked we do
        // not have it, so `.env`/gitignore checks fall back to the change's
        // own parent chain via the canonical root we watched.
        let root = project_root.unwrap_or_else(|| {
            change
                .path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| change.path.clone())
        });

        if let Some(finding) =
            guard::classify_change(change.project_id, &root, &change.path, secrets.as_deref())
        {
            notify(app, &finding);
        }
    }
}

fn notify(app: &AppHandle, finding: &GuardFinding) {
    let (title, body) = describe(finding);

    let _ = app.notification().builder().title(title).body(&body).show();

    // Also hand the finding to the UI (typed event) so it can show an
    // in-app banner with a one-click fix.
    let _ = GuardFindingEvent::from(finding).emit(app);
}

fn describe(finding: &GuardFinding) -> (&'static str, String) {
    match finding {
        GuardFinding::EnvFileAppeared { file_name, .. } => (
            "⚠️ Plaintext secrets appeared",
            format!("A plaintext {file_name} just appeared in a watched project. Secure it?"),
        ),
        GuardFinding::SecretInPlaintext {
            path, secret_keys, ..
        } => {
            let file = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            (
                "⚠️ A vault secret leaked into a file",
                format!(
                    "{} from your vault {} written into {file} in plaintext.",
                    secret_keys.join(", "),
                    if secret_keys.len() == 1 {
                        "was"
                    } else {
                        "were"
                    }
                ),
            )
        }
        GuardFinding::GitignoreStoppedIgnoringEnv { .. } => (
            "⚠️ .gitignore no longer protects .env",
            ".gitignore changed and .env is no longer ignored — a commit could now leak it."
                .to_string(),
        ),
    }
}
