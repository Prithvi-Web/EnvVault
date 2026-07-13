//! Events pushed from Rust to the frontend. Generated into bindings.ts by
//! tauri-specta, so the frontend listens through typed wrappers.

use serde::Serialize;
use specta::Type;

use envvault_core::guard::GuardFinding;

/// Emitted whenever the vault locks for a reason the frontend did not itself
/// initiate (auto-lock on idle). The UI must drop all vault state and return
/// to the lock screen.
#[derive(Debug, Clone, Serialize, Type, tauri_specta::Event)]
pub struct VaultLockedEvent {
    /// "idle" today; "sleep" and "screen-lock" arrive with the platform
    /// hooks.
    pub reason: String,
}

/// Emitted when the Guard catches a dangerous change (spec F6). The UI shows
/// an in-app banner with a one-click fix in addition to the OS notification.
#[derive(Debug, Clone, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct GuardFindingEvent {
    /// "env-appeared" | "secret-in-file" | "gitignore-exposed"
    pub kind: String,
    pub project_id: String,
    pub path: String,
    pub file_name: String,
    /// Populated for the "secret-in-file" kind.
    pub secret_keys: Vec<String>,
}

impl From<&GuardFinding> for GuardFindingEvent {
    fn from(f: &GuardFinding) -> Self {
        match f {
            GuardFinding::EnvFileAppeared {
                project_id,
                path,
                file_name,
            } => Self {
                kind: "env-appeared".into(),
                project_id: project_id.to_string(),
                path: path.display().to_string(),
                file_name: file_name.clone(),
                secret_keys: Vec::new(),
            },
            GuardFinding::SecretInPlaintext {
                project_id,
                path,
                secret_keys,
            } => Self {
                kind: "secret-in-file".into(),
                project_id: project_id.to_string(),
                path: path.display().to_string(),
                file_name: path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                secret_keys: secret_keys.clone(),
            },
            GuardFinding::GitignoreStoppedIgnoringEnv { project_id, path } => Self {
                kind: "gitignore-exposed".into(),
                project_id: project_id.to_string(),
                path: path.display().to_string(),
                file_name: ".gitignore".into(),
                secret_keys: Vec::new(),
            },
        }
    }
}
