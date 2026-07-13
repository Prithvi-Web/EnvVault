//! Events pushed from Rust to the frontend. Generated into bindings.ts by
//! tauri-specta, so the frontend listens through typed wrappers.

use serde::Serialize;
use specta::Type;

/// Emitted whenever the vault locks for a reason the frontend did not itself
/// initiate (auto-lock on idle). The UI must drop all vault state and return
/// to the lock screen.
#[derive(Debug, Clone, Serialize, Type, tauri_specta::Event)]
pub struct VaultLockedEvent {
    /// "idle" today; "sleep" and "screen-lock" arrive with the platform
    /// hooks.
    pub reason: String,
}
