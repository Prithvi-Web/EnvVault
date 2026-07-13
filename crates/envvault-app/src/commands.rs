//! Tauri command layer. Each command is a thin wrapper: convert types, call
//! core, map the error, update session state. All real logic and all tests
//! live in `envvault-core`. Heavy work (scrypt) runs on a blocking thread so
//! the UI never stalls.

use envvault_core::secrecy::{ExposeSecret, SecretString};
use envvault_core::vault;
use serde::Serialize;
use specta::Type;
use tauri::State;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub app_version: String,
    pub vault_exists: bool,
    pub unlocked: bool,
    pub via_recovery: bool,
    pub vault_path: String,
    pub auto_lock_minutes: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct CreatedVaultInfo {
    /// Present only when the user opted in. Shown exactly once, never
    /// persisted anywhere by the frontend.
    pub recovery_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct UnlockOutcome {
    /// True when the recovery key (not the master password) opened the
    /// vault; the UI then requires setting a new master password.
    pub via_recovery: bool,
}

#[tauri::command]
#[specta::specta]
pub fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, AppError> {
    let vault_path = vault::default_vault_path()?;
    let session = state.session();
    Ok(VaultStatus {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        vault_exists: vault_path.exists(),
        unlocked: session.is_some(),
        via_recovery: session.as_ref().is_some_and(|s| s.via_recovery),
        vault_path: vault_path.display().to_string(),
        auto_lock_minutes: session
            .as_ref()
            .and_then(|s| s.vault().settings.auto_lock_minutes),
    })
}

#[tauri::command]
#[specta::specta]
pub async fn create_vault(
    state: State<'_, AppState>,
    password: String,
    generate_recovery_key: bool,
) -> Result<CreatedVaultInfo, AppError> {
    let path = vault::default_vault_path()?;
    let password = SecretString::from(password);

    let created = tauri::async_runtime::spawn_blocking(move || {
        vault::create_vault(&path, password, generate_recovery_key)
    })
    .await
    .map_err(AppError::from_join)??;

    let recovery_key = created
        .recovery_key
        .as_ref()
        .map(|k| k.expose_secret().to_string());
    state.set_session(created.unlocked);

    Ok(CreatedVaultInfo { recovery_key })
}

#[tauri::command]
#[specta::specta]
pub async fn unlock(
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<UnlockOutcome, AppError> {
    let path = vault::default_vault_path()?;
    let passphrase = SecretString::from(passphrase);

    let unlocked = tauri::async_runtime::spawn_blocking(move || {
        envvault_core::ratelimit::unlock_vault_guarded(&path, passphrase)
    })
    .await
    .map_err(AppError::from_join)??;

    let via_recovery = unlocked.via_recovery;
    state.set_session(unlocked);

    Ok(UnlockOutcome { via_recovery })
}

#[tauri::command]
#[specta::specta]
pub fn lock_vault(state: State<'_, AppState>) -> Result<bool, AppError> {
    Ok(state.lock_now())
}

/// Set a new master password from a recovery-key session (no old password
/// needed) — or from a normal session as a plain reset.
#[tauri::command]
#[specta::specta]
pub async fn rekey(state: State<'_, AppState>, new_password: String) -> Result<(), AppError> {
    let mut session = state.session().take().ok_or(AppError::VaultLocked)?;
    let new_password = SecretString::from(new_password);

    let (session, result) = tauri::async_runtime::spawn_blocking(move || {
        let result = session.rekey(new_password);
        (session, result)
    })
    .await
    .map_err(AppError::from_join)?;

    // Restore the session whether or not rekey succeeded — a failed rekey
    // leaves the old credentials fully intact.
    state.set_session(session);
    result?;
    Ok(())
}

/// Called (throttled) by the frontend on user interaction so real activity
/// defers the auto-lock. Every other command already counts via `set_session`
/// or its own state access.
#[tauri::command]
#[specta::specta]
pub fn touch_activity(state: State<'_, AppState>) {
    state.touch();
}
