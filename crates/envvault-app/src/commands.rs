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

// ---------------------------------------------------------------------------
// Phase 3: projects, environments, secret CRUD.
// DTO rule (§4.3): list/summary types NEVER contain a secret value. Plaintext
// leaves Rust only via `reveal_secret` (explicit user action) and never via
// `copy_secret` (Rust writes the clipboard directly).
// ---------------------------------------------------------------------------

use chrono::{DateTime, Utc};
use envvault_core::detect::KeyType;
use envvault_core::secret::SecretValue;
use envvault_core::vault::{SecretUpdate, Vault};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentSummary {
    pub id: Uuid,
    pub name: String,
    pub is_production: bool,
    pub secret_count: u32,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub environments: Vec<EnvironmentSummary>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub id: Uuid,
    pub key: String,
    pub note: Option<String>,
    pub detected_type: Option<KeyType>,
    pub detected_label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: DateTime<Utc>,
    pub value_length: u32,
}

fn project_summary(p: &envvault_core::project::Project) -> ProjectSummary {
    ProjectSummary {
        id: p.id,
        name: p.name.clone(),
        path: p.path.display().to_string(),
        created_at: p.created_at,
        environments: p
            .environments
            .iter()
            .map(|e| EnvironmentSummary {
                id: e.id,
                name: e.name.clone(),
                is_production: e.is_production,
                secret_count: e.secrets.len() as u32,
            })
            .collect(),
    }
}

/// Run a mutation, persist it, roll the in-memory model back if the save
/// fails. Memory and disk never diverge silently (fail closed, §8.4).
fn mutate_and_save<T>(
    state: &AppState,
    f: impl FnOnce(&mut Vault) -> Result<T, envvault_core::CoreError>,
) -> Result<T, AppError> {
    let mut guard = state.session();
    let session = guard.as_mut().ok_or(AppError::VaultLocked)?;
    let snapshot = session.vault().clone();

    let result = f(session.vault_mut())
        .map_err(AppError::from)
        .and_then(|value| session.save().map_err(AppError::from).map(|()| value));

    match result {
        Ok(value) => {
            state.touch();
            Ok(value)
        }
        Err(e) => {
            *session.vault_mut() = snapshot;
            Err(e)
        }
    }
}

fn read_session<T>(
    state: &AppState,
    f: impl FnOnce(&Vault) -> Result<T, envvault_core::CoreError>,
) -> Result<T, AppError> {
    let guard = state.session();
    let session = guard.as_ref().ok_or(AppError::VaultLocked)?;
    state.touch();
    f(session.vault()).map_err(AppError::from)
}

#[tauri::command]
#[specta::specta]
pub fn list_projects(state: State<'_, AppState>) -> Result<Vec<ProjectSummary>, AppError> {
    read_session(&state, |vault| {
        Ok(vault.projects.iter().map(project_summary).collect())
    })
}

#[tauri::command]
#[specta::specta]
pub fn add_project(
    state: State<'_, AppState>,
    name: String,
    path: String,
) -> Result<ProjectSummary, AppError> {
    let id = mutate_and_save(&state, |vault| vault.add_project(name, path.into()))?;
    read_session(&state, move |vault| Ok(project_summary(vault.project(id)?)))
}

#[tauri::command]
#[specta::specta]
pub fn rename_project(
    state: State<'_, AppState>,
    project_id: Uuid,
    name: String,
) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| vault.rename_project(project_id, name))
}

#[tauri::command]
#[specta::specta]
pub fn remove_project(state: State<'_, AppState>, project_id: Uuid) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| vault.remove_project(project_id))
}

#[tauri::command]
#[specta::specta]
pub fn add_environment(
    state: State<'_, AppState>,
    project_id: Uuid,
    name: String,
    is_production: bool,
) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| {
        vault
            .add_environment(project_id, name, is_production)
            .map(|_| ())
    })
}

#[tauri::command]
#[specta::specta]
pub fn remove_environment(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| vault.remove_environment(project_id, env_id))
}

#[tauri::command]
#[specta::specta]
pub fn list_secrets(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
) -> Result<Vec<SecretMeta>, AppError> {
    read_session(&state, |vault| {
        let project = vault.project(project_id)?;
        let env = project
            .environments
            .iter()
            .find(|e| e.id == env_id)
            .ok_or(envvault_core::CoreError::StaleId)?;
        Ok(env
            .secrets
            .iter()
            .map(|s| SecretMeta {
                id: s.id,
                key: s.key.clone(),
                note: s.note.clone(),
                detected_type: s.detected_type,
                detected_label: s
                    .detected_type
                    .map(|t| envvault_core::detect::label(t).to_string()),
                created_at: s.created_at,
                rotated_at: s.rotated_at,
                value_length: s.value.len() as u32,
            })
            .collect())
    })
}

#[tauri::command]
#[specta::specta]
pub fn add_secret(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    key: String,
    value: String,
    note: Option<String>,
) -> Result<(), AppError> {
    let value = SecretValue::new(value);
    mutate_and_save(&state, |vault| {
        vault
            .add_secret(project_id, env_id, key, value, note)
            .map(|_| ())
    })
}

/// `value: None` keeps the current value; `note: Some("")` clears the note.
#[tauri::command]
#[specta::specta]
pub fn update_secret(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    secret_id: Uuid,
    key: Option<String>,
    value: Option<String>,
    note: Option<String>,
) -> Result<(), AppError> {
    let update = SecretUpdate {
        key,
        value: value.map(SecretValue::new),
        note: note.map(|n| if n.is_empty() { None } else { Some(n) }),
    };
    mutate_and_save(&state, |vault| {
        vault.update_secret(project_id, env_id, secret_id, update)
    })
}

#[tauri::command]
#[specta::specta]
pub fn remove_secret(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    secret_id: Uuid,
) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| {
        vault.remove_secret(project_id, env_id, secret_id)
    })
}

/// The one deliberate path where plaintext crosses to the UI, for display in
/// a masked-by-default row the user explicitly revealed. The frontend keeps
/// it in component-local state only and drops it on hide/navigation/lock.
#[tauri::command]
#[specta::specta]
pub fn reveal_secret(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    secret_id: Uuid,
) -> Result<String, AppError> {
    read_session(&state, |vault| {
        let project = vault.project(project_id)?;
        let env = project
            .environments
            .iter()
            .find(|e| e.id == env_id)
            .ok_or(envvault_core::CoreError::StaleId)?;
        let secret = env
            .secrets
            .iter()
            .find(|s| s.id == secret_id)
            .ok_or(envvault_core::CoreError::StaleId)?;
        Ok(secret.value.expose().to_string())
    })
}

/// Copy without the plaintext ever entering JS. Returns the auto-clear delay
/// so the UI can show an honest countdown.
#[tauri::command]
#[specta::specta]
pub fn copy_secret(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    secret_id: Uuid,
) -> Result<u32, AppError> {
    use envvault_core::secrecy::SecretString;
    let value: SecretString = read_session(&state, |vault| {
        let project = vault.project(project_id)?;
        let env = project
            .environments
            .iter()
            .find(|e| e.id == env_id)
            .ok_or(envvault_core::CoreError::StaleId)?;
        let secret = env
            .secrets
            .iter()
            .find(|s| s.id == secret_id)
            .ok_or(envvault_core::CoreError::StaleId)?;
        Ok(SecretString::from(secret.value.expose().to_string()))
    })?;

    crate::clipboard::copy_with_auto_clear(app, &state, value)?;
    Ok(crate::clipboard::CLEAR_AFTER_SECONDS)
}
