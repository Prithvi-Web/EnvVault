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
    // §9 measurement hook: the frontend calls this command on first mount,
    // so process-start → here brackets "cold launch to unlock screen".
    // Prints only when ENVVAULT_PERF is set; no-op otherwise.
    crate::perf_checkpoint("first vault_status (UI mounted)");
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
    _app: tauri::AppHandle,
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
    app: tauri::AppHandle,
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
    crate::guard::resync(&app); // arm the Guard for this session's projects

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
    pub guard_enabled: bool,
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
        guard_enabled: p.guard_enabled,
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
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    name: String,
    path: String,
) -> Result<ProjectSummary, AppError> {
    let id = mutate_and_save(&state, |vault| vault.add_project(name, path.into()))?;
    let summary = read_session(&state, move |vault| Ok(project_summary(vault.project(id)?)))?;
    crate::guard::resync(&app); // start watching the new project
    Ok(summary)
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

// ---------------------------------------------------------------------------
// Phase 4: Import & Secure (spec F4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct EnvFileCandidate {
    pub path: String,
    pub file_name: String,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ExposureInfo {
    pub commit_count: u32,
    pub first_commit: Option<DateTime<Utc>>,
    pub last_commit: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewEntry {
    pub key: String,
    pub value_length: u32,
    pub detected_label: Option<String>,
    /// A secret with this key already exists in the target environment;
    /// importing will update it (and mark it rotated).
    pub will_update: bool,
    /// This key appeared more than once in the file; the last value wins.
    pub had_duplicates: bool,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub file_name: String,
    pub entries: Vec<ImportPreviewEntry>,
    pub warnings: Vec<String>,
    pub exposure: Option<ExposureInfo>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct RotationAdvice {
    pub keys: Vec<String>,
    pub label: String,
    pub url: String,
    pub steps: String,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    pub imported: Vec<String>,
    pub updated: Vec<String>,
    pub example_path: Option<String>,
    pub backup_path: Option<String>,
    pub gitignore_updated: bool,
    pub warnings: Vec<String>,
    pub exposure: Option<ExposureInfo>,
    pub rotation_advice: Vec<RotationAdvice>,
}

fn exposure_dto(e: &envvault_core::scanner::GitExposure) -> ExposureInfo {
    ExposureInfo {
        commit_count: e.commit_count.min(u32::MAX as usize) as u32,
        first_commit: e.first_commit,
        last_commit: e.last_commit,
    }
}

/// Root-level plaintext env files in the project folder (templates like
/// `.env.example` excluded).
#[tauri::command]
#[specta::specta]
pub fn scan_env_files(
    state: State<'_, AppState>,
    project_id: Uuid,
) -> Result<Vec<EnvFileCandidate>, AppError> {
    read_session(&state, |vault| {
        let project = vault.project(project_id)?;
        Ok(envvault_core::scanner::find_env_files(&project.path)
            .into_iter()
            .map(|p| EnvFileCandidate {
                file_name: p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
                path: p.display().to_string(),
            })
            .collect())
    })
}

/// Parse the file and check git history WITHOUT changing anything — the
/// user sees exactly what will happen before confirming.
#[tauri::command]
#[specta::specta]
pub fn preview_env_import(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    path: String,
) -> Result<ImportPreview, AppError> {
    use std::path::Path;
    let path = Path::new(&path);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let content =
        zeroize::Zeroizing::new(
            std::fs::read_to_string(path).map_err(|e| AppError::IoError {
                message: format!("could not read {file_name}: {e}"),
            })?,
        );
    let parsed = envvault_core::envfile::parse(&content);

    read_session(&state, |vault| {
        let project = vault.project(project_id)?;
        let env = project
            .environments
            .iter()
            .find(|e| e.id == env_id)
            .ok_or(envvault_core::CoreError::StaleId)?;

        let duplicated: std::collections::HashSet<&str> = parsed
            .entries
            .iter()
            .filter(|e| e.overridden)
            .map(|e| e.key.as_str())
            .collect();

        let entries = parsed
            .effective_entries()
            .map(|e| ImportPreviewEntry {
                will_update: env.secrets.iter().any(|s| s.key == e.key),
                had_duplicates: duplicated.contains(e.key.as_str()),
                detected_label: envvault_core::detect::detect(&e.key, e.value.expose())
                    .map(|t| envvault_core::detect::label(t).to_string()),
                value_length: e.value.len() as u32,
                key: e.key.clone(),
            })
            .collect();

        let exposure = envvault_core::scanner::git_history_exposure(&project.path, &file_name)
            .unwrap_or(None)
            .as_ref()
            .map(exposure_dto);

        Ok(ImportPreview {
            file_name,
            entries,
            warnings: parsed.warnings.clone(),
            exposure,
        })
    })
}

/// The ten-second rescue: import into the vault, write `.env.example`, fix
/// `.gitignore`, shred the original (7-day backup), report exposure with
/// concrete rotation instructions.
#[tauri::command]
#[specta::specta]
pub fn import_env(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    path: String,
) -> Result<ImportResult, AppError> {
    let backup_dir = envvault_core::scanner::env_backup_root()?;
    let outcome = mutate_and_save(&state, |vault| {
        envvault_core::scanner::import_and_secure(
            vault,
            project_id,
            env_id,
            std::path::Path::new(&path),
            &backup_dir,
            envvault_core::scanner::ImportOptions::default(),
        )
    })?;

    // Group rotation advice by detected type across the touched keys, but
    // only when the file was actually exposed in git history.
    let mut rotation_advice: Vec<RotationAdvice> = Vec::new();
    if outcome.exposure.is_some() {
        let guard = state.session();
        if let Some(session) = guard.as_ref() {
            if let Ok(project) = session.vault().project(project_id) {
                if let Some(env) = project.environments.iter().find(|e| e.id == env_id) {
                    use std::collections::BTreeMap;
                    let mut by_type: BTreeMap<String, (Vec<String>, String, String)> =
                        BTreeMap::new();
                    for key in outcome.imported.iter().chain(outcome.updated.iter()) {
                        let Some(secret) = env.secrets.iter().find(|s| &s.key == key) else {
                            continue;
                        };
                        let Some(t) = secret.detected_type else {
                            continue;
                        };
                        let Some((url, steps)) = envvault_core::detect::rotation_info(t) else {
                            continue;
                        };
                        let label = envvault_core::detect::label(t).to_string();
                        by_type
                            .entry(label)
                            .and_modify(|(keys, _, _)| keys.push(key.clone()))
                            .or_insert((vec![key.clone()], url.to_string(), steps.to_string()));
                    }
                    rotation_advice = by_type
                        .into_iter()
                        .map(|(label, (keys, url, steps))| RotationAdvice {
                            keys,
                            label,
                            url,
                            steps,
                        })
                        .collect();
                }
            }
        }
    }

    Ok(ImportResult {
        imported: outcome.imported,
        updated: outcome.updated,
        example_path: outcome.example_path.map(|p| p.display().to_string()),
        backup_path: outcome.backup_path.map(|p| p.display().to_string()),
        gitignore_updated: outcome.gitignore_updated,
        warnings: outcome.warnings,
        exposure: outcome.exposure.as_ref().map(exposure_dto),
        rotation_advice,
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

// ---------------------------------------------------------------------------
// Phase 6: the Guard (spec F6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct GuardStatus {
    /// Global switch.
    pub enabled: bool,
    /// How many project directories are actively watched right now.
    pub watched_count: u32,
}

#[tauri::command]
#[specta::specta]
pub fn guard_status(
    state: State<'_, AppState>,
    guard_mgr: State<'_, crate::guard::GuardManager>,
) -> Result<GuardStatus, AppError> {
    let enabled = read_session(&state, |vault| Ok(vault.settings.guard_enabled))?;
    Ok(GuardStatus {
        enabled,
        watched_count: guard_mgr.watched_count(),
    })
}

/// Flip the global Guard switch and re-sync watchers immediately.
#[tauri::command]
#[specta::specta]
pub fn set_guard_enabled(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| {
        vault.settings.guard_enabled = enabled;
        Ok(())
    })?;
    crate::guard::resync(&app);
    Ok(())
}

/// Flip a single project's Guard switch and re-sync.
#[tauri::command]
#[specta::specta]
pub fn set_project_guard_enabled(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    project_id: Uuid,
    enabled: bool,
) -> Result<(), AppError> {
    mutate_and_save(&state, |vault| {
        vault.project_mut(project_id)?.guard_enabled = enabled;
        Ok(())
    })?;
    crate::guard::resync(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 8: Secure Share (spec F8)
// ---------------------------------------------------------------------------

/// This vault's share key — its X25519 public key. Teammates encrypt bundles
/// to it; safe to display and copy anywhere.
#[tauri::command]
#[specta::specta]
pub fn share_key(state: State<'_, AppState>) -> Result<String, AppError> {
    let guard = state.session();
    let session = guard.as_ref().ok_or(AppError::VaultLocked)?;
    state.touch();
    Ok(session.recipient().to_string())
}

/// Export one environment as an encrypted share bundle. Exactly one of
/// `passphrase` / `recipient_keys` must be provided (age forbids mixing).
#[tauri::command]
#[specta::specta]
pub async fn export_share_bundle(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Uuid,
    passphrase: Option<String>,
    recipient_keys: Vec<String>,
    expires_in_hours: Option<u32>,
    dest_path: String,
) -> Result<(), AppError> {
    use envvault_core::share::{self, ShareProtection};

    let protection = match (passphrase, recipient_keys.is_empty()) {
        (Some(p), true) => ShareProtection::Passphrase(SecretString::from(p)),
        (None, false) => ShareProtection::RecipientKeys(recipient_keys),
        _ => {
            return Err(AppError::InvalidInput {
                message: "choose either a passphrase or recipient keys".into(),
            })
        }
    };

    // Snapshot the bundle under the session guard, then do the slow part
    // (scrypt + file write) on a blocking thread with no locks held.
    let bundle = read_session(&state, |vault| {
        share::bundle_from_environment(vault, project_id, env_id, expires_in_hours, Utc::now())
    })?;

    tauri::async_runtime::spawn_blocking(move || -> Result<(), AppError> {
        let armored = share::seal_bundle(&bundle, &protection)?;
        let dest = std::path::Path::new(&dest_path);
        std::fs::write(dest, armored.as_bytes()).map_err(|e| AppError::IoError {
            message: format!("could not write {dest_path}: {e}"),
        })?;
        Ok(())
    })
    .await
    .map_err(AppError::from_join)?
}

#[derive(Debug, Clone, Copy, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum ShareBundleKind {
    Passphrase,
    RecipientKeys,
}

/// What kind of credential opens this bundle file — read from the age header
/// without decrypting anything.
#[tauri::command]
#[specta::specta]
pub fn inspect_share_bundle(path: String) -> Result<ShareBundleKind, AppError> {
    let data = std::fs::read(&path).map_err(|e| AppError::IoError {
        message: format!("could not read the bundle file: {e}"),
    })?;
    Ok(
        match envvault_core::share::inspect_bundle(&data).map_err(AppError::from)? {
            envvault_core::share::BundleKind::Passphrase => ShareBundleKind::Passphrase,
            envvault_core::share::BundleKind::RecipientKeys => ShareBundleKind::RecipientKeys,
        },
    )
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SharePreviewEntry {
    pub key: String,
    pub value_length: u32,
    pub detected_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SharePreview {
    pub project_name: String,
    pub environment_name: String,
    pub is_production: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub entries: Vec<SharePreviewEntry>,
}

/// Decrypt a bundle and hold it in Rust as the pending import. Only metadata
/// crosses to the UI (DTO rule §4.3) — the values stay here until confirm.
/// `passphrase` opens passphrase bundles; `master_password` unwraps the vault
/// identity for key bundles (rate-limited like any password attempt).
#[tauri::command]
#[specta::specta]
pub async fn preview_share_import(
    state: State<'_, AppState>,
    path: String,
    passphrase: Option<String>,
    master_password: Option<String>,
) -> Result<SharePreview, AppError> {
    use envvault_core::share::{self, BundleKind};

    let data = std::fs::read(&path).map_err(|e| AppError::IoError {
        message: format!("could not read the bundle file: {e}"),
    })?;
    let kind = share::inspect_bundle(&data)?;

    let bundle =
        tauri::async_runtime::spawn_blocking(move || -> Result<share::ShareBundle, AppError> {
            match kind {
                BundleKind::Passphrase => {
                    let passphrase = passphrase.ok_or(AppError::InvalidInput {
                        message: "this bundle needs its passphrase".into(),
                    })?;
                    Ok(share::open_bundle_with_passphrase(
                        &data,
                        &SecretString::from(passphrase),
                        Utc::now(),
                    )?)
                }
                BundleKind::RecipientKeys => {
                    let master = master_password.ok_or(AppError::InvalidInput {
                        message: "enter your master password to decrypt this bundle".into(),
                    })?;
                    let vault_path = vault::default_vault_path()?;
                    let identity = envvault_core::ratelimit::unwrap_vault_identity_guarded(
                        &vault_path,
                        &SecretString::from(master),
                    )?;
                    Ok(share::open_bundle_with_identity(
                        &data,
                        &identity,
                        Utc::now(),
                    )?)
                }
            }
        })
        .await
        .map_err(AppError::from_join)??;

    let preview = SharePreview {
        project_name: bundle.project_name.clone(),
        environment_name: bundle.environment_name.clone(),
        is_production: bundle.is_production,
        created_at: bundle.created_at,
        expires_at: bundle.expires_at,
        entries: bundle
            .secrets
            .iter()
            .map(|s| SharePreviewEntry {
                key: s.key.clone(),
                value_length: s.value.len() as u32,
                detected_label: envvault_core::detect::detect(&s.key, s.value.expose())
                    .map(|t| envvault_core::detect::label(t).to_string()),
            })
            .collect(),
    };
    state.set_pending_share(bundle);
    state.touch();
    Ok(preview)
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ShareImportResult {
    pub project_name: String,
    pub environment_name: String,
    pub created_environment: bool,
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub unchanged_count: u32,
}

/// Apply the pending bundle to the chosen project — into an existing
/// environment (`env_id`) or a new one (`new_env_name`). The pending bundle
/// is kept on failure so the user can retry without re-entering credentials.
#[tauri::command]
#[specta::specta]
pub fn confirm_share_import(
    state: State<'_, AppState>,
    project_id: Uuid,
    env_id: Option<Uuid>,
    new_env_name: Option<String>,
) -> Result<ShareImportResult, AppError> {
    use envvault_core::share;

    // Clone (still zeroizing) so a failed save keeps the pending bundle
    // intact for a retry without re-entering credentials.
    let bundle = state
        .pending_share()
        .as_ref()
        .cloned()
        .ok_or(AppError::InvalidInput {
            message: "no bundle is waiting to be imported — open one first".into(),
        })?;
    // A bundle can cross its deadline between preview and confirm.
    bundle.check_expiry(Utc::now())?;

    let result = mutate_and_save(&state, |vault| {
        let project_name = vault.project(project_id)?.name.clone();
        let (env_id, created) = match (env_id, &new_env_name) {
            (Some(id), _) => (id, false),
            (None, Some(name)) => {
                // A new environment takes the bundle's production flag only
                // when it IS the bundle's environment — never guess.
                let is_prod =
                    name.eq_ignore_ascii_case(&bundle.environment_name) && bundle.is_production;
                (
                    vault.add_environment(project_id, name.clone(), is_prod)?,
                    true,
                )
            }
            (None, None) => {
                return Err(envvault_core::CoreError::InvalidInput(
                    "choose an environment".into(),
                ))
            }
        };
        let report = share::apply_bundle(vault, project_id, env_id, &bundle)?;
        let env = vault
            .project(project_id)?
            .environments
            .iter()
            .find(|e| e.id == env_id)
            .ok_or(envvault_core::CoreError::StaleId)?;
        Ok(ShareImportResult {
            project_name,
            environment_name: env.name.clone(),
            created_environment: created,
            added: report.added,
            updated: report.updated,
            unchanged_count: report.unchanged.len() as u32,
        })
    })?;

    state.clear_pending_share();
    Ok(result)
}

/// Drop the pending bundle (zeroizing its values) without importing.
#[tauri::command]
#[specta::specta]
pub fn cancel_share_import(state: State<'_, AppState>) {
    state.clear_pending_share();
}

// ---------------------------------------------------------------------------
// Phase 8: vault backup & portability (spec F9)
// ---------------------------------------------------------------------------

/// Write a copy of the encrypted vault file to `dest_path`. It is already
/// ciphertext — safe for Dropbox, USB sticks, anywhere.
#[tauri::command]
#[specta::specta]
pub fn export_vault_backup(state: State<'_, AppState>, dest_path: String) -> Result<(), AppError> {
    let vault_path = vault::default_vault_path()?;
    vault::export_vault_copy(&vault_path, std::path::Path::new(&dest_path))?;
    state.touch();
    Ok(())
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct VaultMergeResult {
    pub projects_added: u32,
    pub environments_added: u32,
    pub secrets_added: u32,
    pub secrets_updated: u32,
}

/// Merge another EnvVault file into the open vault. Needs the password of
/// the file being imported (it has its own). Deliberately unthrottled: the
/// user supplies both the file and its password, so there is nothing of
/// theirs to protect with a lockout — and a throttle sidecar would litter
/// the folder the file came from.
#[tauri::command]
#[specta::specta]
pub async fn import_vault_merge(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> Result<VaultMergeResult, AppError> {
    let source = tauri::async_runtime::spawn_blocking(move || -> Result<Vault, AppError> {
        let unlocked =
            vault::unlock_vault(std::path::Path::new(&path), SecretString::from(password))?;
        Ok(unlocked.vault().clone())
    })
    .await
    .map_err(AppError::from_join)??;

    let report = mutate_and_save(&state, |vault| Ok(vault.merge_from(source)))?;
    Ok(VaultMergeResult {
        projects_added: report.projects_added,
        environments_added: report.environments_added,
        secrets_added: report.secrets_added,
        secrets_updated: report.secrets_updated,
    })
}

/// Replace the live vault with another EnvVault file. The session is locked
/// FIRST so no in-memory state can overwrite the imported file, then the
/// swap happens atomically with the previous vault kept in the rolling
/// backups. Afterwards the vault opens with the imported file's password.
#[tauri::command]
#[specta::specta]
pub fn import_vault_replace(state: State<'_, AppState>, path: String) -> Result<(), AppError> {
    let vault_path = vault::default_vault_path()?;
    // Validate before locking the user out of their session for nothing.
    vault::validate_vault_file(std::path::Path::new(&path))?;
    state.lock_now();
    vault::replace_vault_file(&vault_path, std::path::Path::new(&path))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 7: the health dashboard (spec F7)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct HealthLocation {
    pub project_id: Uuid,
    pub project_name: String,
    pub environment_id: Uuid,
    pub environment_name: String,
    pub is_production: bool,
    pub secret_id: Uuid,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct HealthFinding {
    /// "stale" | "reused" | "weak" | "exposed"
    pub category: String,
    /// "critical" | "warning" | "info"
    pub severity: String,
    pub title: String,
    pub fix: String,
    pub fix_url: String,
    pub locations: Vec<HealthLocation>,
}

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    pub findings: Vec<HealthFinding>,
    pub total_secrets: u32,
    pub critical_count: u32,
    pub warning_count: u32,
}

/// Analyze every secret in the (unlocked) vault. No secret values ever cross
/// the boundary — only names and finding metadata.
#[tauri::command]
#[specta::specta]
pub fn health_report(state: State<'_, AppState>) -> Result<HealthReport, AppError> {
    use envvault_core::health::{self, FindingKind, Severity};

    read_session(&state, |vault| {
        let findings = health::analyze(vault);
        let total_secrets = vault
            .projects
            .iter()
            .flat_map(|p| &p.environments)
            .map(|e| e.secrets.len())
            .sum::<usize>() as u32;

        let mut critical = 0u32;
        let mut warning = 0u32;
        let dto: Vec<HealthFinding> = findings
            .into_iter()
            .map(|f| {
                match f.severity {
                    Severity::Critical => critical += 1,
                    Severity::Warning => warning += 1,
                    Severity::Info => {}
                }
                HealthFinding {
                    category: match f.kind {
                        FindingKind::Stale { .. } => "stale",
                        FindingKind::Reused => "reused",
                        FindingKind::Weak { .. } => "weak",
                        FindingKind::Exposed { .. } => "exposed",
                    }
                    .to_string(),
                    severity: match f.severity {
                        Severity::Critical => "critical",
                        Severity::Warning => "warning",
                        Severity::Info => "info",
                    }
                    .to_string(),
                    title: f.title,
                    fix: f.fix,
                    fix_url: f.fix_url,
                    locations: f
                        .locations
                        .into_iter()
                        .map(|l| HealthLocation {
                            project_id: l.project_id,
                            project_name: l.project_name,
                            environment_id: l.environment_id,
                            environment_name: l.environment_name,
                            is_production: l.is_production,
                            secret_id: l.secret_id,
                            secret_key: l.secret_key,
                        })
                        .collect(),
                }
            })
            .collect();

        Ok(HealthReport {
            findings: dto,
            total_secrets,
            critical_count: critical,
            warning_count: warning,
        })
    })
}
