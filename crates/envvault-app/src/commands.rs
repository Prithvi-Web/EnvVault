//! Tauri command layer. Each command is a thin wrapper: call core, map the
//! error, return. All real logic and all tests live in `envvault-core`.

use serde::Serialize;
use specta::Type;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub vault_path: String,
    pub vault_exists: bool,
}

#[tauri::command]
#[specta::specta]
pub fn app_info() -> Result<AppInfo, AppError> {
    let vault_path = envvault_core::vault::default_vault_path()?;
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        vault_exists: vault_path.exists(),
        vault_path: vault_path.display().to_string(),
    })
}
