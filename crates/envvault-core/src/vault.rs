//! The vault: the single encrypted file holding all projects and secrets.
//!
//! Load/save, atomic writes, and backup rotation are implemented in Phase 1.

use std::path::PathBuf;

use crate::error::CoreError;
use crate::project::Project;

/// Bumped on every schema change. `load_vault` must be able to read and
/// upgrade every prior version (migration harness lands in Phase 1).
pub const VAULT_SCHEMA_VERSION: u32 = 1;

/// Deliberately generic filename — the name must not leak what is inside.
pub const VAULT_FILE_NAME: &str = "vault.age";

/// The root of the data model. Encrypted with `age` at rest; this struct
/// only ever exists in memory while the vault is unlocked.
#[derive(Debug)]
pub struct Vault {
    pub version: u32,
    pub projects: Vec<Project>,
    pub settings: Settings,
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Auto-lock timeout in minutes. `None` means "Never" (UI shows a warning).
    pub auto_lock_minutes: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        // Spec §4.3: default auto-lock is 10 minutes of inactivity.
        Self {
            auto_lock_minutes: Some(10),
        }
    }
}

/// The vault lives in the OS app-data directory — never inside a project
/// directory, and there is deliberately no option to change that.
pub fn default_vault_dir() -> Result<PathBuf, CoreError> {
    dirs::data_dir()
        .map(|d| d.join("EnvVault"))
        .ok_or(CoreError::NoDataDir)
}

pub fn default_vault_path() -> Result<PathBuf, CoreError> {
    Ok(default_vault_dir()?.join(VAULT_FILE_NAME))
}
