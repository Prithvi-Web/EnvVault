//! The typed error union that crosses the IPC boundary.
//!
//! Serialized as `{ kind: "...", detail: ... }`. The frontend switches
//! exhaustively on `kind` with a `never` default case, so adding a variant
//! here without handling it in the UI breaks the TypeScript build.

use serde::Serialize;
use specta::Type;

#[derive(Debug, Clone, Serialize, Type)]
#[serde(tag = "kind", content = "detail", rename_all_fields = "camelCase")]
pub enum AppError {
    VaultLocked,
    WrongPassword {
        /// Attempts left before the 5-minute lockout. `null` when the failure
        /// came from a non-throttled path (e.g. wrong current password during
        /// a password change).
        attempts_remaining: Option<u32>,
    },
    RateLimited {
        retry_after_seconds: u32,
    },
    VaultCorrupted {
        path: String,
    },
    VaultNotFound,
    VaultAlreadyExists {
        path: String,
    },
    ProjectNotFound {
        path: String,
    },
    SecretNameTaken {
        name: String,
    },
    EnvironmentNameTaken {
        name: String,
    },
    DuplicateProjectPath {
        path: String,
    },
    InvalidInput {
        message: String,
    },
    StaleId,
    IoError {
        message: String,
    },
    NoDataDir,
}

impl AppError {
    /// A background task failed to complete (thread panic/cancellation).
    pub fn from_join(e: tauri::Error) -> Self {
        AppError::IoError {
            message: format!("background task failed: {e}"),
        }
    }
}

impl From<envvault_core::CoreError> for AppError {
    fn from(e: envvault_core::CoreError) -> Self {
        use envvault_core::CoreError as E;
        match e {
            E::VaultLocked => Self::VaultLocked,
            E::WrongPassword { attempts_remaining } => Self::WrongPassword { attempts_remaining },
            E::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds: retry_after_seconds.min(u32::MAX as u64) as u32,
            },
            E::VaultCorrupted { path, .. } => Self::VaultCorrupted {
                path: path.display().to_string(),
            },
            E::VaultNotFound(_) => Self::VaultNotFound,
            E::VaultAlreadyExists(path) => Self::VaultAlreadyExists {
                path: path.display().to_string(),
            },
            E::ProjectNotFound(path) => Self::ProjectNotFound {
                path: path.display().to_string(),
            },
            E::SecretNameTaken(name) => Self::SecretNameTaken { name },
            E::EnvironmentNameTaken(name) => Self::EnvironmentNameTaken { name },
            E::DuplicateProjectPath(path) => Self::DuplicateProjectPath {
                path: path.display().to_string(),
            },
            E::InvalidInput(message) => Self::InvalidInput { message },
            E::StaleId => Self::StaleId,
            E::NoDataDir => Self::NoDataDir,
            E::Git(message) => Self::IoError {
                message: format!("git: {message}"),
            },
            E::Io(err) => Self::IoError {
                message: err.to_string(),
            },
            E::Serde(err) => Self::IoError {
                message: err.to_string(),
            },
        }
    }
}
