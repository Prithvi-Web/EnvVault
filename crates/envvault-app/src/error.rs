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
    WrongPassword { attempts_remaining: u32 },
    VaultCorrupted { path: String },
    VaultNotFound,
    VaultAlreadyExists { path: String },
    ProjectNotFound { path: String },
    SecretNameTaken { name: String },
    IoError { message: String },
    NoDataDir,
}

impl From<envvault_core::CoreError> for AppError {
    fn from(e: envvault_core::CoreError) -> Self {
        use envvault_core::CoreError as E;
        match e {
            E::VaultLocked => Self::VaultLocked,
            // attempts_remaining is wired up with rate limiting in Phase 2.
            E::WrongPassword => Self::WrongPassword {
                attempts_remaining: 0,
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
            E::NoDataDir => Self::NoDataDir,
            E::Io(err) => Self::IoError {
                message: err.to_string(),
            },
            E::Serde(err) => Self::IoError {
                message: err.to_string(),
            },
        }
    }
}
