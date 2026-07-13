use std::path::PathBuf;

use thiserror::Error;

/// Every failure mode in the core library. No `Box<dyn Error>`, no strings
/// masquerading as errors — callers (GUI, CLI) match on these variants and
/// map them to their own user-facing error types.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("the vault is locked")]
    VaultLocked,

    #[error("wrong master password")]
    WrongPassword,

    #[error("vault file is corrupted or not a valid EnvVault file: {path}")]
    VaultCorrupted { path: PathBuf, reason: String },

    #[error("no vault exists at {0}")]
    VaultNotFound(PathBuf),

    #[error("a vault already exists at {0}")]
    VaultAlreadyExists(PathBuf),

    #[error("no project registered for path {0}")]
    ProjectNotFound(PathBuf),

    #[error("a secret named {0} already exists in this environment")]
    SecretNameTaken(String),

    #[error("could not determine the OS application-data directory")]
    NoDataDir,

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("vault serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
