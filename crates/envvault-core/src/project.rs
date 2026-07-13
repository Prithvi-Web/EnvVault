//! Projects and environments.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secret::Secret;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    /// Absolute path to the repo root — used to auto-match `envvault run`
    /// invocations to the right project by walking up from `$PWD`.
    pub path: PathBuf,
    pub environments: Vec<Environment>,
    pub created_at: DateTime<Utc>,
    /// Per-project Guard switch (spec F6). `serde(default)` keeps old vaults
    /// readable with the Guard on.
    #[serde(default = "guard_default")]
    pub guard_enabled: bool,
}

fn guard_default() -> bool {
    true
}

impl Project {
    /// A new project with the default environment pair. `production` is
    /// flagged so the UI renders it red and gates reveals behind
    /// confirmation.
    pub fn new(name: String, path: PathBuf) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            path,
            environments: vec![
                Environment::new("development".into(), false),
                Environment::new("production".into(), true),
            ],
            created_at: Utc::now(),
            guard_enabled: true,
        }
    }
}

/// A project has multiple environments. The #1 real-world footgun is using a
/// production key in local dev; `is_production` drives the red warning UI and
/// the extra confirmation step everywhere.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Environment {
    pub id: Uuid,
    pub name: String,
    pub secrets: Vec<Secret>,
    pub is_production: bool,
}

impl Environment {
    pub fn new(name: String, is_production: bool) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            secrets: Vec::new(),
            is_production,
        }
    }
}
