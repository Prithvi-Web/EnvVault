//! Projects and environments.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::secret::Secret;

#[derive(Debug)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    /// Absolute path to the repo root — used to auto-match `envvault run`
    /// invocations to the right project by walking up from `$PWD`.
    pub path: PathBuf,
    pub environments: Vec<Environment>,
    pub created_at: DateTime<Utc>,
}

/// A project has multiple environments. The #1 real-world footgun is using a
/// production key in local dev; `is_production` drives the red warning UI and
/// the extra confirmation step everywhere.
#[derive(Debug)]
pub struct Environment {
    pub id: Uuid,
    pub name: String,
    pub secrets: Vec<Secret>,
    pub is_production: bool,
}
