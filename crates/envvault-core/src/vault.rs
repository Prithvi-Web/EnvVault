//! The vault: one encrypted file holding all projects and secrets.
//!
//! ## On-disk format (documented for the README, per the anti-lock-in rule)
//!
//! `vault.age` is a JSON envelope:
//!
//! ```json
//! {
//!   "format": "envvault",
//!   "format_version": 1,
//!   "wrapped_identity": "<armored age file: scrypt(master password) -> X25519 identity>",
//!   "recipient": "age1...",              // vault identity public key
//!   "recovery_recipient": "age1... | null",
//!   "payload": "<armored age file: X25519 -> vault JSON>"
//! }
//! ```
//!
//! To decrypt without EnvVault: extract `wrapped_identity`, run `age -d` on
//! it (enter the master password), then `age -d -i <identity>` on `payload`.
//! Or run `age -d -i <recovery key>` directly on `payload`. The envelope
//! contains no project names, no counts, no plaintext metadata.
//!
//! ## Atomic writes (§4.4)
//!
//! Every save: exclusive OS file lock → rotate 3 backups → write temp file in
//! the same directory → fsync → atomic rename → fsync directory (POSIX). A
//! crash at any point leaves either the old vault or the new vault on disk,
//! never a torn file, and never fewer than the last 3 good versions.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use uuid::Uuid;

use crate::crypto::{self, CryptoError};
use crate::error::CoreError;
use crate::project::{Environment, Project};
use crate::secret::{Secret, SecretValue};

/// Bumped on every payload schema change. `load` upgrades every prior
/// version in memory via [`migrate_payload`].
pub const VAULT_SCHEMA_VERSION: u32 = 1;

/// Bumped on every envelope change.
pub const VAULT_FORMAT_VERSION: u32 = 1;

const VAULT_FORMAT_NAME: &str = "envvault";

/// Deliberately generic filename — the name must not leak what is inside.
pub const VAULT_FILE_NAME: &str = "vault.age";

const BACKUP_COUNT: u32 = 3;

/// The root of the data model. Exists in memory only while unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    pub version: u32,
    pub projects: Vec<Project>,
    pub settings: Settings,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            version: VAULT_SCHEMA_VERSION,
            projects: Vec::new(),
            settings: Settings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// Auto-lock timeout in minutes. `None` means "Never" (UI shows a warning).
    pub auto_lock_minutes: Option<u32>,
    /// Global Guard switch (spec F6). `serde(default)` = existing vaults get
    /// the Guard on without a migration.
    #[serde(default = "default_true")]
    pub guard_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        // Spec §4.3: default auto-lock is 10 minutes of inactivity.
        Self {
            auto_lock_minutes: Some(10),
            guard_enabled: true,
        }
    }
}

impl Vault {
    // -----------------------------------------------------------------
    // CRUD. All mutation goes through these methods so invariants
    // (unique paths, unique names) hold no matter which frontend calls.
    // -----------------------------------------------------------------

    pub fn project(&self, id: Uuid) -> Result<&Project, CoreError> {
        self.projects
            .iter()
            .find(|p| p.id == id)
            .ok_or(CoreError::StaleId)
    }

    pub fn project_mut(&mut self, id: Uuid) -> Result<&mut Project, CoreError> {
        self.projects
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(CoreError::StaleId)
    }

    pub fn add_project(&mut self, name: String, path: PathBuf) -> Result<Uuid, CoreError> {
        let name = valid_name(name, "project name")?;
        if self.projects.iter().any(|p| p.path == path) {
            return Err(CoreError::DuplicateProjectPath(path));
        }
        let project = Project::new(name, path);
        let id = project.id;
        self.projects.push(project);
        Ok(id)
    }

    pub fn rename_project(&mut self, id: Uuid, name: String) -> Result<(), CoreError> {
        let name = valid_name(name, "project name")?;
        self.project_mut(id)?.name = name;
        Ok(())
    }

    pub fn remove_project(&mut self, id: Uuid) -> Result<(), CoreError> {
        let before = self.projects.len();
        self.projects.retain(|p| p.id != id);
        if self.projects.len() == before {
            return Err(CoreError::StaleId);
        }
        Ok(())
    }

    pub fn environment_mut(
        &mut self,
        project_id: Uuid,
        env_id: Uuid,
    ) -> Result<&mut Environment, CoreError> {
        self.project_mut(project_id)?
            .environments
            .iter_mut()
            .find(|e| e.id == env_id)
            .ok_or(CoreError::StaleId)
    }

    pub fn add_environment(
        &mut self,
        project_id: Uuid,
        name: String,
        is_production: bool,
    ) -> Result<Uuid, CoreError> {
        let name = valid_name(name, "environment name")?;
        let project = self.project_mut(project_id)?;
        if project
            .environments
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(&name))
        {
            return Err(CoreError::EnvironmentNameTaken(name));
        }
        let env = Environment::new(name, is_production);
        let id = env.id;
        project.environments.push(env);
        Ok(id)
    }

    pub fn remove_environment(&mut self, project_id: Uuid, env_id: Uuid) -> Result<(), CoreError> {
        let project = self.project_mut(project_id)?;
        if project.environments.len() == 1 {
            return Err(CoreError::InvalidInput(
                "a project needs at least one environment".into(),
            ));
        }
        let before = project.environments.len();
        project.environments.retain(|e| e.id != env_id);
        if project.environments.len() == before {
            return Err(CoreError::StaleId);
        }
        Ok(())
    }

    pub fn add_secret(
        &mut self,
        project_id: Uuid,
        env_id: Uuid,
        key: String,
        value: SecretValue,
        note: Option<String>,
    ) -> Result<Uuid, CoreError> {
        let key = valid_env_key(key)?;
        let env = self.environment_mut(project_id, env_id)?;
        if env.secrets.iter().any(|s| s.key == key) {
            return Err(CoreError::SecretNameTaken(key));
        }
        let mut secret = Secret::new(key, value);
        secret.detected_type = crate::detect::detect(&secret.key, secret.value.expose());
        secret.note = note.filter(|n| !n.trim().is_empty());
        let id = secret.id;
        env.secrets.push(secret);
        Ok(id)
    }

    pub fn update_secret(
        &mut self,
        project_id: Uuid,
        env_id: Uuid,
        secret_id: Uuid,
        update: SecretUpdate,
    ) -> Result<(), CoreError> {
        let new_key = update.key.map(valid_env_key).transpose()?;
        let env = self.environment_mut(project_id, env_id)?;
        if let Some(key) = &new_key {
            if env
                .secrets
                .iter()
                .any(|s| s.key == *key && s.id != secret_id)
            {
                return Err(CoreError::SecretNameTaken(key.clone()));
            }
        }
        let secret = env
            .secrets
            .iter_mut()
            .find(|s| s.id == secret_id)
            .ok_or(CoreError::StaleId)?;

        if let Some(key) = new_key {
            secret.key = key;
        }
        if let Some(value) = update.value {
            secret.value = value;
            // A changed value IS a rotation — this drives the health view.
            secret.rotated_at = chrono::Utc::now();
        }
        if let Some(note) = update.note {
            secret.note = note.filter(|n| !n.trim().is_empty());
        }
        secret.detected_type = crate::detect::detect(&secret.key, secret.value.expose());
        Ok(())
    }

    pub fn remove_secret(
        &mut self,
        project_id: Uuid,
        env_id: Uuid,
        secret_id: Uuid,
    ) -> Result<(), CoreError> {
        let env = self.environment_mut(project_id, env_id)?;
        let before = env.secrets.len();
        env.secrets.retain(|s| s.id != secret_id);
        if env.secrets.len() == before {
            return Err(CoreError::StaleId);
        }
        Ok(())
    }

    /// Merge another vault into this one (spec F9 import-merge). The policy
    /// is deterministic and documented in the UI:
    ///
    /// - Projects match by path, then by name (case-insensitive); unmatched
    ///   projects are added whole.
    /// - Environments match by name (case-insensitive); unmatched ones are
    ///   added whole.
    /// - Secrets match by key. A differing value is taken from the import
    ///   ("the imported file wins"), keeping the existing id and `created_at`.
    ///   An identical value changes nothing.
    /// - This vault's settings are kept; the imported file's are ignored.
    pub fn merge_from(&mut self, other: Vault) -> MergeReport {
        let mut report = MergeReport::default();

        for incoming_project in other.projects {
            let index = self
                .projects
                .iter()
                .position(|p| p.path == incoming_project.path)
                .or_else(|| {
                    self.projects
                        .iter()
                        .position(|p| p.name.eq_ignore_ascii_case(&incoming_project.name))
                });

            match index.and_then(|i| self.projects.get_mut(i)) {
                None => {
                    report.projects_added += 1;
                    report.secrets_added += incoming_project
                        .environments
                        .iter()
                        .map(|e| e.secrets.len() as u32)
                        .sum::<u32>();
                    self.projects.push(incoming_project);
                }
                Some(existing) => merge_project(existing, incoming_project, &mut report),
            }
        }
        report
    }
}

/// Counts from a vault merge, shown to the user afterwards.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeReport {
    pub projects_added: u32,
    pub environments_added: u32,
    pub secrets_added: u32,
    pub secrets_updated: u32,
}

fn merge_project(existing: &mut Project, incoming: Project, report: &mut MergeReport) {
    for incoming_env in incoming.environments {
        match existing
            .environments
            .iter_mut()
            .find(|e| e.name.eq_ignore_ascii_case(&incoming_env.name))
        {
            None => {
                report.environments_added += 1;
                report.secrets_added += incoming_env.secrets.len() as u32;
                existing.environments.push(incoming_env);
            }
            Some(env) => {
                for incoming_secret in incoming_env.secrets {
                    match env
                        .secrets
                        .iter_mut()
                        .find(|s| s.key == incoming_secret.key)
                    {
                        None => {
                            report.secrets_added += 1;
                            env.secrets.push(incoming_secret);
                        }
                        Some(secret) => {
                            if secret.value != incoming_secret.value {
                                // Imported file wins; keep our id/created_at.
                                secret.value = incoming_secret.value;
                                secret.note = incoming_secret.note;
                                secret.rotated_at = incoming_secret.rotated_at;
                                secret.detected_type = incoming_secret.detected_type;
                                secret.exposed_in_git_at = incoming_secret.exposed_in_git_at;
                                report.secrets_updated += 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Fields to change on a secret. `None` = leave untouched. For `note`,
/// `Some(None)` clears it.
#[derive(Debug, Default)]
pub struct SecretUpdate {
    pub key: Option<String>,
    pub value: Option<SecretValue>,
    pub note: Option<Option<String>>,
}

fn valid_name(name: String, what: &str) -> Result<String, CoreError> {
    let trimmed = name.trim().to_string();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput(format!("{what} cannot be empty")));
    }
    Ok(trimmed)
}

/// Env-var names: what POSIX tools and dotenv parsers actually accept.
fn valid_env_key(key: String) -> Result<String, CoreError> {
    let trimmed = key.trim().to_string();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput(
            "secret name cannot be empty".into(),
        ));
    }
    let mut chars = trimmed.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if !first_ok
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(CoreError::InvalidInput(
            "secret names use letters, digits and underscores, and cannot start with a digit"
                .into(),
        ));
    }
    Ok(trimmed)
}

/// The plaintext-JSON envelope stored on disk. Everything sensitive inside
/// it is age ciphertext; the only information it reveals is "this is an
/// EnvVault file" and whether a recovery key exists.
#[derive(Debug, Serialize, Deserialize)]
struct VaultEnvelope {
    format: String,
    format_version: u32,
    wrapped_identity: String,
    recipient: String,
    recovery_recipient: Option<String>,
    payload: String,
}

/// An unlocked vault. Holds the decrypted model and the (public) recipients
/// needed to re-encrypt on save. Note what it does **not** hold: the master
/// password, the derived key, and the vault identity are all dropped as soon
/// as unlock completes — saving only needs public keys.
#[derive(Debug)]
pub struct UnlockedVault {
    vault: Vault,
    path: PathBuf,
    wrapped_identity: String,
    recipient: x25519::Recipient,
    recovery_recipient: Option<x25519::Recipient>,
    /// True if this session was opened with the recovery key rather than the
    /// master password. The UI uses this to force a password reset.
    pub via_recovery: bool,
}

/// Result of creating a vault: the unlocked session plus the one-time
/// recovery key (shown once, never stored).
pub struct CreatedVault {
    pub unlocked: UnlockedVault,
    pub recovery_key: Option<SecretString>,
}

impl std::fmt::Debug for CreatedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedVault")
            .field("unlocked", &self.unlocked)
            .field(
                "recovery_key",
                &self.recovery_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// The vault lives in the OS app-data directory — never inside a project
/// directory, and there is deliberately no option to change that.
pub fn default_vault_dir() -> Result<PathBuf, CoreError> {
    // Debug-build-only test hook so dev runs and E2E tests never touch the
    // real vault. Compiled out of release binaries: users have no such knob.
    #[cfg(debug_assertions)]
    if let Ok(dir) = std::env::var("ENVVAULT_DEV_VAULT_DIR") {
        return Ok(PathBuf::from(dir));
    }
    dirs::data_dir()
        .map(|d| d.join("EnvVault"))
        .ok_or(CoreError::NoDataDir)
}

pub fn default_vault_path() -> Result<PathBuf, CoreError> {
    Ok(default_vault_dir()?.join(VAULT_FILE_NAME))
}

/// Create a new vault at `path`, protected by `password`.
pub fn create_vault(
    path: &Path,
    password: SecretString,
    with_recovery_key: bool,
) -> Result<CreatedVault, CoreError> {
    create_vault_with_work_factor(
        path,
        password,
        with_recovery_key,
        crypto::SCRYPT_WORK_FACTOR_LOG_N,
    )
}

/// Test-visible variant: a lower scrypt work factor keeps the test suite
/// fast. Production code paths always use [`create_vault`].
#[doc(hidden)]
pub fn create_vault_with_work_factor(
    path: &Path,
    password: SecretString,
    with_recovery_key: bool,
    work_factor_log_n: u8,
) -> Result<CreatedVault, CoreError> {
    if path.exists() {
        return Err(CoreError::VaultAlreadyExists(path.to_path_buf()));
    }

    let identity = crypto::generate_identity();
    let recipient = identity.to_public();
    let wrapped_identity = crypto::wrap_identity(&identity, &password, work_factor_log_n)
        .map_err(|e| map_crypto(e, path))?;

    let (recovery_key, recovery_recipient) = if with_recovery_key {
        let recovery = crypto::generate_identity();
        (Some(recovery.to_string()), Some(recovery.to_public()))
    } else {
        (None, None)
    };

    let unlocked = UnlockedVault {
        vault: Vault::default(),
        path: path.to_path_buf(),
        wrapped_identity,
        recipient,
        recovery_recipient,
        via_recovery: false,
    };
    unlocked.save()?;

    Ok(CreatedVault {
        unlocked,
        recovery_key,
    })
}

/// Unlock the vault with either the master password or the recovery key
/// (an `AGE-SECRET-KEY-1…` string). Fails closed: any ambiguity is an error.
pub fn unlock_vault(path: &Path, passphrase: SecretString) -> Result<UnlockedVault, CoreError> {
    let envelope = read_envelope(path)?;

    let recipient = envelope
        .recipient
        .parse::<x25519::Recipient>()
        .map_err(|e| corrupted(path, format!("invalid recipient: {e}")))?;
    let recovery_recipient = envelope
        .recovery_recipient
        .as_deref()
        .map(|r| {
            r.parse::<x25519::Recipient>()
                .map_err(|e| corrupted(path, format!("invalid recovery recipient: {e}")))
        })
        .transpose()?;

    // Path 1: master password unwraps the vault identity.
    match crypto::unwrap_identity(&envelope.wrapped_identity, &passphrase) {
        Ok(identity) => {
            // Sanity: the unwrapped identity must match the stored recipient,
            // otherwise the envelope was stitched together from two files.
            if identity.to_public().to_string() != envelope.recipient {
                return Err(corrupted(path, "identity does not match recipient".into()));
            }
            let vault = decrypt_and_migrate(&envelope.payload, &identity, path)?;
            Ok(UnlockedVault {
                vault,
                path: path.to_path_buf(),
                wrapped_identity: envelope.wrapped_identity,
                recipient,
                recovery_recipient,
                via_recovery: false,
            })
        }
        Err(CryptoError::WrongPassphrase) => {
            // Path 2: the passphrase may be the recovery key itself.
            if let Ok(recovery_identity) = passphrase
                .expose_secret()
                .trim()
                .parse::<x25519::Identity>()
            {
                if let Ok(vault) = decrypt_and_migrate(&envelope.payload, &recovery_identity, path)
                {
                    return Ok(UnlockedVault {
                        vault,
                        path: path.to_path_buf(),
                        wrapped_identity: envelope.wrapped_identity,
                        recipient,
                        recovery_recipient,
                        via_recovery: true,
                    });
                }
            }
            Err(CoreError::WrongPassword {
                attempts_remaining: None,
            })
        }
        Err(other) => Err(map_crypto(other, path)),
    }
}

impl UnlockedVault {
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn vault_mut(&mut self) -> &mut Vault {
        &mut self.vault
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The vault's X25519 public key. Doubles as the user's **share key**
    /// (spec F8): teammates encrypt bundles to it, and the vault identity —
    /// unwrapped with the master password — decrypts them. Public material;
    /// safe to display and copy.
    pub fn recipient(&self) -> &x25519::Recipient {
        &self.recipient
    }

    /// Serialize, encrypt, and atomically persist the vault.
    pub fn save(&self) -> Result<(), CoreError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.vault)?);

        let mut recipients: Vec<&x25519::Recipient> = vec![&self.recipient];
        if let Some(r) = &self.recovery_recipient {
            recipients.push(r);
        }
        let payload = crypto::encrypt_payload(&plaintext, &recipients)
            .map_err(|e| map_crypto(e, &self.path))?;

        let envelope = VaultEnvelope {
            format: VAULT_FORMAT_NAME.into(),
            format_version: VAULT_FORMAT_VERSION,
            wrapped_identity: self.wrapped_identity.clone(),
            recipient: self.recipient.to_string(),
            recovery_recipient: self.recovery_recipient.as_ref().map(|r| r.to_string()),
            payload,
        };
        let bytes = serde_json::to_vec_pretty(&envelope)?;

        atomic_write_with_backups(&self.path, &bytes)
    }

    /// Re-wrap the vault identity under a new master password. Requires the
    /// current password (the identity is never held in memory after unlock).
    pub fn change_password(
        &mut self,
        current_password: &SecretString,
        new_password: SecretString,
    ) -> Result<(), CoreError> {
        self.change_password_with_work_factor(
            current_password,
            new_password,
            crypto::SCRYPT_WORK_FACTOR_LOG_N,
        )
    }

    #[doc(hidden)]
    pub fn change_password_with_work_factor(
        &mut self,
        current_password: &SecretString,
        new_password: SecretString,
        work_factor_log_n: u8,
    ) -> Result<(), CoreError> {
        let identity = crypto::unwrap_identity(&self.wrapped_identity, current_password)
            .map_err(|e| map_crypto(e, &self.path))?;
        self.wrapped_identity = crypto::wrap_identity(&identity, &new_password, work_factor_log_n)
            .map_err(|e| map_crypto(e, &self.path))?;
        self.save()
    }

    /// Lock the vault: consumes the session. Every `SecretValue` in the model
    /// zeroizes on drop; no key material survives (none was retained).
    pub fn lock(self) {
        drop(self);
    }

    /// Replace the vault identity entirely and wrap the new one under
    /// `new_password`. This is the "forgot my password, unlocked with the
    /// recovery key" path: it needs no knowledge of the old password or the
    /// old identity. The recovery key keeps working (the payload stays
    /// encrypted to the recovery recipient too).
    pub fn rekey(&mut self, new_password: SecretString) -> Result<(), CoreError> {
        self.rekey_with_work_factor(new_password, crypto::SCRYPT_WORK_FACTOR_LOG_N)
    }

    #[doc(hidden)]
    pub fn rekey_with_work_factor(
        &mut self,
        new_password: SecretString,
        work_factor_log_n: u8,
    ) -> Result<(), CoreError> {
        let identity = crypto::generate_identity();
        let recipient = identity.to_public();
        let wrapped_identity = crypto::wrap_identity(&identity, &new_password, work_factor_log_n)
            .map_err(|e| map_crypto(e, &self.path))?;
        self.wrapped_identity = wrapped_identity;
        self.recipient = recipient;
        self.via_recovery = false;
        self.save()
    }
}

/// Read-modify-write under the same exclusive file lock, for writers that do
/// not hold a long-lived session (e.g. the CLI importing a file while the
/// GUI is open). Two processes hammering this concurrently must serialize
/// cleanly — proven by the concurrency test.
pub fn update_vault<F>(path: &Path, passphrase: SecretString, f: F) -> Result<(), CoreError>
where
    F: FnOnce(&mut Vault),
{
    update_vault_try(path, passphrase, |vault| {
        f(vault);
        Ok(())
    })
}

/// Like [`update_vault`], but the mutation can fail and can return a value.
/// On `Err` nothing is written — the vault on disk stays exactly as it was.
pub fn update_vault_try<F, T>(path: &Path, passphrase: SecretString, f: F) -> Result<T, CoreError>
where
    F: FnOnce(&mut Vault) -> Result<T, CoreError>,
{
    let _lock = VaultLock::acquire(path)?;
    let mut unlocked = unlock_vault(path, passphrase)?;
    let value = f(unlocked.vault_mut())?;
    // Skip re-acquiring the lock we already hold.
    unlocked.save_locked_held()?;
    Ok(value)
}

/// Unwrap the vault's X25519 identity with the master password — used to
/// decrypt share bundles that were encrypted to this vault's share key. The
/// caller must drop the identity as soon as the decryption is done; nothing
/// long-lived may hold it.
pub fn unwrap_vault_identity(
    path: &Path,
    password: &SecretString,
) -> Result<x25519::Identity, CoreError> {
    let envelope = read_envelope(path)?;
    let identity = crypto::unwrap_identity(&envelope.wrapped_identity, password)
        .map_err(|e| map_crypto(e, path))?;
    // Same stitched-envelope sanity check as unlock.
    if identity.to_public().to_string() != envelope.recipient {
        return Err(corrupted(path, "identity does not match recipient".into()));
    }
    Ok(identity)
}

impl UnlockedVault {
    fn save_locked_held(&self) -> Result<(), CoreError> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.vault)?);
        let mut recipients: Vec<&x25519::Recipient> = vec![&self.recipient];
        if let Some(r) = &self.recovery_recipient {
            recipients.push(r);
        }
        let payload = crypto::encrypt_payload(&plaintext, &recipients)
            .map_err(|e| map_crypto(e, &self.path))?;
        let envelope = VaultEnvelope {
            format: VAULT_FORMAT_NAME.into(),
            format_version: VAULT_FORMAT_VERSION,
            wrapped_identity: self.wrapped_identity.clone(),
            recipient: self.recipient.to_string(),
            recovery_recipient: self.recovery_recipient.as_ref().map(|r| r.to_string()),
            payload,
        };
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        atomic_write_unlocked(&self.path, &bytes)
    }
}

// ---------------------------------------------------------------------------
// Backup & portability (spec F9)
// ---------------------------------------------------------------------------

/// What a vault file reveals without any password: only that it is a valid
/// EnvVault file and whether a recovery key was configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultFileInfo {
    pub has_recovery_recipient: bool,
}

/// Check that `path` is a readable, well-formed EnvVault file (envelope
/// only — no password needed, nothing decrypted).
pub fn validate_vault_file(path: &Path) -> Result<VaultFileInfo, CoreError> {
    let envelope = read_envelope(path)?;
    Ok(VaultFileInfo {
        has_recovery_recipient: envelope.recovery_recipient.is_some(),
    })
}

/// Export a copy of the encrypted vault file to `dest` (spec F9). The vault
/// is already ciphertext — the copy is safe to put anywhere. Validates the
/// source first so a corrupted vault is never exported as a "backup", and
/// fsyncs the destination so the backup actually exists once we report it.
pub fn export_vault_copy(vault_path: &Path, dest: &Path) -> Result<(), CoreError> {
    validate_vault_file(vault_path)?;
    // Hold the lock so an in-flight save cannot be copied half-replaced.
    let _lock = VaultLock::acquire(vault_path)?;
    fs::copy(vault_path, dest)?;
    fsync_file(dest)?;
    Ok(())
}

/// Replace the live vault file with `source` (spec F9 import-replace). The
/// source is validated first; the write is atomic and the previous vault is
/// kept in the rolling backups, so a mistaken replace is recoverable. The
/// caller must lock any open session afterwards — the imported file opens
/// with **its own** master password.
pub fn replace_vault_file(vault_path: &Path, source: &Path) -> Result<(), CoreError> {
    validate_vault_file(source)?;
    let bytes = fs::read(source)?;
    atomic_write_with_backups(vault_path, &bytes)
}

// ---------------------------------------------------------------------------
// Envelope reading + migrations
// ---------------------------------------------------------------------------

fn read_envelope(path: &Path) -> Result<VaultEnvelope, CoreError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CoreError::VaultNotFound(path.to_path_buf()))
        }
        Err(e) => return Err(e.into()),
    };
    if bytes.is_empty() {
        return Err(corrupted(path, "file is empty".into()));
    }
    let envelope: VaultEnvelope = serde_json::from_slice(&bytes)
        .map_err(|e| corrupted(path, format!("not a valid EnvVault file: {e}")))?;
    if envelope.format != VAULT_FORMAT_NAME {
        return Err(corrupted(path, "unrecognized format marker".into()));
    }
    if envelope.format_version > VAULT_FORMAT_VERSION {
        return Err(corrupted(
            path,
            format!(
                "created by a newer EnvVault (format v{}); this app reads up to v{}",
                envelope.format_version, VAULT_FORMAT_VERSION
            ),
        ));
    }
    Ok(envelope)
}

fn decrypt_and_migrate(
    payload: &str,
    identity: &x25519::Identity,
    path: &Path,
) -> Result<Vault, CoreError> {
    let plaintext = crypto::decrypt_payload(payload, identity).map_err(|e| map_crypto(e, path))?;
    migrate_payload(&plaintext, path)
}

/// The migration harness, in place from day one. Reads the schema version
/// with a minimal probe (no secret material is parsed into intermediate
/// structures on the current-version fast path), then applies stepwise
/// upgrades for older versions.
fn migrate_payload(plaintext: &[u8], path: &Path) -> Result<Vault, CoreError> {
    #[derive(Deserialize)]
    struct VersionProbe {
        version: u32,
    }

    let probe: VersionProbe = serde_json::from_slice(plaintext)
        .map_err(|e| corrupted(path, format!("payload is not vault JSON: {e}")))?;

    if probe.version > VAULT_SCHEMA_VERSION {
        return Err(corrupted(
            path,
            format!(
                "vault schema v{} is newer than this app supports (v{})",
                probe.version, VAULT_SCHEMA_VERSION
            ),
        ));
    }

    if probe.version == VAULT_SCHEMA_VERSION {
        return serde_json::from_slice(plaintext)
            .map_err(|e| corrupted(path, format!("vault JSON invalid: {e}")));
    }

    // Older version: this is where the stepwise JSON-value migration chain
    // lives. v1 is the first shipped schema, so today every older number is
    // invalid; when v2 ships, an arm upgrading v1→v2 is added here and the
    // v1 fixture in tests/fixtures/ guards it forever.
    Err(corrupted(
        path,
        format!("no migration path from vault schema v{}", probe.version),
    ))
}

// ---------------------------------------------------------------------------
// Atomic writes, backups, cross-process locking
// ---------------------------------------------------------------------------

/// Exclusive advisory lock on `<vault>.lock` in the vault directory.
/// Serializes writers across processes (GUI + CLI). Released on drop.
pub struct VaultLock {
    file: File,
}

impl std::fmt::Debug for VaultLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultLock")
    }
}

impl VaultLock {
    pub fn acquire(vault_path: &Path) -> Result<Self, CoreError> {
        let lock_path = lock_path_for(vault_path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        // Blocks until the other writer finishes — "waits cleanly" per spec.
        FileExt::lock_exclusive(&file)?;
        Ok(Self { file })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn lock_path_for(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    vault_path.with_file_name(name)
}

pub fn backup_path(vault_path: &Path, n: u32) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bak.{n}"));
    vault_path.with_file_name(name)
}

fn atomic_write_with_backups(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let _lock = VaultLock::acquire(path)?;
    atomic_write_unlocked(path, bytes)
}

/// The write itself; callers must hold the vault lock.
fn atomic_write_unlocked(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| corrupted(path, "vault path has no parent directory".into()))?;
    fs::create_dir_all(parent)?;

    // Remove temp files a killed process may have left behind. Safe: we hold
    // the exclusive vault lock, so no live writer owns them.
    let stale_prefix = format!(
        ".{}.tmp.",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&stale_prefix)
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    // Rolling backups: bak.2 -> bak.3, bak.1 -> bak.2, current -> bak.1.
    // `copy` (not rename) so the live vault file never disappears before the
    // atomic replace below.
    if path.exists() {
        for n in (1..BACKUP_COUNT).rev() {
            let from = backup_path(path, n);
            if from.exists() {
                fs::rename(&from, backup_path(path, n + 1))?;
            }
        }
        let bak1 = backup_path(path, 1);
        fs::copy(path, &bak1)?;
        fsync_file(&bak1)?;
    }

    test_failpoint("before-temp-write")?;

    // Temp file in the same directory => same filesystem => rename is atomic.
    let tmp = path.with_file_name(format!(
        ".{}.tmp.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        test_failpoint("during-temp-write")?;
        f.sync_all()?;
    }

    test_failpoint("after-temp-write")?;

    fs::rename(&tmp, path)?;
    fsync_dir(parent)?;
    Ok(())
}

fn fsync_file(path: &Path) -> Result<(), CoreError> {
    // Must open with WRITE access: Windows' FlushFileBuffers rejects
    // read-only handles ("Access is denied"), while POSIX doesn't care.
    OpenOptions::new().write(true).open(path)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn fsync_dir(dir: &Path) -> Result<(), CoreError> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> Result<(), CoreError> {
    // Windows has no directory fsync; the ReplaceFile-style rename via
    // MoveFileExW(MOVEFILE_REPLACE_EXISTING) is the atomicity guarantee.
    Ok(())
}

/// Test-only failure injection, compiled out of release builds. The
/// kill-mid-write and disk-full tests drive this via environment variables
/// from a spawned child process.
#[cfg(debug_assertions)]
fn test_failpoint(stage: &str) -> Result<(), CoreError> {
    if let Ok(v) = std::env::var("ENVVAULT_TEST_ABORT_AT") {
        if v == stage {
            std::process::abort();
        }
    }
    if let Ok(v) = std::env::var("ENVVAULT_TEST_FAIL_AT") {
        if v == stage {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "simulated disk-full",
            )));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn test_failpoint(_stage: &str) -> Result<(), CoreError> {
    Ok(())
}

fn corrupted(path: &Path, reason: String) -> CoreError {
    CoreError::VaultCorrupted {
        path: path.to_path_buf(),
        reason,
    }
}

fn map_crypto(e: CryptoError, path: &Path) -> CoreError {
    match e {
        CryptoError::WrongPassphrase => CoreError::WrongPassword {
            attempts_remaining: None,
        },
        CryptoError::Corrupted(reason) => corrupted(path, reason),
        CryptoError::Io(io) => CoreError::Io(io),
    }
}
