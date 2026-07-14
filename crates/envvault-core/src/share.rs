//! Secure Share (spec F8): hand an environment's secrets to a teammate
//! without emailing a `.env`.
//!
//! ## The bundle format (documented for the README, per the anti-lock-in rule)
//!
//! A share bundle is a **plain ASCII-armored age file** — nothing wraps it,
//! so the recipient can decrypt it with the stock `age` CLI:
//!
//! ```text
//! age -d bundle.age                       # passphrase bundle
//! age -d -i ~/.ssh/id_ed25519 bundle.age  # bundle encrypted to your SSH key
//! ```
//!
//! The plaintext inside is JSON:
//!
//! ```json
//! {
//!   "format": "envvault-share",
//!   "version": 1,
//!   "project_name": "...", "environment_name": "...", "is_production": false,
//!   "created_at": "...", "expires_at": "... | null",
//!   "secrets": [{ "key": "...", "value": "...", "note": "... | null" }]
//! }
//! ```
//!
//! Everything sensitive — including the project name and the expiry — lives
//! inside the ciphertext. The file leaks only what age itself leaks: the
//! recipient stanza types in its header.
//!
//! ## Protection: passphrase XOR public keys
//!
//! age forbids mixing an scrypt (passphrase) recipient with key recipients in
//! one file, so [`ShareProtection`] is an either-or enum. Key recipients may
//! be age X25519 keys (`age1…`) or SSH public keys (`ssh-ed25519 …`,
//! `ssh-rsa …`). A recipient's EnvVault "share key" is simply their vault's
//! X25519 public key — no extra key management.
//!
//! ## Expiry is a courtesy guardrail, not cryptography
//!
//! The expiry timestamp is enforced on import, but someone who kept the file
//! can set their clock back. Say so in the docs; never overclaim.

use age::secrecy::SecretString;
use age::x25519;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, CryptoError};
use crate::error::CoreError;
use crate::secret::SecretValue;
use crate::vault::Vault;
use uuid::Uuid;

/// Bumped on every bundle schema change. Import refuses newer versions with
/// a clear message instead of misreading them.
pub const SHARE_SCHEMA_VERSION: u32 = 1;

const SHARE_FORMAT_NAME: &str = "envvault-share";

/// Share-bundle passphrases are chosen ad hoc and travel out-of-band, so a
/// floor on length is the one guardrail we can enforce at export time.
pub const MIN_SHARE_PASSPHRASE_CHARS: usize = 12;

/// One secret inside a bundle. The value zeroizes on drop and its `Debug`
/// prints `[REDACTED]`, exactly like vault secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareSecret {
    pub key: String,
    pub value: SecretValue,
    #[serde(default)]
    pub note: Option<String>,
}

/// The decrypted contents of a share bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBundle {
    format: String,
    version: u32,
    pub project_name: String,
    pub environment_name: String,
    pub is_production: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub secrets: Vec<ShareSecret>,
}

impl ShareBundle {
    pub fn new(
        project_name: String,
        environment_name: String,
        is_production: bool,
        expires_in_hours: Option<u32>,
        secrets: Vec<ShareSecret>,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            format: SHARE_FORMAT_NAME.into(),
            version: SHARE_SCHEMA_VERSION,
            project_name,
            environment_name,
            is_production,
            created_at: now,
            expires_at: expires_in_hours.map(|h| now + Duration::hours(i64::from(h))),
            secrets,
        }
    }
}

/// How a bundle is (or will be) protected. Either-or by construction — age
/// forbids mixing a passphrase recipient with key recipients.
#[derive(Debug)]
pub enum ShareProtection {
    /// scrypt passphrase, communicated out-of-band.
    Passphrase(SecretString),
    /// One or more age X25519 / SSH public keys, unparsed as the user gave
    /// them (one per string).
    RecipientKeys(Vec<String>),
}

/// What kind of key opens a bundle — readable from the age header without
/// decrypting (stanza types are plaintext by design in age).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleKind {
    Passphrase,
    RecipientKeys,
}

/// Parse one recipient key string: `age1…` or an OpenSSH public key line.
fn parse_recipient_key(raw: &str) -> Result<Box<dyn age::Recipient + Send>, CoreError> {
    let key = raw.trim();
    if key.is_empty() {
        return Err(CoreError::InvalidRecipientKey("empty recipient key".into()));
    }
    if let Ok(r) = key.parse::<x25519::Recipient>() {
        return Ok(Box::new(r));
    }
    if key.starts_with("ssh-") || key.starts_with("ecdsa-") {
        return match key.parse::<age::ssh::Recipient>() {
            Ok(r) => Ok(Box::new(r)),
            Err(_) => Err(CoreError::InvalidRecipientKey(
                "unsupported SSH key — age accepts ssh-ed25519 and ssh-rsa public keys".into(),
            )),
        };
    }
    Err(CoreError::InvalidRecipientKey(format!(
        "{}… is neither an age key (age1…) nor an SSH public key (ssh-ed25519 …, ssh-rsa …)",
        key.chars().take(12).collect::<String>()
    )))
}

/// Encrypt a bundle. Returns the ASCII-armored age file contents.
pub fn seal_bundle(
    bundle: &ShareBundle,
    protection: &ShareProtection,
) -> Result<String, CoreError> {
    seal_bundle_with_work_factor(bundle, protection, crypto::SCRYPT_WORK_FACTOR_LOG_N)
}

/// Test-visible variant: a lower scrypt work factor keeps the test suite
/// fast. Production code paths always use [`seal_bundle`].
#[doc(hidden)]
pub fn seal_bundle_with_work_factor(
    bundle: &ShareBundle,
    protection: &ShareProtection,
    work_factor_log_n: u8,
) -> Result<String, CoreError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(bundle)?);

    match protection {
        ShareProtection::Passphrase(passphrase) => {
            use age::secrecy::ExposeSecret;
            if passphrase.expose_secret().chars().count() < MIN_SHARE_PASSPHRASE_CHARS {
                return Err(CoreError::InvalidInput(format!(
                    "share passphrases need at least {MIN_SHARE_PASSPHRASE_CHARS} characters"
                )));
            }
            crypto::encrypt_with_passphrase(&plaintext, passphrase, work_factor_log_n)
                .map_err(map_bundle_crypto)
        }
        ShareProtection::RecipientKeys(keys) => {
            if keys.iter().all(|k| k.trim().is_empty()) {
                return Err(CoreError::InvalidInput(
                    "add at least one recipient key".into(),
                ));
            }
            let recipients = keys
                .iter()
                .filter(|k| !k.trim().is_empty())
                .map(|k| parse_recipient_key(k))
                .collect::<Result<Vec<_>, _>>()?;
            crypto::encrypt_to_parsed_recipients(&plaintext, &recipients).map_err(map_bundle_crypto)
        }
    }
}

/// Read the age header (without decrypting) to learn what opens this bundle.
/// age stanza types are plaintext by design; this leaks nothing new.
pub fn inspect_bundle(data: &[u8]) -> Result<BundleKind, CoreError> {
    use age::armor::ArmoredReader;
    use std::io::Read;

    // The age binary header is textual: "age-encryption.org/v1\n-> <type> …".
    // ArmoredReader transparently handles both armored and binary files.
    // Read a bounded prefix — headers are small; the payload after the
    // "--- <MAC>" line is binary and never scanned.
    let mut reader = ArmoredReader::new(data);
    let mut prefix = vec![0u8; 16 * 1024];
    let mut filled = 0;
    while filled < prefix.len() {
        match reader.read(&mut prefix[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(CoreError::BundleInvalid(format!("not an age file: {e}"))),
        }
    }
    prefix.truncate(filled);

    let text = String::from_utf8_lossy(&prefix);
    if !text.starts_with("age-encryption.org/v1") {
        return Err(CoreError::BundleInvalid(
            "not an age file (missing age-encryption.org/v1 header)".into(),
        ));
    }

    let mut saw_scrypt = false;
    let mut saw_key = false;
    for line in text.lines().skip(1) {
        if line.starts_with("---") {
            break; // header MAC — everything after is ciphertext
        }
        if let Some(rest) = line.strip_prefix("-> ") {
            match rest.split_whitespace().next() {
                Some("scrypt") => saw_scrypt = true,
                Some(_) => saw_key = true,
                None => {}
            }
        }
    }
    match (saw_scrypt, saw_key) {
        (true, false) => Ok(BundleKind::Passphrase),
        (false, true) => Ok(BundleKind::RecipientKeys),
        _ => Err(CoreError::BundleInvalid(
            "unrecognized age header stanzas".into(),
        )),
    }
}

/// Decrypt and validate a passphrase bundle. `now` is a parameter so expiry
/// is testable; production callers pass `Utc::now()`.
pub fn open_bundle_with_passphrase(
    data: &[u8],
    passphrase: &SecretString,
    now: DateTime<Utc>,
) -> Result<ShareBundle, CoreError> {
    let plaintext = crypto::decrypt_with_passphrase(data, passphrase).map_err(map_bundle_crypto)?;
    parse_bundle(&plaintext, now)
}

/// Decrypt and validate a key bundle with any age identity (the recipient's
/// vault identity, or an SSH identity via the age CLI path).
pub fn open_bundle_with_identity(
    data: &[u8],
    identity: &dyn age::Identity,
    now: DateTime<Utc>,
) -> Result<ShareBundle, CoreError> {
    let plaintext = crypto::decrypt_with_identity(data, identity).map_err(map_bundle_crypto)?;
    parse_bundle(&plaintext, now)
}

fn parse_bundle(plaintext: &[u8], now: DateTime<Utc>) -> Result<ShareBundle, CoreError> {
    let bundle: ShareBundle = serde_json::from_slice(plaintext)
        .map_err(|e| CoreError::BundleInvalid(format!("payload is not bundle JSON: {e}")))?;

    if bundle.format != SHARE_FORMAT_NAME {
        return Err(CoreError::BundleInvalid(
            "decrypted payload is not an EnvVault share bundle".into(),
        ));
    }
    if bundle.version > SHARE_SCHEMA_VERSION {
        return Err(CoreError::BundleInvalid(format!(
            "created by a newer EnvVault (bundle v{}); this app reads up to v{}",
            bundle.version, SHARE_SCHEMA_VERSION
        )));
    }
    bundle.check_expiry(now)?;
    Ok(bundle)
}

impl ShareBundle {
    /// Expiry check, also re-run at import-confirm time — a bundle can cross
    /// its deadline between preview and confirm. Courtesy guardrail only
    /// (a recipient controls their own clock); the docs say so.
    pub fn check_expiry(&self, now: DateTime<Utc>) -> Result<(), CoreError> {
        if let Some(expired_at) = self.expires_at {
            if expired_at <= now {
                return Err(CoreError::BundleExpired { expired_at });
            }
        }
        Ok(())
    }
}

fn map_bundle_crypto(e: CryptoError) -> CoreError {
    match e {
        CryptoError::WrongPassphrase => CoreError::BundleWrongKey,
        CryptoError::Corrupted(reason) => CoreError::BundleInvalid(reason),
        CryptoError::Io(io) => CoreError::Io(io),
    }
}

/// What happened to each key when a bundle was applied to an environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareImportReport {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    /// Keys whose value already matched — nothing changed.
    pub unchanged: Vec<String>,
}

/// Apply a decrypted bundle to one environment: add missing keys, update
/// keys whose value differs (an update counts as a rotation), leave matching
/// values untouched. Goes through the vault's own CRUD methods so every
/// invariant (key validation, uniqueness) holds.
pub fn apply_bundle(
    vault: &mut Vault,
    project_id: Uuid,
    env_id: Uuid,
    bundle: &ShareBundle,
) -> Result<ShareImportReport, CoreError> {
    let mut report = ShareImportReport {
        added: Vec::new(),
        updated: Vec::new(),
        unchanged: Vec::new(),
    };

    for secret in &bundle.secrets {
        let existing = vault
            .environment_mut(project_id, env_id)?
            .secrets
            .iter()
            .find(|s| s.key == secret.key)
            .map(|s| (s.id, s.value == secret.value));

        match existing {
            Some((_, true)) => report.unchanged.push(secret.key.clone()),
            Some((id, false)) => {
                vault.update_secret(
                    project_id,
                    env_id,
                    id,
                    crate::vault::SecretUpdate {
                        key: None,
                        value: Some(secret.value.clone()),
                        note: secret.note.clone().map(Some),
                    },
                )?;
                report.updated.push(secret.key.clone());
            }
            None => {
                vault.add_secret(
                    project_id,
                    env_id,
                    secret.key.clone(),
                    secret.value.clone(),
                    secret.note.clone(),
                )?;
                report.added.push(secret.key.clone());
            }
        }
    }
    Ok(report)
}

/// Build a bundle from one environment of the vault.
pub fn bundle_from_environment(
    vault: &Vault,
    project_id: Uuid,
    env_id: Uuid,
    expires_in_hours: Option<u32>,
    now: DateTime<Utc>,
) -> Result<ShareBundle, CoreError> {
    let project = vault.project(project_id)?;
    let env = project
        .environments
        .iter()
        .find(|e| e.id == env_id)
        .ok_or(CoreError::StaleId)?;

    if env.secrets.is_empty() {
        return Err(CoreError::InvalidInput(
            "this environment has no secrets to share".into(),
        ));
    }

    Ok(ShareBundle::new(
        project.name.clone(),
        env.name.clone(),
        env.is_production,
        expires_in_hours,
        env.secrets
            .iter()
            .map(|s| ShareSecret {
                key: s.key.clone(),
                value: s.value.clone(),
                note: s.note.clone(),
            })
            .collect(),
        now,
    ))
}
