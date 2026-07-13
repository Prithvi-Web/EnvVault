//! A single secret, and [`SecretValue`] — the only type in this codebase
//! allowed to hold a plaintext secret value.
//!
//! Guarantees:
//! - **Zeroized on drop** (via `secrecy::SecretString`).
//! - **`Debug` prints `[REDACTED]`** — it is not possible to log the value
//!   with `{:?}`. There is deliberately no `Display` impl.
//! - **Construction zeroizes its input**, including the `String`'s spare
//!   capacity, so no stray copy of the value outlives the call.
//! - `Serialize` exists *only* for the vault-payload path, where the output
//!   buffer is encrypted and then zeroized. Nothing else serializes secrets.

use std::fmt;

use age::secrecy::{ExposeSecret, SecretString};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::detect::KeyType;

pub struct SecretValue(SecretString);

impl SecretValue {
    /// Takes ownership of the input and zeroizes it (including spare
    /// capacity) after copying it into the guarded allocation.
    pub fn new(mut value: String) -> Self {
        let boxed: Box<str> = value.as_str().into();
        value.zeroize();
        Self(SecretString::from(boxed.into_string()))
    }

    /// Deliberate, visible access to the plaintext. Callers must not copy
    /// the value into anything that outlives its use.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    pub fn len(&self) -> usize {
        self.expose().len()
    }

    pub fn is_empty(&self) -> bool {
        self.expose().is_empty()
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        Self::new(self.expose().to_owned())
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Constant-time comparison — used by the health dashboard's reuse check.
impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        let a = self.expose().as_bytes();
        let b = other.expose().as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Eq for SecretValue {}

impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `new` zeroizes the intermediate String that serde hands us.
        Ok(Self::new(String::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Secret {
    pub id: Uuid,
    /// The env-var name, e.g. `STRIPE_SECRET_KEY`.
    pub key: String,
    pub value: SecretValue,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Drives the staleness check in the health dashboard.
    pub rotated_at: DateTime<Utc>,
    pub detected_type: Option<KeyType>,
    /// Set by Import & Secure when the source file was found in git history:
    /// the date of the latest offending commit. The health dashboard flags
    /// the secret as exposed until it is rotated after this date.
    /// `serde(default)` keeps every existing vault readable unchanged.
    #[serde(default)]
    pub exposed_in_git_at: Option<DateTime<Utc>>,
}

impl Secret {
    pub fn new(key: String, value: SecretValue) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            key,
            value,
            note: None,
            created_at: now,
            rotated_at: now,
            detected_type: None,
            exposed_in_git_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretValue::new("sk_live_supersecret".into());
        let printed = format!("{s:?}");
        assert_eq!(printed, "[REDACTED]");
        assert!(!printed.contains("sk_live"));
    }

    #[test]
    fn secret_struct_debug_is_redacted() {
        let s = Secret::new(
            "STRIPE_KEY".into(),
            SecretValue::new("sk_live_abc123".into()),
        );
        let printed = format!("{s:?}");
        assert!(printed.contains("[REDACTED]"));
        assert!(!printed.contains("sk_live_abc123"));
    }

    #[test]
    fn equality_is_by_value() {
        let a = SecretValue::new("same".into());
        let b = SecretValue::new("same".into());
        let c = SecretValue::new("different".into());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn serde_round_trip() {
        let s = SecretValue::new("value-with-ünïcode\nand newline".into());
        let json = serde_json::to_string(&s).unwrap();
        let back: SecretValue = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
