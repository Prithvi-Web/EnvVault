//! A single secret. The value is a `secrecy::SecretString`: zeroized on drop,
//! and its `Debug` impl prints `SecretBox<str>([REDACTED])` — it is not
//! possible to accidentally log the plaintext.

use chrono::{DateTime, Utc};
use secrecy::SecretString;
use uuid::Uuid;

use crate::detect::KeyType;

#[derive(Debug)]
pub struct Secret {
    pub id: Uuid,
    /// The env-var name, e.g. `STRIPE_SECRET_KEY`.
    pub key: String,
    /// The plaintext value — wrapped so it cannot be Debug-printed and is
    /// zeroized when dropped.
    pub value: SecretString,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Drives the staleness check in the health dashboard.
    pub rotated_at: DateTime<Utc>,
    pub detected_type: Option<KeyType>,
}
