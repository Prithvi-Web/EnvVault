//! API-key format detection (Stripe, AWS, OpenAI, …).
//!
//! Detection logic lands in Phase 4 with the `.env` importer; the type lives
//! here from day one because the data model references it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    StripeSecret,
    StripePublishable,
    AwsAccessKey,
    AwsSecretKey,
    OpenAi,
    Anthropic,
    GitHubToken,
    GoogleApi,
    SendGrid,
    Twilio,
    DatabaseUrl,
    JwtSecret,
    PrivateKey,
    Generic,
}
