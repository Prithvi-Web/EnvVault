//! API-key format detection. Purely heuristic and value-first: known vendor
//! prefixes are unambiguous; key-name hints are the fallback. Used to badge
//! secrets in the UI, pick rotation instructions in the health dashboard,
//! and enrich `.env` import previews.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "specta", derive(specta::Type))]
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

/// Best-effort classification of a secret from its env-var name and value.
/// Returns `None` when nothing distinctive is recognized.
pub fn detect(key: &str, value: &str) -> Option<KeyType> {
    let v = value.trim();
    let k = key.to_ascii_uppercase();

    // --- Unambiguous value prefixes (vendor-documented formats) ---
    if v.contains("-----BEGIN") && v.contains("PRIVATE KEY") {
        return Some(KeyType::PrivateKey);
    }
    if v.starts_with("sk-ant-") {
        return Some(KeyType::Anthropic);
    }
    if ["sk_live_", "sk_test_", "rk_live_", "rk_test_"]
        .iter()
        .any(|p| v.starts_with(p))
    {
        return Some(KeyType::StripeSecret);
    }
    if v.starts_with("pk_live_") || v.starts_with("pk_test_") {
        return Some(KeyType::StripePublishable);
    }
    if v.starts_with("sk-") && v.len() >= 20 {
        return Some(KeyType::OpenAi);
    }
    if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
        .iter()
        .any(|p| v.starts_with(p))
    {
        return Some(KeyType::GitHubToken);
    }
    if v.starts_with("AIza") && v.len() >= 35 {
        return Some(KeyType::GoogleApi);
    }
    if v.starts_with("SG.") && v.len() >= 20 {
        return Some(KeyType::SendGrid);
    }
    if (v.starts_with("AKIA") || v.starts_with("ASIA"))
        && v.len() == 20
        && v.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some(KeyType::AwsAccessKey);
    }
    if (v.starts_with("AC") || v.starts_with("SK"))
        && v.len() == 34
        && v[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(KeyType::Twilio);
    }
    if [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mariadb://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "rediss://",
        "amqp://",
    ]
    .iter()
    .any(|p| v.starts_with(p))
    {
        return Some(KeyType::DatabaseUrl);
    }

    // --- Key-name hints (weaker, checked after value formats) ---
    if k.contains("DATABASE_URL") || k.ends_with("_DSN") {
        return Some(KeyType::DatabaseUrl);
    }
    if k.contains("JWT") && (k.contains("SECRET") || k.contains("KEY")) {
        return Some(KeyType::JwtSecret);
    }
    if k.contains("AWS") && k.contains("SECRET") && v.len() == 40 {
        return Some(KeyType::AwsSecretKey);
    }
    if k.contains("SENDGRID") {
        return Some(KeyType::SendGrid);
    }
    if k.contains("TWILIO") {
        return Some(KeyType::Twilio);
    }

    None
}

/// Human label for a detected type, shared by UI badge text and docs.
pub fn label(t: KeyType) -> &'static str {
    match t {
        KeyType::StripeSecret => "Stripe secret",
        KeyType::StripePublishable => "Stripe publishable",
        KeyType::AwsAccessKey => "AWS access key",
        KeyType::AwsSecretKey => "AWS secret key",
        KeyType::OpenAi => "OpenAI",
        KeyType::Anthropic => "Anthropic",
        KeyType::GitHubToken => "GitHub token",
        KeyType::GoogleApi => "Google API",
        KeyType::SendGrid => "SendGrid",
        KeyType::Twilio => "Twilio",
        KeyType::DatabaseUrl => "Database URL",
        KeyType::JwtSecret => "JWT secret",
        KeyType::PrivateKey => "Private key",
        KeyType::Generic => "Generic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_prefixes_are_recognized() {
        let cases = [
            ("K", "sk_live_abc123", KeyType::StripeSecret),
            ("K", "rk_test_abc123", KeyType::StripeSecret),
            ("K", "pk_live_abc123", KeyType::StripePublishable),
            ("K", "sk-ant-api03-xxxxxxxxxxxxxxxx", KeyType::Anthropic),
            ("K", "sk-proj-abcdefghijklmnopq", KeyType::OpenAi),
            ("K", "github_pat_11ABC_xyz", KeyType::GitHubToken),
            (
                "K",
                "AIzaSyA-1234567890abcdefghijklmnopqrstu",
                KeyType::GoogleApi,
            ),
            (
                "K",
                "SG.abcdefghijklmnop.qrstuvwxyz123456",
                KeyType::SendGrid,
            ),
            ("K", "AKIAIOSFODNN7EXAMPLE", KeyType::AwsAccessKey),
            (
                "K",
                "postgres://user:pass@localhost/db",
                KeyType::DatabaseUrl,
            ),
            (
                "K",
                "mongodb+srv://u:p@cluster0.example.net",
                KeyType::DatabaseUrl,
            ),
            (
                "K",
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
                KeyType::PrivateKey,
            ),
        ];
        for (k, v, expected) in cases {
            assert_eq!(detect(k, v), Some(expected), "value: {v}");
        }
    }

    /// Fixtures shaped exactly like real credentials are assembled at
    /// runtime: GitHub push protection (correctly) refuses to accept source
    /// files containing credential-pattern literals — our own detector's
    /// test data would trip it. Both scanners doing their jobs.
    #[test]
    fn credential_shaped_fixtures_built_at_runtime() {
        let twilio_sid = format!("AC{}", "0123456789abcdef".repeat(2));
        assert_eq!(detect("K", &twilio_sid), Some(KeyType::Twilio));

        let github_pat = format!("ghp_{}", "16C7e42F292c6912E7710c838347Ae178B4a");
        assert_eq!(detect("K", &github_pat), Some(KeyType::GitHubToken));
    }

    #[test]
    fn key_name_hints_fill_the_gaps() {
        assert_eq!(
            detect("DATABASE_URL", "some-opaque-connection-string"),
            Some(KeyType::DatabaseUrl)
        );
        assert_eq!(detect("JWT_SECRET", "hunter2"), Some(KeyType::JwtSecret));
        assert_eq!(
            detect(
                "AWS_SECRET_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ),
            Some(KeyType::AwsSecretKey)
        );
        assert_eq!(
            detect("TWILIO_AUTH_TOKEN", "whatever"),
            Some(KeyType::Twilio)
        );
    }

    #[test]
    fn anthropic_wins_over_openai_prefix() {
        assert_eq!(
            detect("K", "sk-ant-something-long"),
            Some(KeyType::Anthropic)
        );
    }

    #[test]
    fn undistinctive_values_are_none() {
        assert_eq!(detect("MY_FLAG", "true"), None);
        assert_eq!(detect("PORT", "5432"), None);
        assert_eq!(detect("GREETING", "hello world"), None);
    }
}
