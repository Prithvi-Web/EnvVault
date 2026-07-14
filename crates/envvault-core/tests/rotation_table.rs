//! The rotation-advice table (spec F7: "a specific, actionable fix, not
//! generic advice"). Every key type must have a human label; every type with
//! rotation info must point at a real HTTPS console URL and non-empty steps.

use envvault_core::detect::{label, rotation_info, KeyType};

const ALL_TYPES: [KeyType; 14] = [
    KeyType::StripeSecret,
    KeyType::StripePublishable,
    KeyType::AwsAccessKey,
    KeyType::AwsSecretKey,
    KeyType::OpenAi,
    KeyType::Anthropic,
    KeyType::GitHubToken,
    KeyType::GoogleApi,
    KeyType::SendGrid,
    KeyType::Twilio,
    KeyType::DatabaseUrl,
    KeyType::JwtSecret,
    KeyType::PrivateKey,
    KeyType::Generic,
];

#[test]
fn every_type_has_a_label_and_sane_rotation_advice() {
    for t in ALL_TYPES {
        let l = label(t);
        assert!(!l.trim().is_empty(), "{t:?} has an empty label");

        if let Some((url, steps)) = rotation_info(t) {
            // Convention (relied on by both frontends): the URL is either a
            // well-formed https console link, or empty for credential kinds
            // that have no provider console (DATABASE_URL, JWT secrets,
            // private keys) — the UIs render no link in that case.
            assert!(
                url.is_empty() || url.starts_with("https://"),
                "{t:?} rotation url is neither empty nor https: {url}"
            );
            assert!(
                steps.trim().len() > 20,
                "{t:?} rotation steps look like a stub: {steps:?}"
            );
        }
    }
}

/// The types a leak most urgently needs advice for must actually have it.
#[test]
fn high_value_types_have_concrete_rotation_advice() {
    for t in [
        KeyType::StripeSecret,
        KeyType::AwsAccessKey,
        KeyType::AwsSecretKey,
        KeyType::OpenAi,
        KeyType::Anthropic,
        KeyType::GitHubToken,
        KeyType::GoogleApi,
        KeyType::SendGrid,
        KeyType::Twilio,
    ] {
        assert!(
            rotation_info(t).is_some(),
            "{t:?} must carry rotation advice"
        );
    }
}
