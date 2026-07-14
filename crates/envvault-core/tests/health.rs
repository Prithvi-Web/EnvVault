//! Health dashboard suite (spec F7 gate): all four finding types
//! demonstrated on seeded data, plus ranking and entropy behavior.

use chrono::{Duration, Utc};

use envvault_core::detect::KeyType;
use envvault_core::health::{
    analyze_at, shannon_bits, FindingKind, Severity, WeakReason, MIN_SIGNING_KEY_BITS,
};
use envvault_core::secret::SecretValue;
use envvault_core::vault::Vault;

fn vault_with(secrets: &[(&str, &str, bool)]) -> Vault {
    // Each tuple: (key, value, is_production). All in one project.
    let mut vault = Vault::default();
    let pid = vault.add_project("app".into(), "/tmp/app".into()).unwrap();
    let (dev, prod) = {
        let p = vault.project(pid).unwrap();
        (p.environments[0].id, p.environments[1].id)
    };
    for (k, v, is_prod) in secrets {
        let env = if *is_prod { prod } else { dev };
        vault
            .add_secret(pid, env, (*k).into(), SecretValue::new((*v).into()), None)
            .unwrap();
    }
    vault
}

#[test]
fn stale_secrets_are_flagged_and_ranked_by_age_and_prod() {
    let now = Utc::now();
    let mut vault = vault_with(&[
        ("FRESH_KEY", "value-just-set-now-abcdef", false),
        ("OLD_DEV_KEY", "some-old-dev-value-1234", false),
        ("ANCIENT_PROD_KEY", "sk_live_ancientvalue999", true),
    ]);

    // Backdate rotation times.
    for p in vault.projects.iter_mut() {
        for e in p.environments.iter_mut() {
            for s in e.secrets.iter_mut() {
                s.rotated_at = match s.key.as_str() {
                    "OLD_DEV_KEY" => now - Duration::days(120),
                    "ANCIENT_PROD_KEY" => now - Duration::days(400),
                    _ => now,
                };
            }
        }
    }

    let findings = analyze_at(&vault, now);
    let stale: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Stale { .. }))
        .collect();
    assert_eq!(stale.len(), 2, "fresh key must not be flagged");

    // The 400-day production key ranks above the 120-day dev key.
    let ancient = stale
        .iter()
        .find(|f| f.locations[0].secret_key == "ANCIENT_PROD_KEY")
        .unwrap();
    let old = stale
        .iter()
        .find(|f| f.locations[0].secret_key == "OLD_DEV_KEY")
        .unwrap();
    assert_eq!(ancient.severity, Severity::Critical); // prod + very old
    assert_eq!(old.severity, Severity::Warning);
    // Overall ordering puts the ancient prod key first among these two.
    let idx_ancient = findings
        .iter()
        .position(|f| std::ptr::eq(*ancient, f))
        .unwrap();
    let idx_old = findings.iter().position(|f| std::ptr::eq(*old, f)).unwrap();
    assert!(idx_ancient < idx_old);
}

#[test]
fn reused_value_across_dev_and_prod_is_critical() {
    let vault = vault_with(&[
        ("API_KEY", "shared-secret-value-xyz", false),
        ("API_KEY", "shared-secret-value-xyz", true), // same value in prod
    ]);
    let findings = analyze_at(&vault, Utc::now());
    let reused: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Reused))
        .collect();
    assert_eq!(reused.len(), 1);
    assert_eq!(reused[0].severity, Severity::Critical);
    assert_eq!(reused[0].locations.len(), 2);
    // The finding names both places but never the value.
    assert!(!format!("{:?}", reused[0]).contains("shared-secret-value-xyz"));
}

#[test]
fn reuse_across_projects_is_flagged_as_warning() {
    let mut vault = Vault::default();
    let p1 = vault.add_project("one".into(), "/tmp/one".into()).unwrap();
    let p2 = vault.add_project("two".into(), "/tmp/two".into()).unwrap();
    let e1 = vault.project(p1).unwrap().environments[0].id;
    let e2 = vault.project(p2).unwrap().environments[0].id;
    vault
        .add_secret(
            p1,
            e1,
            "DB".into(),
            SecretValue::new("same-db-password-01".into()),
            None,
        )
        .unwrap();
    vault
        .add_secret(
            p2,
            e2,
            "DB".into(),
            SecretValue::new("same-db-password-01".into()),
            None,
        )
        .unwrap();

    let findings = analyze_at(&vault, Utc::now());
    let reused: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Reused))
        .collect();
    assert_eq!(reused.len(), 1);
    assert_eq!(reused[0].severity, Severity::Warning);
}

#[test]
fn unique_values_are_never_flagged_as_reused() {
    let vault = vault_with(&[
        ("A", "unique-value-one-aaaa", false),
        ("B", "unique-value-two-bbbb", false),
    ]);
    let findings = analyze_at(&vault, Utc::now());
    assert!(!findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::Reused)));
}

#[test]
fn weak_signing_secret_by_common_value() {
    let vault = vault_with(&[("JWT_SECRET", "secret", false)]);
    let findings = analyze_at(&vault, Utc::now());
    let weak: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Weak { .. }))
        .collect();
    assert_eq!(weak.len(), 1);
    assert!(matches!(
        weak[0].kind,
        FindingKind::Weak {
            reason: WeakReason::CommonValue
        }
    ));
}

#[test]
fn weak_signing_secret_by_low_entropy() {
    // A short low-variety JWT secret: below 60 bits.
    let vault = vault_with(&[("SESSION_SECRET", "aaaaaaaaaaaa", false)]);
    let findings = analyze_at(&vault, Utc::now());
    assert!(findings.iter().any(|f| matches!(
        f.kind,
        FindingKind::Weak {
            reason: WeakReason::LowEntropy
        }
    )));
}

#[test]
fn strong_signing_secret_is_not_flagged() {
    // A real 48-byte base64 secret is well above the threshold.
    let strong = "kJ8h2Lp0qRzX4vN7wYbC3mFdG9sT1uA6eW5rH0iK2oPjLnQ8xZ";
    let vault = vault_with(&[("JWT_SECRET", strong, true)]);
    let findings = analyze_at(&vault, Utc::now());
    assert!(!findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::Weak { .. })));
}

#[test]
fn non_signing_weak_values_are_not_flagged() {
    // A plain feature flag of "test" is not a signing key.
    let vault = vault_with(&[("FEATURE_FLAG", "test", false)]);
    let findings = analyze_at(&vault, Utc::now());
    assert!(!findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::Weak { .. })));
}

#[test]
fn exposed_in_git_is_critical_until_rotated() {
    let now = Utc::now();
    let mut vault = vault_with(&[("STRIPE_SECRET_KEY", "sk_live_committedvalue", true)]);
    {
        let s = &mut vault.projects[0].environments[1].secrets[0];
        s.exposed_in_git_at = Some(now - Duration::days(10));
        s.rotated_at = now - Duration::days(10); // not rotated since exposure
    }
    let findings = analyze_at(&vault, now);
    let exposed: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Exposed { .. }))
        .collect();
    assert_eq!(exposed.len(), 1);
    assert_eq!(exposed[0].severity, Severity::Critical);
    // Exposed-critical outranks everything → it is first.
    assert!(matches!(findings[0].kind, FindingKind::Exposed { .. }));

    // Now rotate it AFTER the exposure: the finding clears.
    vault.projects[0].environments[1].secrets[0].rotated_at = now;
    let findings = analyze_at(&vault, now);
    assert!(!findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::Exposed { .. })));
}

#[test]
fn detected_type_carries_specific_rotation_url() {
    let now = Utc::now();
    let mut vault = vault_with(&[("STRIPE_SECRET_KEY", "sk_live_abcdefghij", true)]);
    vault.projects[0].environments[1].secrets[0].rotated_at = now - Duration::days(200);
    // Detection runs on add_secret, so the type is set.
    assert_eq!(
        vault.projects[0].environments[1].secrets[0].detected_type,
        Some(KeyType::StripeSecret)
    );
    let findings = analyze_at(&vault, now);
    let stale = findings
        .iter()
        .find(|f| matches!(f.kind, FindingKind::Stale { .. }))
        .unwrap();
    assert!(stale.fix_url.contains("dashboard.stripe.com"));
}

#[test]
fn entropy_estimate_separates_weak_from_strong() {
    assert!(shannon_bits("secret") < MIN_SIGNING_KEY_BITS);
    assert!(shannon_bits("aaaaaaaaaaaaaaaa") < MIN_SIGNING_KEY_BITS);
    assert!(
        shannon_bits("kJ8h2Lp0qRzX4vN7wYbC3mFdG9sT1uA6eW5rH0iK2oPjLnQ8xZ") > MIN_SIGNING_KEY_BITS
    );
    assert_eq!(shannon_bits(""), 0.0);
}

#[test]
fn empty_vault_has_no_findings() {
    assert!(analyze_at(&Vault::default(), Utc::now()).is_empty());
}
