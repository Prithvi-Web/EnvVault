//! Secret health analysis (spec F7): the four finding types the health
//! dashboard surfaces, each with a specific, actionable fix. Pure functions
//! over a [`Vault`] — no I/O, fully unit-tested.
//!
//! Findings never carry a secret's plaintext value. Reuse detection groups
//! by a salted-free fingerprint (a hash) so identical values can be matched
//! without the value leaving the vault.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::detect::{self, KeyType};
use crate::vault::Vault;

/// Not rotated in this many days ⇒ "stale" (spec F7).
pub const STALE_DAYS: i64 = 90;

/// A signing secret below this Shannon-entropy estimate is "weak" (spec F7).
pub const MIN_SIGNING_KEY_BITS: f64 = 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Warning = 1,
    Critical = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    /// Not rotated in 90+ days.
    Stale { days_since_rotation: i64 },
    /// The same value appears in 2+ locations (across projects, or across
    /// dev/prod of one project).
    Reused,
    /// A signing secret with too little entropy (or a known weak value).
    Weak { reason: WeakReason },
    /// The key was found in git history and has not been rotated since.
    Exposed {
        exposed_at: DateTime<Utc>,
        rotated_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeakReason {
    /// A well-known weak value (`secret`, `password`, `changeme`, …).
    CommonValue,
    /// Estimated entropy below [`MIN_SIGNING_KEY_BITS`].
    LowEntropy,
}

/// Where a finding lives. Names, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub project_id: uuid::Uuid,
    pub project_name: String,
    pub environment_id: uuid::Uuid,
    pub environment_name: String,
    pub is_production: bool,
    pub secret_id: uuid::Uuid,
    pub secret_key: String,
    pub detected_type: Option<KeyType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// One-line summary.
    pub title: String,
    /// The concrete fix, e.g. rotation steps.
    pub fix: String,
    /// A provider dashboard URL when we have one (empty otherwise).
    pub fix_url: String,
    /// All secrets this finding covers (reuse spans several; the others one).
    pub locations: Vec<Location>,
}

/// A ranking score so the dashboard can sort worst-first. Higher = worse.
pub fn risk_score(finding: &Finding) -> i64 {
    let mut score = match finding.severity {
        Severity::Critical => 10_000,
        Severity::Warning => 1_000,
        Severity::Info => 100,
    };
    // Production and sensitive key types float to the top within a severity.
    if finding.locations.iter().any(|l| l.is_production) {
        score += 500;
    }
    if finding
        .locations
        .iter()
        .any(|l| is_high_value_type(l.detected_type))
    {
        score += 250;
    }
    if let FindingKind::Stale {
        days_since_rotation,
    } = finding.kind
    {
        score += days_since_rotation; // older = worse
    }
    score
}

fn is_high_value_type(t: Option<KeyType>) -> bool {
    matches!(
        t,
        Some(
            KeyType::StripeSecret
                | KeyType::AwsAccessKey
                | KeyType::AwsSecretKey
                | KeyType::PrivateKey
                | KeyType::DatabaseUrl
                | KeyType::GitHubToken
        )
    )
}

/// Run every check over the vault and return findings, worst-first.
pub fn analyze(vault: &Vault) -> Vec<Finding> {
    analyze_at(vault, Utc::now())
}

/// Testable variant with an injected "now".
pub fn analyze_at(vault: &Vault, now: DateTime<Utc>) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(stale_findings(vault, now));
    findings.extend(reused_findings(vault));
    findings.extend(weak_findings(vault));
    findings.extend(exposed_findings(vault));
    // Worst-first: highest risk score at the top.
    findings.sort_by_key(|f| std::cmp::Reverse(risk_score(f)));
    findings
}

fn location_of(
    vault: &Vault,
    p: &crate::project::Project,
    e: &crate::project::Environment,
    s: &crate::secret::Secret,
) -> Location {
    let _ = vault;
    Location {
        project_id: p.id,
        project_name: p.name.clone(),
        environment_id: e.id,
        environment_name: e.name.clone(),
        is_production: e.is_production,
        secret_id: s.id,
        secret_key: s.key.clone(),
        detected_type: s.detected_type,
    }
}

fn rotation_fix(t: Option<KeyType>) -> (String, String) {
    match t.and_then(detect::rotation_info) {
        Some((url, steps)) => (steps.to_string(), url.to_string()),
        None => (
            "Rotate this credential at its provider and update it here.".to_string(),
            String::new(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Stale
// ---------------------------------------------------------------------------

fn stale_findings(vault: &Vault, now: DateTime<Utc>) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &vault.projects {
        for e in &p.environments {
            for s in &e.secrets {
                let age = (now - s.rotated_at).num_days();
                if age >= STALE_DAYS {
                    let loc = location_of(vault, p, e, s);
                    let (fix, fix_url) = rotation_fix(s.detected_type);
                    let severity = if e.is_production && age >= STALE_DAYS * 3 {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    };
                    out.push(Finding {
                        kind: FindingKind::Stale {
                            days_since_rotation: age,
                        },
                        severity,
                        title: format!("{} hasn't been rotated in {age} days", s.key),
                        fix,
                        fix_url,
                        locations: vec![loc],
                    });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Reused (same value in 2+ places)
// ---------------------------------------------------------------------------

fn reused_findings(vault: &Vault) -> Vec<Finding> {
    // Group locations by value fingerprint. Empty values are ignored.
    let mut groups: HashMap<u64, Vec<Location>> = HashMap::new();
    for p in &vault.projects {
        for e in &p.environments {
            for s in &e.secrets {
                if s.value.is_empty() {
                    continue;
                }
                let fp = fingerprint(s.value.expose());
                groups
                    .entry(fp)
                    .or_default()
                    .push(location_of(vault, p, e, s));
            }
        }
    }

    let mut out = Vec::new();
    for (_, locations) in groups {
        if locations.len() < 2 {
            continue;
        }
        // Cross-environment reuse within one project (dev value == prod
        // value) is the most dangerous form; call it out specifically.
        let same_project = locations
            .iter()
            .all(|l| l.project_id == locations[0].project_id);
        let spans_prod =
            locations.iter().any(|l| l.is_production) && locations.iter().any(|l| !l.is_production);
        let severity = if same_project && spans_prod {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let title = if same_project && spans_prod {
            "The same value is used in development and production".to_string()
        } else {
            format!("The same value is reused in {} places", locations.len())
        };
        out.push(Finding {
            kind: FindingKind::Reused,
            severity,
            title,
            fix: "Give each place its own unique secret. Sharing one value means \
                  a leak anywhere is a leak everywhere."
                .to_string(),
            fix_url: String::new(),
            locations,
        });
    }
    out
}

/// A stable, non-reversible fingerprint of a value (FNV-1a). Used only to
/// group identical values for reuse detection — never stored, never shown.
fn fingerprint(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x00000100000001B3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Weak signing secrets
// ---------------------------------------------------------------------------

const COMMON_WEAK_VALUES: &[&str] = &[
    "secret",
    "password",
    "changeme",
    "change-me",
    "admin",
    "test",
    "default",
    "123456",
    "password123",
    "supersecret",
    "your-secret-here",
    "mysecret",
    "topsecret",
];

/// Does this secret act as a signing/session key, where entropy matters?
fn is_signing_secret(key: &str, detected: Option<KeyType>) -> bool {
    if matches!(detected, Some(KeyType::JwtSecret | KeyType::PrivateKey)) {
        return true;
    }
    let k = key.to_ascii_uppercase();
    (k.contains("JWT")
        || k.contains("SIGN")
        || k.contains("HMAC")
        || k.contains("SESSION")
        || k.contains("COOKIE")
        || k.contains("ENCRYPTION")
        || k.contains("APP_KEY")
        || k.contains("SECRET_KEY_BASE"))
        && (k.contains("SECRET") || k.contains("KEY"))
}

fn weak_findings(vault: &Vault) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &vault.projects {
        for e in &p.environments {
            for s in &e.secrets {
                if !is_signing_secret(&s.key, s.detected_type) {
                    continue;
                }
                let value = s.value.expose();
                if value.is_empty() {
                    continue;
                }
                let reason = if COMMON_WEAK_VALUES
                    .iter()
                    .any(|w| value.eq_ignore_ascii_case(w))
                {
                    Some(WeakReason::CommonValue)
                } else if shannon_bits(value) < MIN_SIGNING_KEY_BITS {
                    Some(WeakReason::LowEntropy)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    let loc = location_of(vault, p, e, s);
                    out.push(Finding {
                        kind: FindingKind::Weak { reason },
                        severity: if e.is_production {
                            Severity::Critical
                        } else {
                            Severity::Warning
                        },
                        title: match reason {
                            WeakReason::CommonValue => {
                                format!("{} uses a well-known weak value", s.key)
                            }
                            WeakReason::LowEntropy => {
                                format!("{} is too weak to sign tokens", s.key)
                            }
                        },
                        fix: "Replace it with a long random value, e.g. \
                              `openssl rand -base64 48`, then invalidate old tokens if you can."
                            .to_string(),
                        fix_url: String::new(),
                        locations: vec![loc],
                    });
                }
            }
        }
    }
    out
}

/// Estimated total Shannon entropy in bits: `len * H`, where `H` is the
/// per-character entropy of the value's byte distribution. Distinguishes
/// `secret` (~14 bits) from a 32-byte random key (~180 bits) reliably.
pub fn shannon_bits(value: &str) -> f64 {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h * len
}

// ---------------------------------------------------------------------------
// Exposed in git history
// ---------------------------------------------------------------------------

fn exposed_findings(vault: &Vault) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &vault.projects {
        for e in &p.environments {
            for s in &e.secrets {
                let Some(exposed_at) = s.exposed_in_git_at else {
                    continue;
                };
                // Only a problem if it has NOT been rotated since exposure.
                // A small grace window (1 min) absorbs the import timestamp.
                if s.rotated_at > exposed_at + Duration::minutes(1) {
                    continue;
                }
                let loc = location_of(vault, p, e, s);
                let (fix, fix_url) = rotation_fix(s.detected_type);
                out.push(Finding {
                    kind: FindingKind::Exposed {
                        exposed_at,
                        rotated_at: s.rotated_at,
                    },
                    severity: Severity::Critical,
                    title: format!("{} was committed to git and is still exposed", s.key),
                    fix: format!(
                        "This value lives in your git history forever. Rotate it now — {fix}"
                    ),
                    fix_url,
                    locations: vec![loc],
                });
            }
        }
    }
    out
}
