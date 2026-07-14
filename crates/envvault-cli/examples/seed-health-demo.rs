//! Dev utility (never shipped): seed a vault that exhibits all four health
//! findings — stale, reused, weak, and git-exposed — for demoing Phase 7.
//!
//! Usage: cargo run -p envvault-cli --example seed-health-demo -- \
//!            <vault-dir> <project-a-dir> <project-b-dir> <password>

use chrono::{Duration, Utc};
use envvault_core::secrecy::SecretString;
use envvault_core::secret::SecretValue;
use envvault_core::vault::create_vault;

fn main() {
    let mut args = std::env::args().skip(1);
    let vault_dir = args.next().expect("vault-dir");
    let proj_a = args.next().expect("project-a-dir");
    let proj_b = args.next().expect("project-b-dir");
    let password = args.next().expect("password");

    std::fs::create_dir_all(&vault_dir).unwrap();
    let created = create_vault(
        std::path::Path::new(&vault_dir).join("vault.age").as_path(),
        SecretString::from(password),
        false,
    )
    .unwrap();
    let mut u = created.unlocked;
    let now = Utc::now();

    let pa = u
        .vault_mut()
        .add_project("payments-api".into(), proj_a.into())
        .unwrap();
    let pb = u
        .vault_mut()
        .add_project("web-frontend".into(), proj_b.into())
        .unwrap();
    let (a_dev, a_prod) = {
        let p = u.vault().project(pa).unwrap();
        (p.environments[0].id, p.environments[1].id)
    };
    let b_dev = u.vault().project(pb).unwrap().environments[0].id;

    let v = u.vault_mut();
    // Exposed-in-git (critical): a committed Stripe key, never rotated.
    v.add_secret(
        pa,
        a_prod,
        "STRIPE_SECRET_KEY".into(),
        SecretValue::new("sk_live_exposedInGitForever".into()),
        None,
    )
    .unwrap();
    // Weak signing secret (critical, prod): JWT_SECRET = "secret".
    v.add_secret(
        pa,
        a_prod,
        "JWT_SECRET".into(),
        SecretValue::new("secret".into()),
        None,
    )
    .unwrap();
    // Reused across dev+prod (critical): same DB URL in both.
    v.add_secret(
        pa,
        a_dev,
        "DATABASE_URL".into(),
        SecretValue::new("postgres://prod:realpw@db/main".into()),
        None,
    )
    .unwrap();
    v.add_secret(
        pa,
        a_prod,
        "DATABASE_URL".into(),
        SecretValue::new("postgres://prod:realpw@db/main".into()),
        None,
    )
    .unwrap();
    // Stale (warning): an old dev API key.
    v.add_secret(
        pa,
        a_dev,
        "SENDGRID_API_KEY".into(),
        SecretValue::new("SG.oldkeyoldkeyoldkey.abcdefghij".into()),
        None,
    )
    .unwrap();
    // Reused across projects (warning): shared analytics token.
    v.add_secret(
        pa,
        a_dev,
        "ANALYTICS_TOKEN".into(),
        SecretValue::new("shared-analytics-token-9911".into()),
        None,
    )
    .unwrap();
    v.add_secret(
        pb,
        b_dev,
        "ANALYTICS_TOKEN".into(),
        SecretValue::new("shared-analytics-token-9911".into()),
        None,
    )
    .unwrap();

    // Now set timestamps/exposure so the analysis fires.
    for p in v.projects.iter_mut() {
        for e in p.environments.iter_mut() {
            for s in e.secrets.iter_mut() {
                match s.key.as_str() {
                    "STRIPE_SECRET_KEY" => {
                        s.exposed_in_git_at = Some(now - Duration::days(30));
                        s.rotated_at = now - Duration::days(30);
                    }
                    "SENDGRID_API_KEY" => s.rotated_at = now - Duration::days(150),
                    _ => {}
                }
            }
        }
    }
    u.save().unwrap();
    println!("seeded health demo");
}
