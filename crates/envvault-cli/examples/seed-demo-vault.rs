//! Dev utility (never shipped): seed a demo vault for CLI demos.
//!
//! Usage: cargo run -p envvault-cli --example seed-demo-vault -- \
//!            <vault-dir> <project-dir> <password>

use envvault_core::secrecy::SecretString;
use envvault_core::secret::SecretValue;
use envvault_core::vault::create_vault;

fn main() {
    let mut args = std::env::args().skip(1);
    let (vault_dir, project_dir, password) = (
        args.next().expect("vault-dir"),
        args.next().expect("project-dir"),
        args.next().expect("password"),
    );

    std::fs::create_dir_all(&vault_dir).expect("create vault dir");
    std::fs::create_dir_all(&project_dir).expect("create project dir");

    let created = create_vault(
        std::path::Path::new(&vault_dir).join("vault.age").as_path(),
        SecretString::from(password),
        false,
    )
    .expect("create vault");
    let mut unlocked = created.unlocked;

    let pid = unlocked
        .vault_mut()
        .add_project("demo-api".into(), project_dir.into())
        .expect("add project");
    let (dev, prod) = {
        let p = unlocked.vault().project(pid).expect("project");
        (p.environments[0].id, p.environments[1].id)
    };
    let v = unlocked.vault_mut();
    v.add_secret(
        pid,
        dev,
        "STRIPE_SECRET_KEY".into(),
        SecretValue::new("sk_test_demo_dev_key".into()),
        None,
    )
    .expect("secret");
    v.add_secret(
        pid,
        dev,
        "DATABASE_URL".into(),
        SecretValue::new("postgres://dev:dev@localhost/demo".into()),
        None,
    )
    .expect("secret");
    v.add_secret(
        pid,
        prod,
        "STRIPE_SECRET_KEY".into(),
        SecretValue::new("sk_live_demo_prod_key".into()),
        None,
    )
    .expect("secret");
    unlocked.save().expect("save");
    println!("seeded demo vault");
}
