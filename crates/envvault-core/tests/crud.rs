//! CRUD invariants: unique paths/names, validation, stale-id handling,
//! rotation timestamps. These methods are the only mutation path shared by
//! the GUI and CLI, so their invariants are the data model's invariants.

use envvault_core::detect::KeyType;
use envvault_core::secret::SecretValue;
use envvault_core::vault::{SecretUpdate, Vault};
use envvault_core::CoreError;

fn vault_with_project() -> (Vault, uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let mut vault = Vault::default();
    let pid = vault
        .add_project("acme".into(), "/tmp/acme".into())
        .unwrap();
    let (dev, prod) = {
        let p = vault.project(pid).unwrap();
        (p.environments[0].id, p.environments[1].id)
    };
    (vault, pid, dev, prod)
}

#[test]
fn new_project_gets_dev_and_prod_environments() {
    let (vault, pid, ..) = vault_with_project();
    let p = vault.project(pid).unwrap();
    assert_eq!(p.environments.len(), 2);
    assert_eq!(p.environments[0].name, "development");
    assert!(!p.environments[0].is_production);
    assert_eq!(p.environments[1].name, "production");
    assert!(p.environments[1].is_production);
}

#[test]
fn duplicate_project_path_is_rejected() {
    let (mut vault, ..) = vault_with_project();
    let err = vault
        .add_project("other".into(), "/tmp/acme".into())
        .unwrap_err();
    assert!(matches!(err, CoreError::DuplicateProjectPath(_)));
}

#[test]
fn empty_names_are_rejected() {
    let (mut vault, pid, dev, _) = vault_with_project();
    assert!(matches!(
        vault.add_project("   ".into(), "/tmp/x".into()),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        vault.rename_project(pid, "".into()),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        vault.add_secret(pid, dev, "  ".into(), SecretValue::new("v".into()), None),
        Err(CoreError::InvalidInput(_))
    ));
}

#[test]
fn env_var_key_syntax_is_enforced() {
    let (mut vault, pid, dev, _) = vault_with_project();
    for bad in ["1STARTS_WITH_DIGIT", "HAS SPACE", "HAS-DASH", "ümlaut"] {
        assert!(
            matches!(
                vault.add_secret(pid, dev, bad.into(), SecretValue::new("v".into()), None),
                Err(CoreError::InvalidInput(_))
            ),
            "should reject {bad:?}"
        );
    }
    assert!(vault
        .add_secret(
            pid,
            dev,
            "_VALID_KEY_2".into(),
            SecretValue::new("v".into()),
            None
        )
        .is_ok());
}

#[test]
fn duplicate_secret_key_in_same_env_is_rejected_but_ok_across_envs() {
    let (mut vault, pid, dev, prod) = vault_with_project();
    vault
        .add_secret(
            pid,
            dev,
            "API_KEY".into(),
            SecretValue::new("a".into()),
            None,
        )
        .unwrap();
    let err = vault
        .add_secret(
            pid,
            dev,
            "API_KEY".into(),
            SecretValue::new("b".into()),
            None,
        )
        .unwrap_err();
    assert!(matches!(err, CoreError::SecretNameTaken(_)));
    // Same key in production is fine — that's the whole point of envs.
    assert!(vault
        .add_secret(
            pid,
            prod,
            "API_KEY".into(),
            SecretValue::new("c".into()),
            None
        )
        .is_ok());
}

#[test]
fn add_secret_detects_key_type() {
    let (mut vault, pid, dev, _) = vault_with_project();
    let sid = vault
        .add_secret(
            pid,
            dev,
            "STRIPE_KEY".into(),
            SecretValue::new("sk_live_abc123".into()),
            None,
        )
        .unwrap();
    let env = vault.environment_mut(pid, dev).unwrap();
    let s = env.secrets.iter().find(|s| s.id == sid).unwrap();
    assert_eq!(s.detected_type, Some(KeyType::StripeSecret));
}

#[test]
fn updating_value_bumps_rotated_at_and_redetects() {
    let (mut vault, pid, dev, _) = vault_with_project();
    let sid = vault
        .add_secret(
            pid,
            dev,
            "TOKEN".into(),
            SecretValue::new("plain".into()),
            None,
        )
        .unwrap();
    let before = vault.environment_mut(pid, dev).unwrap().secrets[0].rotated_at;

    vault
        .update_secret(
            pid,
            dev,
            sid,
            SecretUpdate {
                value: Some(SecretValue::new("ghp_1234567890abcdef".into())),
                ..Default::default()
            },
        )
        .unwrap();

    let s = &vault.environment_mut(pid, dev).unwrap().secrets[0];
    assert!(s.rotated_at >= before);
    assert_eq!(s.detected_type, Some(KeyType::GitHubToken));
    assert_eq!(s.value.expose(), "ghp_1234567890abcdef");
}

#[test]
fn key_rename_collision_is_rejected() {
    let (mut vault, pid, dev, _) = vault_with_project();
    vault
        .add_secret(pid, dev, "A".into(), SecretValue::new("1".into()), None)
        .unwrap();
    let sid_b = vault
        .add_secret(pid, dev, "B".into(), SecretValue::new("2".into()), None)
        .unwrap();
    let err = vault
        .update_secret(
            pid,
            dev,
            sid_b,
            SecretUpdate {
                key: Some("A".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, CoreError::SecretNameTaken(_)));
}

#[test]
fn stale_ids_are_typed_errors() {
    let (mut vault, pid, dev, _) = vault_with_project();
    let ghost = uuid::Uuid::new_v4();
    assert!(matches!(vault.project_mut(ghost), Err(CoreError::StaleId)));
    assert!(matches!(
        vault.remove_secret(pid, dev, ghost),
        Err(CoreError::StaleId)
    ));
    assert!(matches!(
        vault.remove_environment(pid, ghost),
        Err(CoreError::StaleId)
    ));
    assert!(matches!(
        vault.remove_project(ghost),
        Err(CoreError::StaleId)
    ));
}

#[test]
fn last_environment_cannot_be_removed() {
    let (mut vault, pid, dev, prod) = vault_with_project();
    vault.remove_environment(pid, prod).unwrap();
    let err = vault.remove_environment(pid, dev).unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
}

#[test]
fn duplicate_environment_name_is_rejected_case_insensitively() {
    let (mut vault, pid, ..) = vault_with_project();
    let err = vault
        .add_environment(pid, "Production".into(), true)
        .unwrap_err();
    assert!(matches!(err, CoreError::EnvironmentNameTaken(_)));
    assert!(vault.add_environment(pid, "staging".into(), false).is_ok());
}

#[test]
fn notes_are_trimmed_to_none_when_blank() {
    let (mut vault, pid, dev, _) = vault_with_project();
    let sid = vault
        .add_secret(
            pid,
            dev,
            "K".into(),
            SecretValue::new("v".into()),
            Some("   ".into()),
        )
        .unwrap();
    let env = vault.environment_mut(pid, dev).unwrap();
    let s = env.secrets.iter().find(|s| s.id == sid).unwrap();
    assert_eq!(s.note, None);
}
