//! Persistent unlock rate limiting (spec F2).
//!
//! Exponential backoff after each failed attempt (1s, 2s, 4s… capped at
//! 64s); from the 10th failure onward every attempt requires a 5-minute
//! lockout. State persists in a sidecar file next to the vault, so
//! restarting the app does not reset the counter.
//!
//! Honesty note (threat model): the sidecar is plain JSON and an attacker
//! with filesystem access can delete it — but such an attacker can copy the
//! vault and brute-force offline anyway; the KDF is the real defense there.
//! Rate limiting protects against casual/opportunistic keyboard attempts.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

pub const MAX_ATTEMPTS_BEFORE_LOCKOUT: u32 = 10;
pub const LOCKOUT_SECONDS: u64 = 300;
const MAX_BACKOFF_SECONDS: u64 = 64;

#[derive(Debug, Default, Serialize, Deserialize)]
struct ThrottleState {
    failures: u32,
    last_failure_unix: u64,
}

fn throttle_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".throttle");
    vault_path.with_file_name(name)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load(vault_path: &Path) -> ThrottleState {
    fs::read(throttle_path(vault_path))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn store(vault_path: &Path, state: &ThrottleState) {
    // Best-effort: a failed write must never block an unlock attempt's
    // error reporting; it only weakens throttling, which fails safe upward.
    if let Ok(bytes) = serde_json::to_vec(state) {
        let _ = fs::write(throttle_path(vault_path), bytes);
    }
}

/// Seconds the caller must still wait before the next attempt is allowed.
/// `0` means an attempt is allowed now.
fn wait_remaining(state: &ThrottleState, now: u64) -> u64 {
    if state.failures == 0 {
        return 0;
    }
    let delay = if state.failures >= MAX_ATTEMPTS_BEFORE_LOCKOUT {
        LOCKOUT_SECONDS
    } else {
        // 1s after the 1st failure, 2s after the 2nd, … capped.
        (1u64 << (state.failures - 1).min(30)).min(MAX_BACKOFF_SECONDS)
    };
    (state.last_failure_unix + delay).saturating_sub(now)
}

#[doc(hidden)]
pub fn check_at(vault_path: &Path, now: u64) -> Result<(), CoreError> {
    let remaining = wait_remaining(&load(vault_path), now);
    if remaining > 0 {
        Err(CoreError::RateLimited {
            retry_after_seconds: remaining,
        })
    } else {
        Ok(())
    }
}

#[doc(hidden)]
pub fn record_failure_at(vault_path: &Path, now: u64) -> u32 {
    let mut state = load(vault_path);
    state.failures = state.failures.saturating_add(1);
    state.last_failure_unix = now;
    store(vault_path, &state);
    MAX_ATTEMPTS_BEFORE_LOCKOUT.saturating_sub(state.failures)
}

pub fn record_success(vault_path: &Path) {
    let _ = fs::remove_file(throttle_path(vault_path));
}

/// Unlock with rate limiting enforced. This is the entry point the GUI and
/// CLI must use; [`crate::vault::unlock_vault`] alone performs no throttling.
pub fn unlock_vault_guarded(
    vault_path: &Path,
    passphrase: age::secrecy::SecretString,
) -> Result<crate::vault::UnlockedVault, CoreError> {
    let now = now_unix();
    check_at(vault_path, now)?;
    match crate::vault::unlock_vault(vault_path, passphrase) {
        Ok(unlocked) => {
            record_success(vault_path);
            Ok(unlocked)
        }
        Err(CoreError::WrongPassword { .. }) => {
            let remaining = record_failure_at(vault_path, now_unix());
            Err(CoreError::WrongPassword {
                attempts_remaining: Some(remaining),
            })
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_progression_then_lockout() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let t0 = 1_000_000;

        // No failures: allowed.
        assert!(check_at(&vault, t0).is_ok());

        // Failures 1..=9: exponential backoff, capped at 64s.
        let mut expected = [1u64, 2, 4, 8, 16, 32, 64, 64, 64].to_vec();
        for exp in expected.drain(..) {
            record_failure_at(&vault, t0);
            match check_at(&vault, t0) {
                Err(CoreError::RateLimited {
                    retry_after_seconds,
                }) => assert_eq!(retry_after_seconds, exp),
                other => panic!("expected RateLimited, got {other:?}"),
            }
            // After the delay passes, an attempt is allowed again.
            assert!(check_at(&vault, t0 + exp).is_ok());
        }

        // 10th failure: 5-minute lockout.
        let remaining = record_failure_at(&vault, t0);
        assert_eq!(remaining, 0);
        match check_at(&vault, t0 + 299) {
            Err(CoreError::RateLimited {
                retry_after_seconds,
            }) => assert_eq!(retry_after_seconds, 1),
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert!(check_at(&vault, t0 + LOCKOUT_SECONDS).is_ok());

        // Every failure past 10 keeps requiring the full lockout.
        record_failure_at(&vault, t0 + LOCKOUT_SECONDS);
        match check_at(&vault, t0 + LOCKOUT_SECONDS + 1) {
            Err(CoreError::RateLimited {
                retry_after_seconds,
            }) => assert_eq!(retry_after_seconds, LOCKOUT_SECONDS - 1),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn counter_persists_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let t0 = 2_000_000;

        for _ in 0..MAX_ATTEMPTS_BEFORE_LOCKOUT {
            record_failure_at(&vault, t0);
        }
        // "Restart": all state is re-read from disk by a fresh call.
        match check_at(&vault, t0 + 10) {
            Err(CoreError::RateLimited {
                retry_after_seconds,
            }) => assert_eq!(retry_after_seconds, LOCKOUT_SECONDS - 10),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn success_clears_the_counter() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        record_failure_at(&vault, 3_000_000);
        record_success(&vault);
        assert!(check_at(&vault, 3_000_000).is_ok());
        assert!(!throttle_path(&vault).exists());
    }

    #[test]
    fn corrupt_throttle_file_fails_open_not_crash() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        fs::write(throttle_path(&vault), b"{not json").unwrap();
        assert!(check_at(&vault, 1).is_ok());
    }

    #[test]
    fn guarded_unlock_counts_failures_and_reports_remaining() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        crate::vault::create_vault_with_work_factor(
            &vault,
            age::secrecy::SecretString::from("right".to_owned()),
            false,
            10,
        )
        .unwrap();

        let err =
            unlock_vault_guarded(&vault, age::secrecy::SecretString::from("wrong".to_owned()))
                .unwrap_err();
        match err {
            CoreError::WrongPassword { attempts_remaining } => {
                assert_eq!(attempts_remaining, Some(9));
            }
            other => panic!("expected WrongPassword, got {other:?}"),
        }

        // Immediately retrying is rate-limited (1s backoff).
        let err =
            unlock_vault_guarded(&vault, age::secrecy::SecretString::from("wrong".to_owned()))
                .unwrap_err();
        assert!(matches!(err, CoreError::RateLimited { .. }), "got {err:?}");
    }
}
