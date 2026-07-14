//! In-process session state. The unlocked vault lives here and nowhere else;
//! locking means dropping it (every secret zeroizes on drop, per core).

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use envvault_core::share::ShareBundle;
use envvault_core::vault::UnlockedVault;

/// The decrypted state a panic must not leave behind (spec §8.5): the
/// unlocked vault and any pending share bundle. Shared `Arc`s so the panic
/// hook can reach them without going through Tauri's state manager.
type SessionStore = Arc<Mutex<Option<UnlockedVault>>>;
type PendingShareStore = Arc<Mutex<Option<ShareBundle>>>;

/// Registered by [`AppState::new`]; consumed by [`wipe_secrets_for_panic`].
static PANIC_WIPE_TARGET: Mutex<Option<(SessionStore, PendingShareStore)>> = Mutex::new(None);

/// Drop (and thereby zeroize) every decrypted secret. Installed as a panic
/// hook in `main` — essential because release builds abort on panic, so
/// unwinding `Drop`s (the normal zeroization path) never run there.
///
/// Must never panic or block: if the panicking thread itself holds a lock,
/// `try_lock` skips it rather than deadlocking. That residual window is
/// documented in LIMITATIONS.md (macOS does not write core dumps by
/// default, so the practical exposure is nil).
pub fn wipe_secrets_for_panic() {
    let stores = match PANIC_WIPE_TARGET.try_lock() {
        Ok(guard) => guard.clone(),
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner().clone(),
        Err(TryLockError::WouldBlock) => None,
    };
    let Some((session, pending)) = stores else {
        return;
    };
    take_and_drop(&session);
    take_and_drop(&pending);
}

/// Best-effort take-and-drop that can never panic or block.
fn take_and_drop<T>(store: &Mutex<Option<T>>) {
    match store.try_lock() {
        Ok(mut guard) => drop(guard.take()),
        Err(TryLockError::Poisoned(poisoned)) => drop(poisoned.into_inner().take()),
        Err(TryLockError::WouldBlock) => {}
    }
}

pub struct AppState {
    session: SessionStore,
    last_activity: Mutex<Instant>,
    auto_lock_minutes: Mutex<Option<u32>>,
    /// A decrypted share bundle between "preview" and "confirm import". Kept
    /// in Rust so the plaintext never crosses to the frontend; dropped
    /// (zeroizing every value) on confirm, cancel, or lock.
    pending_share: PendingShareStore,
    /// Bumped on every secret copy; lets a stale auto-clear timer detect that
    /// a newer copy owns the clipboard. Arc so timer threads can hold it.
    pub clipboard_generation: Arc<AtomicU64>,
}

/// A poisoned mutex means another thread panicked while holding it. For a
/// lock around session state the safe move is to keep going with the data
/// (fail closed happens at the vault layer, not here) rather than crash.
fn unpoisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl AppState {
    pub fn new() -> Self {
        let session: SessionStore = Arc::new(Mutex::new(None));
        let pending_share: PendingShareStore = Arc::new(Mutex::new(None));
        *unpoisoned(&PANIC_WIPE_TARGET) = Some((session.clone(), pending_share.clone()));
        Self {
            session,
            last_activity: Mutex::new(Instant::now()),
            auto_lock_minutes: Mutex::new(None),
            pending_share,
            clipboard_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn session(&self) -> MutexGuard<'_, Option<UnlockedVault>> {
        unpoisoned(&self.session)
    }

    /// Install a freshly unlocked session and cache its auto-lock setting.
    pub fn set_session(&self, unlocked: UnlockedVault) {
        *unpoisoned(&self.auto_lock_minutes) = unlocked.vault().settings.auto_lock_minutes;
        *unpoisoned(&self.session) = Some(unlocked);
        self.touch();
    }

    /// Drop the session (zeroizing all secrets). Returns whether a session
    /// actually existed. A half-finished share import dies with it.
    pub fn lock_now(&self) -> bool {
        unpoisoned(&self.pending_share).take();
        unpoisoned(&self.session).take().is_some()
    }

    pub fn set_pending_share(&self, bundle: ShareBundle) {
        *unpoisoned(&self.pending_share) = Some(bundle);
    }

    pub fn pending_share(&self) -> MutexGuard<'_, Option<ShareBundle>> {
        unpoisoned(&self.pending_share)
    }

    pub fn clear_pending_share(&self) {
        unpoisoned(&self.pending_share).take();
    }

    pub fn is_unlocked(&self) -> bool {
        unpoisoned(&self.session).is_some()
    }

    pub fn touch(&self) {
        *unpoisoned(&self.last_activity) = Instant::now();
    }

    pub fn idle_seconds(&self) -> u64 {
        unpoisoned(&self.last_activity).elapsed().as_secs()
    }

    pub fn auto_lock_minutes(&self) -> Option<u32> {
        *unpoisoned(&self.auto_lock_minutes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envvault_core::secrecy::SecretString;
    use envvault_core::vault::create_vault_with_work_factor;

    /// The panic hook's wipe path: an unlocked session and a pending share
    /// bundle must both be gone (dropped → zeroized) after the wipe runs.
    #[test]
    fn panic_wipe_drops_session_and_pending_share() {
        let dir = tempfile::tempdir().unwrap();
        let created = create_vault_with_work_factor(
            &dir.path().join("vault.age"),
            SecretString::from("panic wipe test pw".to_owned()),
            false,
            10,
        )
        .unwrap();

        let state = AppState::new(); // registers itself as the wipe target
        state.set_session(created.unlocked);
        state.set_pending_share(envvault_core::share::ShareBundle::new(
            "p".into(),
            "development".into(),
            false,
            None,
            Vec::new(),
            chrono::Utc::now(),
        ));
        assert!(state.is_unlocked());
        assert!(state.pending_share().is_some());

        wipe_secrets_for_panic();

        assert!(!state.is_unlocked(), "session must be dropped by the wipe");
        assert!(
            state.pending_share().is_none(),
            "pending share must be dropped"
        );
        // Idempotent and panic-free when there is nothing left to wipe.
        wipe_secrets_for_panic();
    }
}
