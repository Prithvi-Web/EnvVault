//! In-process session state. The unlocked vault lives here and nowhere else;
//! locking means dropping it (every secret zeroizes on drop, per core).

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use envvault_core::vault::UnlockedVault;

pub struct AppState {
    session: Mutex<Option<UnlockedVault>>,
    last_activity: Mutex<Instant>,
    auto_lock_minutes: Mutex<Option<u32>>,
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
        Self {
            session: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            auto_lock_minutes: Mutex::new(None),
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
    /// actually existed.
    pub fn lock_now(&self) -> bool {
        unpoisoned(&self.session).take().is_some()
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
