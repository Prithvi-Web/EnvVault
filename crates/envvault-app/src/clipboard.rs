//! Secret-safe clipboard (spec §4.6): plaintext never crosses into JS for a
//! copy — Rust writes the pasteboard directly, marks it concealed on macOS
//! (`org.nspasteboard.ConcealedType`, honored by clipboard managers), and
//! auto-clears after 30 seconds unless the user has since copied something
//! else.

use std::sync::atomic::Ordering;
use std::time::Duration;

use envvault_core::secrecy::{ExposeSecret, SecretString};
use tauri::AppHandle;

use crate::error::AppError;
use crate::state::AppState;

pub const CLEAR_AFTER_SECONDS: u32 = 30;

/// Write `value` to the clipboard and schedule the auto-clear. The value
/// enters the thread as a `SecretString` (zeroized when the thread drops it).
pub fn copy_with_auto_clear(
    app: AppHandle,
    state: &AppState,
    value: SecretString,
) -> Result<(), AppError> {
    write_text(&app, value.expose_secret())?;

    // Each copy bumps the generation; an older timer that wakes up and sees
    // a newer generation does nothing (a fresher copy owns the clipboard).
    let generation = state.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let state_gen = state.clipboard_generation.clone();

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(u64::from(CLEAR_AFTER_SECONDS)));
        if state_gen.load(Ordering::SeqCst) != generation {
            return;
        }
        // Only clear if the clipboard still holds our secret — never wipe
        // something the user copied in the meantime.
        if read_text(&app).is_some_and(|current| current == value.expose_secret()) {
            let _ = write_text(&app, "");
        }
    });

    Ok(())
}

#[cfg(target_os = "macos")]
fn write_text(_app: &AppHandle, text: &str) -> Result<(), AppError> {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
    use objc2_foundation::NSString;

    unsafe {
        let pasteboard = NSPasteboard::generalPasteboard();
        pasteboard.clearContents();
        let ok = pasteboard.setString_forType(&NSString::from_str(text), NSPasteboardTypeString);
        // The concealment marker: its presence (any value) tells clipboard
        // managers not to archive this entry.
        let concealed = NSString::from_str("org.nspasteboard.ConcealedType");
        pasteboard.setString_forType(&NSString::from_str(""), &concealed);
        if ok {
            Ok(())
        } else {
            Err(AppError::IoError {
                message: "could not write to the clipboard".into(),
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn read_text(_app: &AppHandle) -> Option<String> {
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};

    unsafe {
        let pasteboard = NSPasteboard::generalPasteboard();
        pasteboard
            .stringForType(NSPasteboardTypeString)
            .map(|s| s.to_string())
    }
}

#[cfg(not(target_os = "macos"))]
fn write_text(app: &AppHandle, text: &str) -> Result<(), AppError> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard()
        .write_text(text.to_string())
        .map_err(|e| AppError::IoError {
            message: format!("could not write to the clipboard: {e}"),
        })
}

#[cfg(not(target_os = "macos"))]
fn read_text(app: &AppHandle) -> Option<String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    app.clipboard().read_text().ok()
}
