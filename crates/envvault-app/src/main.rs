//! EnvVault desktop app entry point.
//!
//! This crate is deliberately thin: `#[tauri::command]` functions delegate to
//! `envvault-core` and map `CoreError` to the serializable [`error::AppError`]
//! union. If an `if` about crypto or vault state appears in this crate, it is
//! in the wrong place.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod clipboard;
mod commands;
mod error;
mod events;
mod guard;
mod state;

use std::time::Duration;

use tauri::Manager;
use tauri_specta::{collect_commands, collect_events, Builder, ErrorHandlingMode, Event};

use guard::GuardManager;
use state::AppState;

/// Single source of truth for the IPC surface. Used both by `main` to build
/// the invoke handler and by the `export_bindings` test to emit
/// `ui/src/bindings.ts` — the frontend can only ever call what is listed here.
fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new()
        .commands(collect_commands![
            commands::vault_status,
            commands::create_vault,
            commands::unlock,
            commands::lock_vault,
            commands::rekey,
            commands::touch_activity,
            commands::list_projects,
            commands::add_project,
            commands::rename_project,
            commands::remove_project,
            commands::add_environment,
            commands::remove_environment,
            commands::list_secrets,
            commands::add_secret,
            commands::update_secret,
            commands::remove_secret,
            commands::reveal_secret,
            commands::copy_secret,
            commands::scan_env_files,
            commands::preview_env_import,
            commands::import_env,
            commands::guard_status,
            commands::set_guard_enabled,
            commands::set_project_guard_enabled,
            commands::health_report,
            commands::share_key,
            commands::export_share_bundle,
            commands::inspect_share_bundle,
            commands::preview_share_import,
            commands::confirm_share_import,
            commands::cancel_share_import,
            commands::export_vault_backup,
            commands::import_vault_merge,
            commands::import_vault_replace,
        ])
        .events(collect_events![
            events::VaultLockedEvent,
            events::GuardFindingEvent
        ])
        .error_handling(ErrorHandlingMode::Result)
}

/// Auto-lock (spec §4.3): checks idle time against the vault's configured
/// timeout and drops the session when exceeded, telling the frontend.
fn spawn_auto_lock_monitor(handle: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(10));
        let state = handle.state::<AppState>();
        let Some(minutes) = state.auto_lock_minutes() else {
            continue; // "Never" — or vault locked with no cached setting.
        };
        if !state.is_unlocked() {
            continue;
        }
        if state.idle_seconds() >= u64::from(minutes) * 60 && state.lock_now() {
            let _ = events::VaultLockedEvent {
                reason: "idle".into(),
            }
            .emit(&handle);
        }
    });
}

/// Process start, for the §9 cold-launch measurement. Captured as early as
/// `main` allows; the OS exec overhead before `main` is not included (noted
/// in the measurement methodology).
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Print elapsed-since-start to stderr — only when `ENVVAULT_PERF` is set.
/// Costs one env lookup otherwise; exists so the §9 numbers can be measured
/// on the real release binary instead of guessed.
pub fn perf_checkpoint(label: &str) {
    if std::env::var_os("ENVVAULT_PERF").is_some() {
        if let Some(start) = PROCESS_START.get() {
            eprintln!("ENVVAULT_PERF {label}: {:?}", start.elapsed());
        }
    }
}

fn main() {
    let _ = PROCESS_START.set(std::time::Instant::now());

    // Spec §8.5: a panic must not leave decrypted secrets behind. Release
    // builds abort on panic (no unwinding, so Drop/zeroize never runs) —
    // this hook drops the unlocked session and any pending share bundle,
    // zeroizing every value, before the process dies.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        state::wipe_secrets_for_panic();
        default_panic_hook(info);
    }));

    let specta = specta_builder();

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new())
        .manage(GuardManager::new())
        .invoke_handler(specta.invoke_handler())
        .setup(move |app| {
            perf_checkpoint("tauri setup (window created)");
            specta.mount_events(app);
            spawn_auto_lock_monitor(app.handle().clone());
            // Parked .env backups expire after 7 days (spec F4.4).
            std::thread::spawn(|| {
                if let Ok(root) = envvault_core::scanner::env_backup_root() {
                    let _ = envvault_core::scanner::cleanup_old_backups(&root, 7);
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        // Allowed per error doctrine: main() startup failure is unrecoverable.
        .expect("failed to start EnvVault");
}

#[cfg(test)]
mod tests {
    use super::specta_builder;

    /// Regenerates the TypeScript bindings. Run via `npm run bindings` in
    /// `ui/`, which every `npm run dev` / `npm run build` invokes first — the
    /// frontend cannot drift from the Rust command signatures.
    #[test]
    fn export_bindings() {
        specta_builder()
            .export(
                specta_typescript::Typescript::default()
                    .header("// @ts-nocheck is forbidden — these types are the contract.\n"),
                "ui/src/bindings.ts",
            )
            .expect("failed to export TypeScript bindings");
    }
}
