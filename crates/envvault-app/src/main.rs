//! EnvVault desktop app entry point.
//!
//! This crate is deliberately thin: `#[tauri::command]` functions delegate to
//! `envvault-core` and map `CoreError` to the serializable [`error::AppError`]
//! union. If an `if` about crypto or vault state appears in this crate, it is
//! in the wrong place.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod error;

use tauri_specta::{collect_commands, Builder, ErrorHandlingMode};

/// Single source of truth for the IPC surface. Used both by `main` to build
/// the invoke handler and by the `export_bindings` test to emit
/// `ui/src/bindings.ts` — the frontend can only ever call what is listed here.
fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new()
        .commands(collect_commands![commands::app_info])
        .error_handling(ErrorHandlingMode::Result)
}

fn main() {
    let specta = specta_builder();

    tauri::Builder::default()
        .invoke_handler(specta.invoke_handler())
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
