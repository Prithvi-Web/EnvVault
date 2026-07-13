//! The `envvault` CLI shim.
//!
//! Full implementation lands in Phase 5: `envvault run -- <cmd>` spawns the
//! child with secrets injected into its environment — no `.env` file is ever
//! written, signals are forwarded, and the child's exit code is propagated.

use std::process::ExitCode;

fn main() -> ExitCode {
    let version = env!("CARGO_PKG_VERSION");
    match envvault_core::vault::default_vault_path() {
        Ok(path) => {
            println!("envvault {version}");
            println!("vault location: {}", path.display());
            println!();
            println!("The CLI is scaffolded; `envvault run` arrives in Phase 5.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("envvault: {e}");
            ExitCode::FAILURE
        }
    }
}
