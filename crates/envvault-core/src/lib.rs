//! EnvVault core library.
//!
//! ALL cryptography, vault I/O, and domain logic lives here. This crate has
//! zero knowledge of Tauri and zero knowledge of the CLI. Every
//! security-critical code path is testable with plain `cargo test`.
//!
//! `unwrap()` / `expect()` are compile errors in non-test code: fail closed,
//! return a typed [`CoreError`] instead.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![warn(missing_debug_implementations)]

pub mod crypto;
pub mod detect;
pub mod envfile;
pub mod error;
pub mod guard;
pub mod health;
pub mod project;
pub mod ratelimit;
pub mod scanner;
pub mod secret;
pub mod vault;

pub use error::CoreError;

// Single source of truth for the secrecy/age versions used across the
// workspace: the CLI and app import these re-exports, so a version mismatch
// (two incompatible `SecretString` types) cannot happen.
pub use age;
pub use age::secrecy;
