# EnvVault

A fully local, zero-cloud desktop secrets manager for developers. It replaces
`.env` files: your secrets live in an encrypted vault **outside** your
repository and are injected directly into your dev process at launch — so
plaintext secrets never exist inside the project folder and can never be
committed.

- **No login. No account. No cloud.** Works forever in airplane mode.
- **No telemetry.** The app contains no networking code — enforced in CI.
- **Encrypted with [age](https://age-encryption.org).** Your data is never
  hostage: the vault is a standard `age` file you can decrypt without this app.

> **Status: under construction.** Phase 0 (workspace scaffold) complete.
> Full README — install instructions, threat model, vault format
> documentation — lands with the final phases.

## Repository layout

```
crates/
├── envvault-core/   # ALL crypto, vault I/O, domain logic. Pure library.
├── envvault-cli/    # the `envvault` binary (secret injection)
└── envvault-app/    # Tauri desktop app + React UI (thin shell over core)
```

## Building from source

Requirements: Rust (stable), Node.js ≥ 20. On Linux, Tauri's
[system dependencies](https://tauri.app/start/prerequisites/).

```bash
cd crates/envvault-app/ui && npm install     # once
npm run tauri dev                            # run the app
cargo test --workspace                       # run the test suite
```
