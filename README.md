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

> **Status: under construction.** Phases 0–8 complete (crypto core, vault,
> GUI, Import & Secure, CLI injection, the Guard, health dashboard, secure
> share, backup & portability). Install instructions and the full threat
> model land with Phase 9 (hardening).

## Your data is not hostage

Everything EnvVault writes is a standard [age](https://age-encryption.org)
file. If EnvVault disappeared tomorrow, here is exactly how to get your
secrets out with the stock `age` CLI and `jq` — no EnvVault code involved.
(This recipe is enforced by an automated test in
`crates/envvault-core/tests/crypto_vault.rs`.)

**Where the vault lives:**

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/EnvVault/vault.age` |
| Windows | `%APPDATA%\EnvVault\vault.age` |
| Linux | `~/.local/share/EnvVault/vault.age` |

**The format:** `vault.age` is a small JSON envelope. Everything sensitive in
it is age ciphertext; it leaks no project names, no counts, no metadata.

```json
{
  "format": "envvault",
  "format_version": 1,
  "wrapped_identity": "<age file: scrypt(master password) → X25519 identity>",
  "recipient": "age1…",              // the vault's public key (your share key)
  "recovery_recipient": "age1… | null",
  "payload": "<age file: X25519 → the vault JSON>"
}
```

**Decrypt with your master password:**

```bash
cd "~/Library/Application Support/EnvVault"           # macOS; see table above
jq -r .wrapped_identity vault.age > wrapped.age
jq -r .payload vault.age > payload.age
age -d wrapped.age > identity.txt                     # prompts for master password
age -d -i identity.txt payload.age > vault.json       # every secret, as JSON
```

**Or with your recovery key** (skips the master password entirely):

```bash
jq -r .payload vault.age | age -d -i recovery-key.txt # file containing AGE-SECRET-KEY-1…
```

**Share bundles** (`Share…` in the app, or `envvault import` on the receiving
side) are plain age files with JSON inside — no envelope at all:

```bash
age -d bundle.age                                     # passphrase bundle
age -d -i ~/.ssh/id_ed25519 bundle.age                # bundle sent to your SSH key
```

Bundles carry an expiry timestamp *inside* the ciphertext which EnvVault
enforces on import. Honesty note: that is a courtesy guardrail, not a
cryptographic guarantee — someone who kept the file can set their clock back.

**Vault backups** (`Backup & portability` in the app) are byte-for-byte
copies of `vault.age`, so the same recipe applies. They are ciphertext and
safe to store anywhere — Dropbox, a USB stick, email to yourself.

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
