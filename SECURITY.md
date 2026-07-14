# Security

This document states EnvVault's security invariants and — for each one —
where it is **enforced or proven in code**, not just promised. The test
suite is the authority; if a claim here ever drifts from the code, the code
and its tests win, and that drift is a bug worth reporting.

For what EnvVault deliberately does *not* defend against, read the threat
model in [README.md](README.md#threat-model) and the honest list in
[LIMITATIONS.md](LIMITATIONS.md).

## The invariants

### 1. The vault on disk is always ciphertext

The vault is one file: a small JSON envelope whose every sensitive field is
[age](https://age-encryption.org) ciphertext. The payload is encrypted to an
X25519 vault identity; the identity is wrapped with scrypt (N=2^18) under
your master password. No plaintext header, no metadata sidecar, no project
names, no counts. The filename (`vault.age`) is deliberately generic.

- Implementation: `crates/envvault-core/src/crypto.rs`, `vault.rs`
- Proof: `tests/security.rs::vault_file_reveals_no_names_and_payload_is_high_entropy`
  (asserts no plaintext markers and ≥ 7.0 bits/byte Shannon entropy),
  plus the whole `tests/crypto_vault.rs` round-trip/corruption suite

### 2. Plaintext secrets never touch disk

No temp file, no cache, no log ever contains a secret value. The CLI injects
secrets into the child **process environment** directly — it does not write
a `.env`, not even a temporary one. Import & Secure moves your old `.env` to
an encrypted-at-rest world and shreds the original (with a 7-day parked
backup outside the repo).

- Proof: `tests/security.rs::full_workflow_leaves_zero_plaintext_on_disk`
  (runtime-random values, every write path exercised, every produced byte
  scanned) and the CLI suite's `run_writes_no_file_anywhere`

### 3. Secrets in memory are guarded and zeroized

Every plaintext value lives in a `SecretValue` (built on `secrecy` +
`zeroize`): zeroized on drop, `Debug` prints `[REDACTED]`, and there is **no
`Display` implementation at all** — code that tries to `format!("{}")` a
secret does not compile. Locking the vault drops the whole decrypted model.

- Implementation: `crates/envvault-core/src/secret.rs`
- Proof: `tests/security.rs` (deep-format redaction test + compile-time
  `static_assertions` that `SecretValue`/`Secret`/`Vault` have no `Display`)

### 4. A panic must not leave decrypted secrets behind

Release builds abort on panic, which skips destructors — so a panic hook
drops (and thereby zeroizes) the unlocked session and any pending share
bundle before the process dies. Best-effort by construction: see
LIMITATIONS.md for the narrow window that remains.

- Implementation: `crates/envvault-app/src/state.rs::wipe_secrets_for_panic`,
  installed in `main.rs`
- Proof: `state.rs` unit test `panic_wipe_drops_session_and_pending_share`

### 5. Writes are atomic and keep three generations of backups

Every save: exclusive cross-process file lock → rotate 3 rolling backups →
write a temp file in the same directory → fsync → atomic rename → fsync the
directory. A crash, kill, or full disk at any point leaves either the old
vault or the new vault — never a torn file.

- Implementation: `crates/envvault-core/src/vault.rs`
- Proof: `tests/storage.rs` (kill-mid-write at three failpoints, disk-full,
  backup rotation, and a two-process write-hammering test)

### 6. Unlocking is rate-limited, persistently

Exponential backoff per failure (1s, 2s, 4s… capped), a 5-minute lockout
from the 10th failure, counter persisted next to the vault so restarting
the app does not reset it. Everything that tries the master password —
including share-bundle and vault imports — goes through the same throttle.

- Implementation: `crates/envvault-core/src/ratelimit.rs`
- Proof: unit tests in that module (progression, persistence, fail-open on
  corrupt counter files — documented honestly there)

### 7. The app has no networking code

No account, no telemetry, no update phone-home. The webview CSP allows no
remote origin (`default-src 'self'`; `connect-src` only Tauri's local IPC),
and CI fails the build if any HTTP client crate (`reqwest`, `hyper`, `ureq`,
`curl`, `isahc`, …) appears in the **resolved dependency graph of any
shipped target** — a stronger check than grepping the lockfile.

- Implementation: `crates/envvault-app/tauri.conf.json`
- Enforcement: `scripts/check-no-http.sh`, run in CI on every push

### 8. Secrets cross the IPC boundary only on explicit action

List/summary types never contain a value; plaintext leaves Rust only via
`reveal_secret` (a deliberate user action) — copying happens in Rust, which
writes the clipboard directly and auto-clears it after 30 seconds (with the
`org.nspasteboard.ConcealedType` marker on macOS so clipboard managers skip
it). Share-bundle previews expose names and lengths only; the decrypted
bundle stays in Rust until you confirm.

- Implementation: `crates/envvault-app/src/commands.rs`, `clipboard.rs`
- Proof: frontend tests assert masking and that the store never holds values

### 9. No `unwrap()` in reachable paths — fail closed

`envvault-core` compiles with `deny(clippy::unwrap_used, expect_used,
panic)` outside tests. Every failure is a typed error; wrong password and
tampered ciphertext are indistinguishable by design and both fail closed.

## Reporting a vulnerability

Please **do not open a public issue** for anything you believe is
exploitable. Instead use GitHub's private vulnerability reporting on this
repository ("Security" tab → "Report a vulnerability"). Expect an
acknowledgement within a few days. If the report stands up, the fix ships
before any public discussion, and you will be credited unless you prefer
otherwise.
