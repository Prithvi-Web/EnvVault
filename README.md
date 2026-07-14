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

## Why this exists

Over 28 million credentials leaked on GitHub in 2025, and the dominant cause
is nothing clever: a developer ran `git add .` with a `.env` sitting in the
project directory. Git is append-only — deleting the file later does not
remove the secret from history. EnvVault makes that accident physically
impossible: the plaintext never exists inside the directory that `git add .`
globs.

## How it works, in 30 seconds

1. **Add a project** and let *Import & Secure* eat your existing `.env`: the
   secrets go into the encrypted vault, a safe-to-commit `.env.example` is
   written, `.gitignore` gets fixed, and the original file is shredded (with
   a 7-day parked backup outside the repo). If the `.env` was ever committed,
   EnvVault tells you — plainly — which secrets are already exposed and links
   each provider's rotation page.
2. **Run your app through the CLI**, which injects the secrets into the child
   process's environment. Nothing else changes — stdio, signals, exit codes
   all pass through, and no `.env` is ever written:

   ```bash
   envvault run -- npm run dev            # development (always the default)
   envvault run --env production -- ./deploy.sh   # production is explicit, never implied
   envvault import team-secrets.age       # bring in a teammate's share bundle
   ```
3. **Everything else is the desktop app**: environments with production in
   red everywhere, a Guard that watches your projects and notifies within
   seconds if a plaintext `.env` reappears, a health dashboard (stale /
   reused / weak / exposed secrets, each with a concrete fix), encrypted
   sharing with teammates, and one-click encrypted backups. All of it
   keyboard-first: `⌘K` command palette, `/` to search, `⌘L` to lock.

## Install

There are no signed installers yet — building from source is the supported
path (about two minutes on a warm toolchain).

**Prerequisites (all platforms):** [Rust (stable)](https://rustup.rs) and
Node.js ≥ 20.

- **macOS:** Xcode Command Line Tools (`xcode-select --install`).
- **Windows:** Microsoft C++ Build Tools and WebView2 (preinstalled on
  Windows 11).
- **Linux:** Tauri's [system packages](https://tauri.app/start/prerequisites/)
  (`webkit2gtk`, `libayatana-appindicator`, …).

```bash
git clone https://github.com/Prithvi-Web/EnvVault && cd EnvVault

# The desktop app
cd crates/envvault-app/ui && npm install && cd ..
./ui/node_modules/.bin/tauri build          # bundle lands in target/release/bundle/

# The CLI (puts `envvault` on your PATH)
cargo install --path crates/envvault-cli
```

On first launch the app walks you through creating a vault: one master
password (a real strength meter, not a regex) and an optional offline
recovery key. **There is no password reset** — no recovery email, no cloud
escrow. That is the entire point, and the app makes you acknowledge it.

## Threat model

Stated honestly, because overclaiming in a security product is a bug.

**EnvVault protects against:**

- the accidental `git add .` — plaintext secrets no longer exist in the repo
- secrets already buried in git history going unnoticed (it checks, and
  tells you what to rotate)
- secrets leaking into Docker build contexts, backup tools, and file-sync
  services that sweep your project folder
- plaintext secrets at rest on a lost or stolen laptop (the vault is
  ciphertext; unlocking is rate-limited with a persistent counter)

**EnvVault does not protect against:**

- malware already running as your user (keyloggers, debuggers, clipboard
  sniffers)
- a compromised dependency inside the app you *chose* to run with secrets
  injected — that process legitimately has them
- someone who knows (or can guess) your master password

The full list of limitations and honest uncertainties — including SSD
secure-delete caveats and clipboard edge cases — is in
[LIMITATIONS.md](LIMITATIONS.md). The security invariants and where each one
is proven in the test suite are in [SECURITY.md](SECURITY.md).

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
├── envvault-cli/    # the `envvault` binary (secret injection, import)
└── envvault-app/    # Tauri desktop app + React UI (thin shell over core)
```

The separation is the security architecture: every security-critical code
path lives in `envvault-core` and is testable with plain `cargo test` — no
GUI, no webview, no mocks. The GUI and CLI call identical functions, so they
cannot drift. The TypeScript bindings are generated from the Rust command
signatures at build time; renaming a command or changing a type fails the
frontend build.

## Development

```bash
cargo test --workspace                                   # 150+ tests incl. the security suite
cargo clippy --workspace --all-targets -- -D warnings    # zero-warning policy
bash scripts/check-no-http.sh                            # prove there is no networking code
cd crates/envvault-app/ui && npm run build && npm test   # strict tsc + vitest
```

CI runs all of the above on Linux, macOS, and Windows for every push.
