# EnvVault — Session Handoff Prompt

> Paste everything below (from the horizontal rule down) as your first message to Claude in the next session.

---

You are continuing the build of **EnvVault**, a fully-local, zero-cloud desktop secrets manager for developers (Tauri v2 + Rust + React). This is a multi-session project built in phase gates. Phases 0–7 are DONE, committed, and pushed to GitHub. Your job is **Phase 8, then Phase 9**. The bar the user has set, verbatim: **"completely flawless, absolutely 0 errors."** Hold to it.

## Read these first
- The master spec: `/Users/prithvivinay/Downloads/envvault-master-prompt.md` — read it whole before touching code. Sections 4 (security invariants), 8 (error doctrine), 10 (testing), 11 (phase gates) govern everything.
- The project: `/Users/prithvivinay/Desktop/Claude Code/envvault` (this is NOT a fresh dir — it's a mature codebase; explore it before assuming).
- The user's auto-memory (`envvault-project.md`) has condensed notes; this handoff supersedes it where they differ.

## Who the user is
A **non-coder**. Give plain-English explanations, no jargon dumps. They cannot run terminal git — **they push via GitHub Desktop** (button: "Push origin"). After each phase you commit locally; then tell them in one short paragraph to open GitHub Desktop and click Push origin. Do NOT try to `git push` yourself (no credentials on the machine; it fails with "could not read Username").

## Working discipline (non-negotiable)
1. Build ONE phase at a time. After each phase: run the full verification, do a LIVE app demo proving the gate, commit, then STOP and report to the user with the evidence. Wait for them to say "go" before the next phase.
2. **Never claim something works until you've run it and seen it.** No "this should work." Show real output/screenshots.
3. Write tests as you go, in `envvault-core` (that's where all logic lives). Cutting a feature is acceptable; cutting tests is not.
4. Be honest and non-sycophantic. If the spec is wrong, say so and propose better (this has happened several times and improved the product).

## Current state (as of end of Phase 7)
- Git: `main` branch, latest commit `Phase 7: secret health dashboard`. Local == origin, tree clean. CI green on all 3 OSes for the pushed commits (verify the Phase 7 run went green — see CI section).
- Toolchain: Rust installed via rustup — **every bash shell must start with `source "$HOME/.cargo/env"`** or cargo isn't found. Node/npm already present.
- **14 Rust test suites + 6 frontend (vitest) tests, all green. Zero clippy warnings under `-D warnings`. Zero tsc errors (strict + noUncheckedIndexedAccess).**

## Architecture (already built — match these patterns exactly)
Cargo workspace at repo root, three crates under `crates/`:
- **`envvault-core`** — ALL crypto, vault I/O, domain logic. Pure library, no Tauri/CLI deps. `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` in non-test code — use typed `CoreError` (thiserror), never unwrap/panic in runtime paths. Modules: `crypto` (age + scrypt envelope), `vault` (Vault/Project/Environment/Secret, load/save, atomic writes + 3 backups, cross-process file lock, migrations, CRUD methods), `secret` (`SecretValue` = zeroize-on-drop, redacted Debug), `detect` (KeyType detection + `rotation_info`), `envfile` (.env parser), `scanner` (Import & Secure, git history via git2 default-features-off), `guard` (fs watcher), `health` (dashboard analysis), `ratelimit`, `error`.
- **`envvault-cli`** — the `envvault` binary (`run`/`exec`/`status`/`shell-hook`). Injects secrets into child process env, no .env written, signals forwarded, exit codes propagated.
- **`envvault-app`** — thin Tauri shell. `src/commands.rs` (#[tauri::command] fns delegate to core), `src/error.rs` (`AppError` serializable union), `src/guard.rs` (GuardManager), `src/clipboard.rs`, `src/state.rs`, `src/events.rs`. Frontend in `ui/` (React 18 + Vite + Tailwind v4 + Zustand + Radix + lucide).

### The frontend/backend contract (critical — how drift is impossible)
- `tauri-specta` (`=2.0.0-rc.25`) auto-generates `ui/src/bindings.ts` from Rust command signatures via `cargo test -p envvault-app export_bindings`, which `npm run bindings` (and thus `npm run build`/`dev`) runs first.
- The frontend NEVER calls `invoke("string")`. It imports `commands.xxx()` / `events.xxx` from `bindings.ts`. Rename a command or change a type → TS build fails.
- Errors cross as a typed discriminated union; frontend `describeError` in `ui/src/lib/errors.ts` switches exhaustively with a `never` default — add a Rust error variant without handling it → TS build fails. (This has caught real bugs.)
- All DTOs use `#[serde(rename_all = "camelCase")]`. **DTO RULE (spec §4.3): list/summary types NEVER contain a secret value.** Plaintext leaves Rust only via explicit `reveal_secret`; `copy_secret` writes the clipboard in Rust directly. Health findings carry names, never values.
- Schema evolution: new fields on serialized structs get `#[serde(default = "…")]` so old vaults still load. There's a committed v1 vault fixture (`crates/envvault-core/tests/fixtures/vault-v1.age`) that must always load — never regenerate it.

## HARD-WON GOTCHAS (you WILL hit these — internalize them)
1. **TOML target tables are positional.** Any dependency line placed BELOW a `[target.'cfg(...)'.dependencies]` header silently becomes platform-only. This broke Linux+Windows CI once. Keep the macOS-only `[target.'cfg(target_os = "macos")'.dependencies]` block LAST in `crates/envvault-app/Cargo.toml`; add normal deps ABOVE it.
2. **Run CI-strict clippy locally before EVERY commit:** `cargo clippy --workspace --all-targets -- -D warnings`. A macOS-only local `cargo test` will pass while CI's `-D warnings` fails. (There's one KNOWN-harmless warning: `proc-macro-error2` future-incompat — grep it out: `| grep -v proc-macro-error2`.)
3. **GitHub push-protection blocks credential-shaped literals** even in tests. Build such fixtures at runtime with `format!("AC{}", ...)` etc., never as source literals. Also never put real-looking keys in commit messages.
4. **macOS FSEvents reports canonical `/private/var/...` paths** but tempdirs are `/var/...` symlinks. The Guard canonicalizes watched roots so prefix-matching works. Any new fs-path matching must canonicalize.
5. **CLI signal demos must run envvault in the FOREGROUND.** Backgrounding (`envvault &`) makes the shell set SIGINT=SIG_IGN, which the child inherits, disabling its trap — looks like a bug but isn't. The impl resets child signal dispositions in `pre_exec`. When writing signal tests, also avoid orphaned background `sleep` holding the stdout pipe (use a short-sleep loop instead).
6. **`commit -m` with `⌘K`/special chars breaks zsh.** Write commit messages to a scratchpad file and use `git commit -F file`.
7. **Live-testing overlays:** the user's Mac runs **NotchNest** (blocks clicks in a top-center band) and **Wispr Flow** (blocks bottom-center). Prefer keyboard paths (⌘K palette, `N`, `/`, `Tab`, `Return`) and right-edge clicks. If a click is blocked, use the command palette or keyboard.

## Commands you'll use constantly (always `source "$HOME/.cargo/env"` first)
```bash
cd "/Users/prithvivinay/Desktop/Claude Code/envvault"
cargo test --workspace                                   # all Rust tests
cargo clippy --workspace --all-targets -- -D warnings    # CI-strict lint (grep -v proc-macro-error2)
cargo fmt --all && cargo fmt --all -- --check            # format + verify
bash scripts/check-no-http.sh                            # no-network audit (all 6 targets)
cd crates/envvault-app/ui && npm run build               # bindings + strict tsc + vite
cd crates/envvault-app/ui && npm test                    # vitest
```

### Running the real GUI app for live verification (the ONLY reliable way)
The sandboxed `tauri dev` GUI dies silently and isn't visible to computer-use. Instead:
```bash
cd "/Users/prithvivinay/Desktop/Claude Code/envvault/crates/envvault-app"
./ui/node_modules/.bin/tauri build --debug --bundles app     # ~1-2 min
rm -rf /Applications/EnvVault.app && cp -R ../../target/debug/bundle/macos/EnvVault.app /Applications/EnvVault.app
ENVVAULT_DEV_VAULT_DIR="<scratch>/some-vault-dir" /Applications/EnvVault.app/Contents/MacOS/envvault-app > /dev/null 2>&1 &
```
- Run the launch/copy commands with `dangerouslyDisableSandbox: true` (sandbox kills the GUI).
- `ENVVAULT_DEV_VAULT_DIR` (debug-only env override) points the vault at a scratch dir so you never touch the user's real vault. Use the scratchpad dir.
- computer-use `request_access` needs the **bundle id `dev.envvault.desktop`**, NOT "EnvVault" (name doesn't resolve).
- To seed a vault for demos there are examples: `cargo run -p envvault-cli --example seed-demo-vault -- <vaultdir> <projdir> <password>` and `seed-health-demo`. Write more example seeders as needed (they're dev-only, never shipped).
- Test password used in demos: `glacier otter 42` (or `quartz falcon meadow 88`). The strength meter requires zxcvbn score ≥ 3.

## Crypto design (already implemented — don't redesign)
Vault file = JSON envelope: `wrapped_identity` (X25519 vault identity, scrypt-wrapped under master password, N=2^18), `recipient` (+ optional `recovery_recipient`), `payload` (vault JSON age-encrypted to the identity, and to the recovery recipient if present). age forbids scrypt+other recipients in one file, so recovery is a second X25519 recipient on the payload, not a second recipient on the wrap. Recovery key is a standard `AGE-SECRET-KEY-1…` (decryptable with the stock `age` CLI — proven by test; this is the anti-lock-in property for Phase 9 docs). Debug builds compile crypto crates at opt-level 3 (`[profile.dev.package.*]` in root Cargo.toml) or scrypt takes 18s.

## Git / commit conventions
- Commit after each phase with a detailed multi-line message via `git -c user.name="Prithvi Vinay" -c user.email="vinay.gopinath@gmail.com" commit -F <msgfile>`.
- End messages with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` (match the model you are).
- After committing, watch CI: poll `https://api.github.com/repos/Prithvi-Web/EnvVault/actions/runs?per_page=1` for status/conclusion; read failed-job logs by navigating claude-in-chrome to the job's `html_url` and `get_page_text`. CI runs build+clippy+fmt+test+frontend on ubuntu+macos+windows plus a no-http-crates audit.

## WHAT TO BUILD

### Phase 8 — Secure Share (F8) + Vault Backup & Portability (F9)
Gate: round-trip a shared secrets bundle between two vaults; round-trip an encrypted vault export/import.
- **Secure Share (F8):** Export a selected environment's secrets as a single `age`-encrypted `.age` file, encrypted EITHER to a passphrase (communicated out-of-band) OR to a recipient's `age`/SSH public key (genuinely secure, no shared secret). No server, no link, no upload — the file moves via Signal/AirDrop/USB. Recipient runs `envvault import <file>` (add this CLI subcommand) or imports via the GUI. Bake an **expiry timestamp inside the encrypted payload**; refuse to import an expired bundle. Be honest in docs: expiry is a courtesy guardrail, not cryptographic (someone can change their clock) — say so.
- **Backup & Portability (F9):** One-click "Export encrypted vault" (it's already ciphertext — safe for Dropbox). One-click "Import vault" with a clear **merge vs replace** choice. Document the vault format in the README precisely enough that a user could decrypt it with the standalone `age` CLI + a script, WITHOUT EnvVault. State prominently: "Your data is not hostage. Here is exactly how to get it out." (You already have a passing test proving standalone-age decryption works — reference it.)
- Put all crypto/serialization in core with tests (bundle create/parse, expiry enforcement, merge vs replace, wrong-passphrase, corrupted bundle). Thin commands + GUI in the app. Native file save/open dialogs (tauri-plugin-dialog is already a dep). Verify LIVE: create a bundle from one vault, import into a second vault, show the secrets arrived.

### Phase 9 — Hardening (Section 9, 10.3, 12)
Gate: the full security test-suite output; the performance numbers vs Section 9; a written list of every known limitation.
- **`tests/security.rs` (spec §10.3):** (1) grep the built binary + all app-data/temp dirs after a full workflow → ZERO plaintext secret values; (2) `Cargo.lock`/dep-graph has no HTTP client (already have `scripts/check-no-http.sh`); (3) log a secret deliberately → it appears as `[REDACTED]` (add a `tracing` layer incapable of printing `Secret<T>` if not already present); (4) after `envvault run -- true`, snapshot fs before/after → no `.env` created anywhere; (5) vault file is high-entropy ciphertext with no plaintext project names.
- **Panic hook** that zeroizes the key before the process dies (no decrypted key in a core dump).
- **Performance vs Section 9** (measure, don't guess; report honestly, propose tradeoffs if any miss): cold launch→unlock <400ms; unlock (KDF+decrypt, 100 secrets) <1s; search <16ms; guard idle CPU <0.1% (already measured 0.0%); binary <15MB; idle RSS <80MB (measured ~111MB debug — measure the RELEASE build). Build `--release` for real numbers.
- **Deliverables (Section 12):** `README.md` (install for all 3 OSes, the honest threat model from §4.8 — protects against accidental `git add`, secrets in history/Docker context/backups/stolen laptop at rest; does NOT protect against malware running as your user, compromised deps, or someone who knows your master password — do not overclaim), vault-format decryption doc; `SECURITY.md` (the §4 invariants + how to report a vuln); `LIMITATIONS.md` (everything it doesn't do + everything you're unsure about — e.g. secure-delete on SSD/APFS can't guarantee old blocks are gone, interactive-TTY nuance in the CLI, biometric/Touch-ID unlock is deferred, lock-on-sleep hook deferred). Ensure `cargo clippy -- -D warnings` and `tsc --noEmit` both clean.
- Confirm the **CSP** in `tauri.conf.json` is locked (`default-src 'self'`, no remote `connect-src`) and the About screen states "0 network requests / no networking code" truthfully.

## Deferred items promised honestly at earlier gates (do in Phase 9 or note in LIMITATIONS)
- Touch ID / Windows Hello biometric unlock via OS keychain (`keyring` crate) — was deferred; either implement or document as not-yet.
- Lock-on-system-sleep / screen-lock (macOS platform hook) — auto-lock-on-idle and ⌘L already work.
- Two minor keyboard-polish items: dialogs return focus to body not the originating row; arrow-key row focus doesn't survive a reveal.

## The standard (from the spec, section 14)
"A tool a developer can put their production Stripe key into and sleep soundly." Memory-safe crypto in Rust, a compiler-enforced boundary that can't drift, atomic writes that survive a power cut, tests that PROVE the security invariants rather than asserting them, and total honesty in the docs about what it does not protect against. Build it that way.

First action in the new session: `source "$HOME/.cargo/env"`, `cd` into the project, run `cargo test --workspace` and `git log --oneline -5` to confirm you're at a clean green Phase 7, read the master spec, then begin Phase 8.
