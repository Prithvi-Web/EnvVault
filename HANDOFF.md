# EnvVault — Session Handoff Prompt

> Paste everything below (from the horizontal rule down) as your first message to Claude in the next session.

---

You are picking up **EnvVault**, a fully-local, zero-cloud desktop secrets manager for developers (Tauri v2 + Rust + React). It was built across multiple sessions in phase gates. **ALL PHASES 0–9 ARE DONE AND COMMITTED — the phased build per the master prompt is COMPLETE.** There is no "next phase." Any further work is new: bug fixes, follow-ups the user names, or polishing deferred items (see the LIMITATIONS list). The bar the user set, verbatim: **"completely flawless, absolutely 0 errors."** Hold to it.

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

## Current state (as of end of Phase 9 — project complete)
- Git: `main` branch, latest commit `Phase 9: hardening — security suite, panic wipe, perf, docs` (`ba85405`). Committed locally; the user pushes via GitHub Desktop. Verify CI went green after they push.
- Toolchain: Rust installed via rustup — **every bash shell must start with `source "$HOME/.cargo/env"`** or cargo isn't found. Node/npm already present.
- **18 Rust test suites / 169 tests + 10 frontend (vitest) tests, all green. Zero clippy warnings under `-D warnings`. Zero tsc errors (strict + noUncheckedIndexedAccess). no-http audit green on all 6 targets. envvault-core line coverage 90.1% (`cargo llvm-cov -p envvault-core`).**
- Phase 9 shipped: `tests/security.rs` (§10.3 — no plaintext on disk after a full workflow, vault-file entropy + no plaintext names, redaction incl. compile-time `static_assertions` no-Display proofs) + CLI `run_writes_no_file_anywhere`; a panic hook (`state.rs::wipe_secrets_for_panic`) that zeroizes the session before a release-abort; About screen stating "0 network requests" truthfully; ⌘K no longer opens over a modal; local-date backup filename; `ENVVAULT_PERF` launch instrumentation; README/SECURITY.md/LIMITATIONS.md/PERFORMANCE.md. Perf vs §9 all pass except cold-launch (~475ms to interactive vs 400ms target — WKWebView warmup, honestly documented) and idle RSS (~94MB RSS / ~24MB private — RSS overcounts shared WebKit pages; documented).
- Phase 8 (context): core `share` module (bundles are PLAIN armored age files decryptable with the stock age CLI; passphrase XOR age/SSH recipient keys; expiry inside the ciphertext, re-checked at confirm), `envvault import` CLI subcommand, vault portability (`export_vault_copy`, `replace_vault_file`, `Vault::merge_from`, `update_vault_try`), rate-limited `unwrap_vault_identity_guarded` + `update_vault_guarded`, GUI dialogs (Share, ImportBundle, VaultBackup, ShareKey) + palette actions. A user's share key = their vault's X25519 public key. The `age` crate has the "ssh" feature.

## CRITICAL live-testing gotcha discovered in Phase 9 (internalize this)
**The RELEASE binary IGNORES `ENVVAULT_DEV_VAULT_DIR`** — that override is `#[cfg(debug_assertions)]`-only by design (users must not be able to relocate their vault into a repo). So a release app launched with that env var reads the USER'S REAL VAULT at `~/Library/Application Support/EnvVault/vault.age`. In Phase 9 this caused test-password attempts to register as failures against the real vault (its throttle counter was created and had to be cleaned up). **For any live GUI verification against a scratch vault, ALWAYS build/run a DEBUG bundle (`tauri build --debug`), never release.** Use release ONLY for perf/size measurement and only at the locked screen (never type a password into it). Never attempt to unlock the user's real vault; if you ever create a throttle file at the real path from testing, `rm` it so they aren't locked out.

## Deferred items (documented honestly in LIMITATIONS.md — future work if the user asks)
- Touch ID / Windows Hello biometric unlock (keyring crate) — not implemented.
- Lock-on-system-sleep / screen-lock hook — auto-lock-on-idle + ⌘L work; instant lock on lid-close does not.
- Esc doesn't close Radix dialogs in this WKWebView (every dialog has a button); focus returns to body not the originating row; arrow-key row focus doesn't survive a reveal.
- `envvault import` decrypts passphrase + vault-share-key bundles, NOT SSH-key bundles (those are for the stock age CLI).
- No signed installers; macOS bundles are ad-hoc signed.

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
7. **Live-testing overlays:** the user's Mac runs **NotchNest** (blocks clicks in a top-center band) and **Wispr Flow** (blocks bottom-center — extends surprisingly high, ~y 560–850 in the 1372px-wide screenshot space). Prefer keyboard paths (⌘K palette, `N`, `/`, `Tab`, `Return`) and right-edge clicks. If a click is blocked, use the command palette or keyboard.
8. **Native save/open panels are OUT-OF-PROCESS** (`openAndSavePanelService`) — sometimes invisible to computer-use screenshots even when open. Drive them blind: `cmd+shift+g` → `cmd+a` → type the full path (ALWAYS cmd+a first; the go-to field remembers old text) → `Return` (navigate) → `Return` (confirm), then verify the file on disk. Save panels needed `dialog:allow-save` in `capabilities/default.json` (added in Phase 8 — `open` alone was granted before, and a missing capability makes the JS promise reject SILENTLY).
9. **Palette rows shift as actions appear/disappear** (e.g. "Share <env>" hides when the env is empty) — never click a palette row by remembered position; type-to-filter then Return.
10. **Escape does not reliably close Radix dialogs in this WKWebView** — dismiss via the dialog's own buttons (Tab + Return). Also, opening the ⌘K palette on top of an open Radix dialog fights its focus trap: palette input never focuses and outside-clicks are swallowed. Close the dialog first. (Candidate Phase 9 polish: palette shouldn't open over a modal, and Escape handling.)
11. **Waiting for unlock in GUI automation:** unlock takes ~1s of scrypt; a batched click 2s after Return can race the transition. Screenshot to confirm the unlocked toolbar before clicking things on it.

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

## WHAT'S LEFT
The phased build is finished — all 10 gates (0–9) are met. The deliverables in spec §12 exist: full source building clean on all 3 OSes with zero warnings, README + SECURITY.md + LIMITATIONS.md + PERFORMANCE.md, the passing test suite with coverage reported. There is no remaining phase work.

If the user asks for more, it's one of: a bug they hit, a deferred item they want built (biometric unlock, lock-on-sleep, the keyboard-focus polish, signed installers — all in the CRITICAL/deferred sections above and in LIMITATIONS.md), or a new feature. Treat it as fresh work: brainstorm/plan first if it's non-trivial, keep all logic in `envvault-core` with tests, run the full verification, and do a LIVE **debug-build** demo before claiming it works.

## The standard (from the spec, section 14)
"A tool a developer can put their production Stripe key into and sleep soundly." Memory-safe crypto in Rust, a compiler-enforced boundary that can't drift, atomic writes that survive a power cut, tests that PROVE the security invariants rather than asserting them, and total honesty in the docs about what it does not protect against. That standard is met; keep it met.

First action in a new session: `source "$HOME/.cargo/env"`, `cd` into the project, run `cargo test --workspace` and `git log --oneline -5` to confirm you're at a clean green Phase 9 (`ba85405`), then address whatever the user actually asks for.
