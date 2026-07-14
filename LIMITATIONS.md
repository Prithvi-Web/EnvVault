# Limitations

Everything EnvVault does **not** do, plus everything we are honestly unsure
about. Overclaiming in a security product is a bug; treat this file as part
of the product.

## Out of scope by design (the threat model's other side)

- **Malware running as your user wins.** A keylogger reads your master
  password; a debugger reads decrypted memory; a malicious process can read
  the clipboard during the 30-second copy window. No local secrets manager
  survives a compromised account, and EnvVault does not claim to.
- **A compromised dependency of *your* app receives your secrets.** `envvault
  run -- npm run dev` hands the child process its environment — that is the
  entire point. Anything that child loads (including a hostile npm package)
  can read its own environment.
- **Someone who knows your master password has your secrets.** There is no
  second factor. Conversely, if you lose the password *and* the recovery
  key, the secrets are gone permanently — that is the point, not a flaw.
- **A stolen vault file is protected only by your password.** scrypt at
  N=2^18 makes guessing expensive, not impossible. A weak master password
  falls to offline brute force; the strength meter's minimum exists for
  this reason.

## Known gaps and honest uncertainties

- **Secure deletion of imported `.env` files is best-effort.** Import &
  Secure overwrites the bytes before unlinking, but on APFS/SSDs (copy-on-
  write, wear leveling, snapshots) the old blocks may survive the
  overwrite. Time Machine or other backup tools may also hold pre-import
  copies of your old `.env`. The parked recovery copy EnvVault itself keeps
  for 7 days lives outside the repo but is a plaintext copy — deliberately,
  so a panicked user can recover; it is shredded after 7 days.
- **Rotation is on you.** When the git-history scan says a secret was
  exposed, EnvVault links the provider's rotation page — but it cannot
  rotate the credential or rewrite git history for you.
- **Memory is not locked.** Decrypted secrets are zeroized on drop, but the
  pages holding them are not `mlock`ed, so the OS could in principle swap
  them out (macOS encrypts swap by default; other OSes vary). We have not
  verified zeroization survives every compiler optimization on every
  platform — `zeroize` is designed to, and we rely on that.
- **The panic wipe is best-effort.** The hook takes locks with `try_lock`
  so it can never deadlock; if the panicking thread itself held the session
  lock, that wipe is skipped and the process aborts with secrets still in
  memory. macOS does not write core dumps by default, so the practical
  exposure is a machine already configured for kernel-level debugging.
- **Clipboard guarantees end at the clipboard.** Auto-clear fires after 30
  seconds and macOS clipboard managers honoring `ConcealedType` skip the
  value — but a paste target keeps what you pasted, a clipboard manager
  that ignores the marker keeps a copy, and macOS Universal Clipboard may
  sync it to your other devices before the clear.
- **Share-bundle expiry is a courtesy guardrail.** It is enforced on
  import, inside the ciphertext — but a recipient who kept the file can set
  their clock back. Real revocation is rotating the shared secrets.
- **The Guard runs only while the app runs.** It is a filesystem watcher,
  not a kernel hook: a `.env` created and committed in the seconds before a
  notification fires can still reach git. It also skips heavy directories
  (`node_modules`, `.git`, `target`, …) by design, and the
  secret-appeared-in-a-file check silently pauses while the vault is
  locked.
- **Biometric unlock is not implemented.** Touch ID / Windows Hello via the
  OS keychain was planned and deferred; unlocking is master password (or
  recovery key) only.
- **No lock-on-system-sleep hook.** Idle auto-lock (default 10 minutes) and
  ⌘L cover most of it, but the vault does not currently lock the instant
  the lid closes or the screen locks. Quitting the app locks by
  definition (the process — and every decrypted byte — is gone).
- **`envvault import` does not decrypt SSH-key bundles.** Bundles encrypted
  to your EnvVault share key or a passphrase import natively; a bundle
  encrypted to your SSH public key is for the stock `age` CLI
  (`age -d -i ~/.ssh/id_ed25519 bundle.age`).
- **The CLI needs a terminal for its password prompt.** In scripts or CI,
  use `--password-stdin`; there is no keychain integration yet.
- **No signed installers yet.** Building from source is the supported
  install; macOS bundles are ad-hoc signed, so Gatekeeper on another Mac
  will warn. Windows/Linux packaging is compiled but not release-tested.
- **One vault per machine, schema v1.** No profiles or multiple vaults. A
  vault from a *newer* EnvVault is refused with a clear message rather than
  misread; older vaults are migrated forward automatically (the migration
  harness exists and is tested from day one).
- **Minor UI nuances.** Esc-to-close is inconsistent in the macOS webview —
  every dialog has an explicit close button. After closing a dialog, focus
  returns to the page body rather than the originating row, and arrow-key
  row focus does not survive a reveal.
