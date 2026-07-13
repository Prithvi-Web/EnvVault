//! The `envvault` CLI: injects vault secrets directly into a child process's
//! environment (spec F5). No `.env` file is ever written — not even a
//! temporary one. The child's stdio is inherited untouched, signals are
//! forwarded, and its exit code is propagated, so `envvault run -- npm run
//! dev` behaves exactly like `npm run dev`.
//!
//! Talks to the vault through `envvault-core` — the identical code the GUI
//! uses. There is exactly one implementation of "decrypt a vault".

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use clap::{Parser, Subcommand};
use envvault_core::secrecy::{ExposeSecret, SecretString};
use envvault_core::{ratelimit, vault, CoreError};

#[derive(Parser)]
#[command(
    name = "envvault",
    version,
    about = "Inject encrypted project secrets into your dev process — no .env files.",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command with this project's secrets in its environment
    ///
    /// Resolves the project by walking up from the current directory.
    /// Defaults to the `development` environment — production is always an
    /// explicit choice.
    Run(RunArgs),

    /// Alias of `run`
    Exec(RunArgs),

    /// Show where the vault lives and whether it exists
    Status,

    /// Print a shell snippet for a cd hint: eval "$(envvault shell-hook)"
    ShellHook,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Environment to inject (e.g. development, staging, production)
    #[arg(long = "env", default_value = "development", value_name = "NAME")]
    env_name: String,

    /// Read the master password (or recovery key) from stdin — for scripts
    #[arg(long)]
    password_stdin: bool,

    /// Suppress the informational line on stderr
    #[arg(short, long)]
    quiet: bool,

    /// The command to run (everything after --)
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Run(args) | Cmd::Exec(args) => cmd_run(args),
        Cmd::Status => cmd_status(),
        Cmd::ShellHook => {
            print!("{}", SHELL_HOOK);
            Ok(0)
        }
    };
    match result {
        Ok(code) => ExitCode::from(code.min(255) as u8),
        Err(message) => {
            eprintln!("envvault: {message}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// run / exec
// ---------------------------------------------------------------------------

fn cmd_run(args: RunArgs) -> Result<u32, String> {
    let vault_path = vault::default_vault_path().map_err(|e| e.to_string())?;
    if !vault_path.exists() {
        return Err(format!(
            "no vault exists yet at {} — open the EnvVault app to create one",
            vault_path.display()
        ));
    }

    let passphrase = read_passphrase(args.password_stdin)?;
    let unlocked =
        ratelimit::unlock_vault_guarded(&vault_path, passphrase).map_err(friendly_unlock_error)?;
    if unlocked.via_recovery {
        eprintln!(
            "envvault: unlocked with the recovery key — set a new master password in the app soon"
        );
    }

    // Resolve the project by walking up from $PWD.
    let cwd = std::env::current_dir().map_err(|e| format!("cannot read current directory: {e}"))?;
    let project = find_project(unlocked.vault(), &cwd).ok_or_else(|| {
        format!(
            "no project registered for {} (or any parent directory) — add it in the EnvVault app",
            cwd.display()
        )
    })?;

    // Environment: exact-then-case-insensitive match. No fuzzy guessing —
    // injecting the wrong environment is the failure mode this tool exists
    // to prevent.
    let environment = project
        .environments
        .iter()
        .find(|e| e.name == args.env_name)
        .or_else(|| {
            project
                .environments
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(&args.env_name))
        })
        .ok_or_else(|| {
            format!(
                "project {} has no environment named {:?} (available: {})",
                project.name,
                args.env_name,
                project
                    .environments
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let pairs: Vec<(String, SecretString)> = environment
        .secrets
        .iter()
        .map(|s| {
            (
                s.key.clone(),
                SecretString::from(s.value.expose().to_string()),
            )
        })
        .collect();

    if !args.quiet {
        let (prefix, suffix) = if std::io::stderr().is_terminal() && environment.is_production {
            ("\x1b[31m", "\x1b[0m") // production is red, even here
        } else {
            ("", "")
        };
        eprintln!(
            "🔓 envvault: {} {prefix}[{}]{suffix} · injecting {} secret{}",
            project.name,
            environment.name,
            pairs.len(),
            if pairs.len() == 1 { "" } else { "s" }
        );
        if environment.is_production {
            eprintln!("{prefix}⚠ envvault: this is PRODUCTION{suffix}");
        }
    }

    let program = args.command.first().ok_or("no command given")?.clone();
    let child_args = &args.command[1..];

    let mut command = Command::new(&program);
    command
        .args(child_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in &pairs {
        command.env(key, value.expose_secret());
    }

    // The child stays in our process group so it remains the terminal's
    // foreground job — interactive dev servers (`npm run dev`'s "press r to
    // reload") keep working, and a real terminal Ctrl-C reaches the whole
    // group at once. But we also reset the child's signal dispositions to
    // default: if envvault was itself started with signals ignored (a
    // background `&` job, or under a supervisor) the child would otherwise
    // inherit SIG_IGN and its own `trap`s would silently never fire.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                libc::signal(sig, libc::SIG_DFL);
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("command not found: {program}")
        } else {
            format!("failed to start {program}: {e}")
        }
    })?;

    // The vault (and every plaintext value it held) is dropped — zeroized —
    // before we settle in to wait on the child.
    drop(unlocked);
    drop(pairs);

    forward_signals(&child);

    let status = child
        .wait()
        .map_err(|e| format!("failed waiting for {program}: {e}"))?;

    Ok(exit_code_of(status))
}

fn read_passphrase(from_stdin: bool) -> Result<SecretString, String> {
    if from_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("could not read password from stdin: {e}"))?;
        let line = buf.lines().next().unwrap_or("").to_string();
        Ok(SecretString::from(line))
    } else {
        let pw = rpassword::prompt_password("EnvVault master password: ")
            .map_err(|e| format!("could not read password: {e}"))?;
        Ok(SecretString::from(pw))
    }
}

fn friendly_unlock_error(e: CoreError) -> String {
    match e {
        CoreError::WrongPassword { attempts_remaining } => match attempts_remaining {
            Some(0) => "wrong password — the vault is now locked for 5 minutes".into(),
            Some(n) => format!("wrong password — {n} attempts left before a 5-minute lockout"),
            None => "wrong password".into(),
        },
        CoreError::RateLimited {
            retry_after_seconds,
        } => format!("too many failed attempts — try again in {retry_after_seconds}s"),
        other => other.to_string(),
    }
}

/// Match the deepest registered project containing `cwd`.
fn find_project<'v>(
    vault: &'v envvault_core::vault::Vault,
    cwd: &Path,
) -> Option<&'v envvault_core::project::Project> {
    let cwd = canonical(cwd);
    let mut best: Option<(&envvault_core::project::Project, usize)> = None;
    for project in &vault.projects {
        let root = canonical(&project.path);
        if cwd.starts_with(&root) {
            let depth = root.components().count();
            if best.is_none_or(|(_, d)| depth > d) {
                best = Some((project, depth));
            }
        }
    }
    best.map(|(p, _)| p)
}

fn canonical(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(unix)]
fn forward_signals(child: &std::process::Child) {
    use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    use signal_hook::iterator::Signals;

    // Forward to the child so it shuts down when envvault is signalled
    // directly — e.g. a supervisor sending SIGTERM to the wrapper. (A real
    // terminal's Ctrl-C already reaches the child via the shared process
    // group; this handler covers the cases where it does not.)
    let child_pid = child.id() as i32;
    if let Ok(mut signals) = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT]) {
        std::thread::spawn(move || {
            for signal in signals.forever() {
                unsafe {
                    libc::kill(child_pid, signal);
                }
            }
        });
    }
}

#[cfg(not(unix))]
fn forward_signals(_child: &std::process::Child) {
    // Windows: Ctrl-C is delivered to the whole console process group by the
    // OS, which includes the child. Nothing to forward manually.
}

#[cfg(unix)]
fn exit_code_of(status: std::process::ExitStatus) -> u32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        code.max(0) as u32
    } else if let Some(signal) = status.signal() {
        // Shell convention: killed by signal N → exit 128+N.
        128 + signal as u32
    } else {
        1
    }
}

#[cfg(not(unix))]
fn exit_code_of(status: std::process::ExitStatus) -> u32 {
    status.code().unwrap_or(1).max(0) as u32
}

// ---------------------------------------------------------------------------
// status / shell-hook
// ---------------------------------------------------------------------------

fn cmd_status() -> Result<u32, String> {
    let vault_path = vault::default_vault_path().map_err(|e| e.to_string())?;
    if vault_path.exists() {
        println!("vault:   {}", vault_path.display());
        println!("state:   created (encrypted at rest; unlocked per-invocation)");
        println!("usage:   envvault run -- <your dev command>");
    } else {
        println!("vault:   {} (not created yet)", vault_path.display());
        println!("usage:   open the EnvVault app to create your vault");
    }
    Ok(0)
}

/// Deliberately shows no project names or secret counts: that information
/// lives inside the encrypted vault, and a cd hint is not worth decrypting
/// for (or worth a plaintext index that would leak your project list). The
/// hint keys off the safe artifacts Import & Secure leaves behind.
const SHELL_HOOK: &str = r#"# EnvVault shell hook — install with:  eval "$(envvault shell-hook)"
_envvault_cd_hint() {
  if [ -f .env.example ] && [ ! -f .env ]; then
    printf '🔐 envvault: this project'"'"'s secrets are managed — run: envvault run -- <cmd>\n'
  fi
}
if [ -n "$ZSH_VERSION" ]; then
  autoload -Uz add-zsh-hook
  add-zsh-hook chpwd _envvault_cd_hint
elif [ -n "$BASH_VERSION" ]; then
  _envvault_prev_pwd="$PWD"
  _envvault_prompt() {
    if [ "$PWD" != "$_envvault_prev_pwd" ]; then
      _envvault_prev_pwd="$PWD"
      _envvault_cd_hint
    fi
  }
  case "$PROMPT_COMMAND" in
    *_envvault_prompt*) ;;
    *) PROMPT_COMMAND="_envvault_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}" ;;
  esac
fi
"#;
