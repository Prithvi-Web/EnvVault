//! CLI integration suite (spec F5 gate): injection correctness, environment
//! selection, exit-code propagation, signal forwarding, project resolution.
//! Every test spawns the real `envvault` binary against a real vault.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use envvault_core::secrecy::SecretString;
use envvault_core::secret::SecretValue;
use envvault_core::vault::create_vault_with_work_factor;

const PASSWORD: &str = "cli-suite-password";

struct Fixture {
    /// Holds the tempdir alive.
    _dir: tempfile::TempDir,
    vault_dir: PathBuf,
    project_dir: PathBuf,
}

/// A vault (low work factor) with one project: dev has API_KEY/SHARED,
/// production has SHARED with a different value.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("vaultdir");
    let project_dir = dir.path().join("myproj");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(project_dir.join("sub/deeper")).unwrap();

    let created = create_vault_with_work_factor(
        &vault_dir.join("vault.age"),
        SecretString::from(PASSWORD.to_owned()),
        false,
        10,
    )
    .unwrap();
    let mut unlocked = created.unlocked;
    let pid = unlocked
        .vault_mut()
        .add_project("myproj".into(), project_dir.clone())
        .unwrap();
    let (dev, prod) = {
        let p = unlocked.vault().project(pid).unwrap();
        (p.environments[0].id, p.environments[1].id)
    };
    let v = unlocked.vault_mut();
    v.add_secret(
        pid,
        dev,
        "API_KEY".into(),
        SecretValue::new("dev-key-123".into()),
        None,
    )
    .unwrap();
    v.add_secret(
        pid,
        dev,
        "SHARED".into(),
        SecretValue::new("from-development".into()),
        None,
    )
    .unwrap();
    v.add_secret(
        pid,
        prod,
        "SHARED".into(),
        SecretValue::new("from-production".into()),
        None,
    )
    .unwrap();
    unlocked.save().unwrap();

    Fixture {
        _dir: dir,
        vault_dir,
        project_dir,
    }
}

/// Run `envvault` with the password piped on stdin.
fn envvault(fixture: &Fixture, cwd: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(args)
        .current_dir(cwd)
        .env("ENVVAULT_DEV_VAULT_DIR", &fixture.vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn envvault");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .expect("write password");
    child.wait_with_output().expect("wait")
}

#[test]
fn injects_secrets_into_child_environment() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &[
            "run",
            "--password-stdin",
            "--",
            "sh",
            "-c",
            "printf %s \"$API_KEY\"",
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "dev-key-123");
}

#[test]
fn stdout_is_untouched_and_info_goes_to_stderr() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &["run", "--password-stdin", "--", "echo", "hi"],
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hi\n",
        "stdout must be exactly the child's"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("myproj"),
        "info line names the project: {stderr}"
    );
    assert!(stderr.contains("[development]"));
    assert!(stderr.contains("2 secrets"));
}

#[test]
fn quiet_silences_the_info_line() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &["run", "--password-stdin", "--quiet", "--", "true"],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
}

#[test]
fn defaults_to_development_never_production() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &[
            "run",
            "--password-stdin",
            "--",
            "sh",
            "-c",
            "printf %s \"$SHARED\"",
        ],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from-development");
}

#[test]
fn production_requires_the_explicit_flag_and_warns() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &[
            "run",
            "--password-stdin",
            "--env",
            "production",
            "--",
            "sh",
            "-c",
            "printf %s \"$SHARED\"",
        ],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "from-production");
    assert!(String::from_utf8_lossy(&out.stderr).contains("PRODUCTION"));
}

#[test]
fn unknown_environment_fails_closed_listing_options() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &["run", "--password-stdin", "--env", "staging", "--", "true"],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("staging"));
    assert!(stderr.contains("development, production"));
}

#[test]
fn resolves_project_from_a_subdirectory() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir.join("sub/deeper"),
        &[
            "run",
            "--password-stdin",
            "--",
            "sh",
            "-c",
            "printf %s \"$API_KEY\"",
        ],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "dev-key-123");
}

#[test]
fn unregistered_directory_is_a_clear_error() {
    let f = fixture();
    let elsewhere = f.vault_dir.clone(); // any dir that is not the project
    let out = envvault(&f, &elsewhere, &["run", "--password-stdin", "--", "true"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no project registered"));
}

#[test]
fn child_exit_code_is_propagated() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &["run", "--password-stdin", "--", "sh", "-c", "exit 42"],
    );
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn missing_command_is_exit_127_style_error() {
    let f = fixture();
    let out = envvault(
        &f,
        &f.project_dir,
        &[
            "run",
            "--password-stdin",
            "--",
            "definitely-not-a-real-command-xyz",
        ],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("command not found"));
}

#[test]
fn wrong_password_is_rejected_without_running_the_command() {
    let f = fixture();
    let mut child = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["run", "--password-stdin", "--", "sh", "-c", "echo RAN"])
        .current_dir(&f.project_dir)
        .env("ENVVAULT_DEV_VAULT_DIR", &f.vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"not the password\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(!out.status.success());
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("RAN"),
        "child must never start"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong password"));
}

/// Ctrl-C behavior (spec: "a wrapper that breaks Ctrl-C is a wrapper nobody
/// uses"): SIGINT to the wrapper is forwarded to the child, the child's trap
/// runs, and its exit code comes back through the wrapper.
/// Terminal-faithful Ctrl-C: a real terminal delivers SIGINT to the entire
/// foreground process group. We reproduce that by launching envvault as its
/// own group leader and signalling the group — so envvault, the shell, and
/// the shell's own `sleep` grandchild all receive SIGINT at once. The child's
/// trap must run promptly and its exit code must propagate through envvault.
#[cfg(unix)]
#[test]
fn terminal_ctrl_c_stops_the_child_promptly() {
    use std::os::unix::process::CommandExt;

    let f = fixture();
    let started = std::time::Instant::now();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_envvault"));
    cmd.args([
        "run",
        "--password-stdin",
        "--",
        // A foreground short-sleep loop models a well-behaved dev server:
        // it exits promptly on the trap and leaves no pipe-holding orphan.
        "sh",
        "-c",
        "trap 'echo TRAPPED; exit 7' INT; echo READY; while :; do sleep 0.1; done",
    ])
    .current_dir(&f.project_dir)
    .env("ENVVAULT_DEV_VAULT_DIR", &f.vault_dir)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // Envvault leads its own group; -pid then targets that whole group, the
    // way a controlling terminal signals its foreground job.
    cmd.process_group(0);
    let mut child = cmd.spawn().unwrap();
    let pgid = child.id();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(1500));
    unsafe {
        libc::kill(-(pgid as i32), libc::SIGINT);
    }

    let out = child.wait_with_output().unwrap();
    let elapsed = started.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TRAPPED"),
        "child's INT trap must run; got: {stdout}"
    );
    assert_eq!(out.status.code(), Some(7), "trap exit code must propagate");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "took {elapsed:?} — the grandchild was not interrupted"
    );
}

/// Supervisor case: a process manager (systemd, docker stop, …) sends SIGTERM
/// to envvault ALONE. Envvault must forward it to the child so the child
/// shuts down, and propagate the child's exit code.
#[cfg(unix)]
#[test]
fn sigterm_to_wrapper_is_forwarded_to_child() {
    let f = fixture();
    let mut child = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args([
            "run",
            "--password-stdin",
            "--",
            // A short-sleep loop so the TERM trap is serviced promptly and no
            // long-lived grandchild holds the stdout pipe open.
            "sh",
            "-c",
            "trap 'echo TERMED; exit 9' TERM; echo READY; while :; do sleep 0.1; done",
        ])
        .current_dir(&f.project_dir)
        .env("ENVVAULT_DEV_VAULT_DIR", &f.vault_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // SIGTERM to the wrapper's PID only — not the group.
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("TERMED"),
        "child TERM trap must run"
    );
    assert_eq!(out.status.code(), Some(9), "child exit code must propagate");
}

#[test]
fn status_reports_vault_location() {
    let f = fixture();
    let out = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .arg("status")
        .env("ENVVAULT_DEV_VAULT_DIR", &f.vault_dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("vault.age"));
    assert!(stdout.contains("created"));
}

#[test]
fn shell_hook_emits_posix_sh() {
    let out = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .arg("shell-hook")
        .output()
        .unwrap();
    let hook = String::from_utf8_lossy(&out.stdout);
    assert!(hook.contains("_envvault_cd_hint"));
    // The snippet itself must be valid sh.
    let check = Command::new("sh")
        .args(["-n"])
        .stdin(Stdio::piped())
        .spawn();
    if let Ok(mut c) = check {
        c.stdin.take().unwrap().write_all(hook.as_bytes()).unwrap();
        assert!(c.wait().unwrap().success(), "shell-hook must be valid sh");
    }
}
