// CLI-level tests for the `validate-config` subcommand. They run the compiled
// `doormand` binary against temp config files and assert on exit status and
// output. The security-relevant property — that a secret value never appears
// in the command's output — gets its own assertion.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn doormand() -> Command {
    Command::new(env!("CARGO_BIN_EXE_doormand"))
}

fn write_tmp(label: &str, contents: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let i = N.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!(
        "doorman_cli_{}_{}_{}.yaml",
        std::process::id(),
        i,
        label
    ));
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    p
}

#[test]
fn validate_config_accepts_valid_lists_names_and_hides_secrets() {
    let p = write_tmp(
        "valid",
        "- name: github\n  secret: ghp_supersecret\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.github.com]\n\
         - name: stripe\n  secret: sk_live_dontleak\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.stripe.com]\n  methods: [GET]\n",
    );
    let out = doormand()
        .args(["validate-config", "--config"])
        .arg(&p)
        .arg("--insecure-skip-mode-check")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "expected success, got {:?}\nstdout: {}\nstderr: {}",
        out.status,
        stdout,
        stderr
    );
    assert!(stdout.contains("2 credentials"), "stdout: {}", stdout);
    assert!(stdout.contains("github"), "stdout: {}", stdout);
    assert!(stdout.contains("stripe"), "stdout: {}", stdout);
    // The whole point of names-only output: secrets must never be printed.
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        !combined.contains("ghp_supersecret"),
        "secret leaked: {}",
        combined
    );
    assert!(
        !combined.contains("sk_live_dontleak"),
        "secret leaked: {}",
        combined
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn validate_config_rejects_invalid_with_nonzero_exit() {
    // Two `{}` slots in the inject template — rejected by config::load.
    let p = write_tmp(
        "invalid",
        "- name: bad\n  secret: x\n  inject: 'X: {} {}'\n  hosts: [a.com]\n",
    );
    let out = doormand()
        .args(["validate-config", "--config"])
        .arg(&p)
        .arg("--insecure-skip-mode-check")
        .output()
        .unwrap();
    assert!(!out.status.success(), "expected failure for invalid config");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("slot"),
        "expected a useful error about the inject slot, got: {}",
        stderr
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn validate_config_enforces_mode_0400_unless_flag_given() {
    // A world-readable (0644) config is rejected without the skip flag, the
    // same gate `run` applies.
    let p = write_tmp(
        "mode",
        "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n",
    );
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = doormand()
        .args(["validate-config", "--config"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a 0644 config must be rejected without --insecure-skip-mode-check"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("0400"),
        "expected a mode-0400 error, got: {}",
        stderr
    );
    std::fs::remove_file(&p).ok();
}

/// Boot `doormand run` on `--listen 127.0.0.1:0` (the kernel picks a free
/// port; the test never needs to know which one, since it only reads
/// stderr), wait for its startup diagnostics to appear, then kill it and
/// return whatever stderr was captured. `extra` lets a caller add flags such
/// as `--allow-same-uid`.
///
/// Reads stderr on a background thread so the main thread can apply an
/// overall deadline instead of guessing a fixed sleep: too short and a slow
/// CI runner misses the diagnostics, too long and every test run pays for
/// the worst case. Stops as soon as the posture-warning or "listening" line
/// appears (whichever comes first), or the deadline passes.
fn run_and_capture_stderr(config: &std::path::Path, extra: &[&str]) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let i = N.fetch_add(1, Ordering::Relaxed);
    let audit =
        std::env::temp_dir().join(format!("doorman_cli_run_{}_{}.log", std::process::id(), i));
    let mut cmd = doormand();
    cmd.args(["run", "--config"])
        .arg(config)
        .args(["--audit"])
        .arg(&audit)
        .args(["--listen", "127.0.0.1:0"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match stderr_pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if tx.send(String::from_utf8_lossy(&buf).into_owned()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut captured = String::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(s) => {
                captured = s;
                if captured.contains("SECURITY") || captured.contains("listening on") {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    // Drain anything already buffered before the process actually dies.
    while let Ok(s) = rx.recv_timeout(Duration::from_millis(50)) {
        captured = s;
    }
    let _ = child.wait();
    std::fs::remove_file(&audit).ok();
    captured
}

#[test]
fn run_warns_about_same_uid_exposure_and_flag_silences_it() {
    // The posture warning keys off the login-uid range; a service account
    // (or root) is the separated, safe posture and is intentionally not
    // flagged, so skip the assertion there rather than fail spuriously.
    let euid = unsafe { libc::geteuid() };
    let login_floor: u32 = if cfg!(target_os = "macos") { 500 } else { 1000 };
    if euid == 0 || euid < login_floor {
        return;
    }
    let p = write_tmp(
        "run_uid",
        "- name: github\n  secret: ghp_x\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.github.com]\n",
    );
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();

    let warned = run_and_capture_stderr(&p, &[]);
    assert!(
        warned.contains("SECURITY") && warned.contains("issues/39"),
        "expected a same-UID posture warning, got: {}",
        warned
    );

    let silenced = run_and_capture_stderr(&p, &["--allow-same-uid"]);
    assert!(
        !silenced.contains("SECURITY"),
        "--allow-same-uid should suppress the warning, got: {}",
        silenced
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn install_service_emits_explicit_config_and_audit_paths() {
    // The emitted service definition (systemd unit on Linux, launchd plist on
    // macOS) must invoke `run` with explicit --config/--audit rather than the
    // bare `run` that left operators guessing (#10). The check is the same on
    // both platforms because both templates embed these literals.
    let out = doormand()
        .args(["install-service", "--bin-path", "/usr/local/bin/doormand"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "install-service failed: {:?}",
        out.status
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("/usr/local/bin/doormand"),
        "bin path missing:\n{}",
        s
    );
    assert!(s.contains("--config"), "missing --config:\n{}", s);
    assert!(
        s.contains("/etc/doorman/doorman.yaml"),
        "missing config path:\n{}",
        s
    );
    assert!(s.contains("--audit"), "missing --audit:\n{}", s);
    assert!(
        s.contains("/var/log/doorman/audit.log"),
        "missing audit path:\n{}",
        s
    );
}
