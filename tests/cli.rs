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

#[test]
fn inspect_emits_policy_as_yaml_without_secrets_or_inject_by_default() {
    let pin = "ab".repeat(32);
    let p = write_tmp(
        "inspect_yaml",
        &format!(
            "- name: internal\n  secret: never_print_this\n  inject: 'Authorization: Bearer {{}}'\n  hosts: [internal.example.com]\n  methods: [GET]\n  port: 8443\n  tls_pinned_sha256: '{}'\n",
            pin
        ),
    );
    let out = doormand()
        .args(["inspect", "--config"])
        .arg(&p)
        .arg("--insecure-skip-mode-check")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {}", stderr);
    assert!(stdout.contains("name: internal"), "stdout: {}", stdout);
    assert!(stdout.contains("port: 8443"), "stdout: {}", stdout);
    assert!(stdout.contains(&pin), "stdout: {}", stdout);
    assert!(
        !stdout.contains("never_print_this"),
        "secret leaked: {}",
        stdout
    );
    assert!(
        !stdout.contains("Authorization"),
        "inject leaked: {}",
        stdout
    );
    assert!(
        !stdout.contains("secret:"),
        "secret field emitted: {}",
        stdout
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn inspect_json_is_machine_readable_and_with_inject_is_opt_in() {
    let p = write_tmp(
        "inspect_json",
        "- name: github\n  secret: ghp_never_print_this\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.github.com]\n",
    );
    let out = doormand()
        .args(["inspect", "--config"])
        .arg(&p)
        .args(["--json", "--with-inject", "--insecure-skip-mode-check"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value[0]["name"], "github");
    assert_eq!(value[0]["hosts"][0], "api.github.com");
    assert_eq!(value[0]["methods"], serde_json::json!([]));
    assert_eq!(value[0]["port"], 443);
    assert_eq!(value[0]["tls"], true);
    assert_eq!(value[0]["inject"], "Authorization: Bearer {}");
    let rendered = value.to_string();
    assert!(!rendered.contains("ghp_never_print_this"));
    assert!(value[0].get("secret").is_none());
    std::fs::remove_file(&p).ok();
}

#[test]
fn audit_tail_selects_recent_records_and_projects_safe_fields() {
    let p = write_tmp(
        "audit_tail",
        "{\"ts\":\"one\",\"cred\":\"a\",\"host\":\"a.com\",\"method\":\"GET\",\"status\":200,\"decision\":\"allow\",\"secret\":\"must-not-leak\"}\n\
         {\"ts\":\"two\",\"cred\":\"b\",\"host\":\"b.com\",\"method\":\"POST\",\"status\":403,\"decision\":\"deny\",\"reason\":\"blocked\",\"authorization\":\"Bearer must-not-leak\"}\n",
    );
    let out = doormand()
        .args(["audit", "tail", "-n", "1", "--audit"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"ts\":\"two\""), "stdout: {}", stdout);
    assert!(!stdout.contains("\"ts\":\"one\""), "stdout: {}", stdout);
    assert!(
        !stdout.contains("must-not-leak"),
        "unsafe field leaked: {}",
        stdout
    );
    assert!(
        !stdout.contains("authorization"),
        "unsafe field leaked: {}",
        stdout
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn audit_last_error_returns_most_recent_deny_or_non_2xx() {
    let p = write_tmp(
        "audit_error",
        "{\"ts\":\"one\",\"status\":500,\"decision\":\"allow\",\"reason\":\"upstream\"}\n\
         {\"ts\":\"two\",\"status\":200,\"decision\":\"allow\"}\n\
         {\"ts\":\"three\",\"status\":403,\"decision\":\"deny\",\"reason\":\"policy\"}\n\
         {\"ts\":\"four\",\"status\":204,\"decision\":\"allow\"}\n",
    );
    let out = doormand()
        .args(["audit", "last-error", "--audit"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["ts"], "three");
    assert_eq!(value["reason"], "policy");
    std::fs::remove_file(&p).ok();
}

#[test]
fn list_queries_health_endpoint_and_prints_names_or_json() {
    fn serve_once() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "client closed before completing request headers");
                request.extend_from_slice(&chunk[..n]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /_doorman/health HTTP/1.1"));
            let body = "{\"schema_version\":1,\"ok\":true,\"version\":\"test\",\"credentials\":[\"github\",\"stripe\"]}\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        (address, handle)
    }

    let (address, server) = serve_once();
    let out = doormand()
        .args(["list", "--address", &address.to_string()])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        out.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "github\nstripe\n");

    let (address, server) = serve_once();
    let out = doormand()
        .args(["list", "--address", &address.to_string(), "--json"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        out.status.success(),
        "list --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"credentials": ["github", "stripe"]})
    );
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

#[test]
fn install_service_user_emits_rootless_user_service() {
    let home = std::env::var("HOME").unwrap();
    let out = doormand()
        .args([
            "install-service",
            "--user",
            "--bin-path",
            "/home/example/.local/bin/doormand",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let service = String::from_utf8(out.stdout).unwrap();
    assert!(service.contains("/home/example/.local/bin/doormand"));
    assert!(service.contains(&format!("{}/.config/doorman/doorman.yaml", home)));
    assert!(service.contains(&format!("{}/.local/state/doorman/audit.log", home)));
    assert!(!service.contains("/etc/doorman"));
    assert!(!service.contains("/var/log/doorman"));
    assert!(!service.contains("User=doorman"));
    assert!(!service.contains("<key>UserName</key>"));
}

#[test]
fn sighup_reloads_valid_config_and_keeps_previous_policy_on_invalid_config() {
    let config = write_tmp(
        "reload",
        "- name: before\n  secret: first_secret\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.example.com]\n",
    );
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o400)).unwrap();
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let address = format!("127.0.0.1:{}", port);
    let audit = write_tmp("reload_audit", "");
    let mut child = doormand()
        .args(["run", "--config"])
        .arg(&config)
        .args(["--audit"])
        .arg(&audit)
        .args(["--listen", &address, "--allow-same-uid"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let list_until = |expected: &str| {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let out = doormand()
                .args(["list", "--address", &address, "--json"])
                .output()
                .unwrap();
            if out.status.success() && String::from_utf8_lossy(&out.stdout).contains(expected) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for credential {:?}", expected);
    };

    list_until("before");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        &config,
        "- name: after\n  secret: second_secret\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.example.com]\n",
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o400)).unwrap();
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGHUP) };
    list_until("after");

    // A malformed reload must not replace the working `after` policy.
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&config, "not: [valid").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o400)).unwrap();
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGHUP) };
    std::thread::sleep(Duration::from_millis(100));
    list_until("after");

    let _ = child.kill();
    let _ = child.wait();
    std::fs::remove_file(&config).ok();
    std::fs::remove_file(&audit).ok();
}
