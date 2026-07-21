// CLI-level tests for the `validate-config` subcommand. They run the compiled
// `doormand` binary against temp config files and assert on exit status and
// output. The security-relevant property — that a secret value never appears
// in the command's output — gets its own assertion.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{CertificateParams, DistinguishedName, DnType, Ia5String, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
    assert!(!combined.contains("ghp_supersecret"), "secret leaked: {}", combined);
    assert!(!combined.contains("sk_live_dontleak"), "secret leaked: {}", combined);
    std::fs::remove_file(&p).ok();
}

#[test]
fn validate_config_uses_singular_wording_for_one_credential() {
    let p = write_tmp(
        "single",
        "- name: github\n  secret: ghp_x\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.github.com]\n",
    );
    let out = doormand()
        .args(["validate-config", "--config"])
        .arg(&p)
        .arg("--insecure-skip-mode-check")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1 credential)"), "expected singular wording, stdout: {}", stdout);
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
    assert!(stderr.contains("0400"), "expected a mode-0400 error, got: {}", stderr);
    std::fs::remove_file(&p).ok();
}

/// Boot `doormand run` on a throwaway port, block until it has printed its
/// "listening" line (so the SIGTERM handler is guaranteed registered), send
/// SIGTERM so it takes its own graceful-shutdown path, and return its full
/// stderr plus the audit log path used. `extra` lets a caller add flags such
/// as `--allow-same-uid`.
fn run_and_capture_stderr(config: &std::path::Path, port: u16, extra: &[&str]) -> (String, PathBuf) {
    let audit = std::env::temp_dir().join(format!("doorman_cli_run_{}_{}.log", std::process::id(), port));
    let mut cmd = doormand();
    cmd.args(["run", "--config"])
        .arg(config)
        .args(["--audit"])
        .arg(&audit)
        .args(["--listen", &format!("127.0.0.1:{}", port)])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();

    // Read stderr on a background thread into a shared buffer, so the main
    // thread can poll for the "listening" line without risking a pipe-buffer
    // deadlock. Seeing that line is also the guarantee that the SIGTERM
    // handler is registered: both are set up concurrently, before the daemon
    // blocks on the accept loop.
    let mut stderr_pipe = child.stderr.take().unwrap();
    let buf = Arc::new(std::sync::Mutex::new(String::new()));
    let buf_for_reader = Arc::clone(&buf);
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match stderr_pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf_for_reader
                    .lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&chunk[..n])),
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if buf.lock().unwrap().contains("listening on") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let _ = reader.join();
    let stderr = buf.lock().unwrap().clone();

    // Poll for graceful exit; fall back to SIGKILL if it doesn't shut down.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    (stderr, audit)
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

    let (warned, warned_audit) = run_and_capture_stderr(&p, 18991, &[]);
    assert!(
        warned.contains("SECURITY") && warned.contains("issues/39"),
        "expected a same-UID posture warning, got: {}",
        warned
    );
    std::fs::remove_file(&warned_audit).ok();

    let (silenced, silenced_audit) = run_and_capture_stderr(&p, 18992, &["--allow-same-uid"]);
    std::fs::remove_file(&silenced_audit).ok();
    assert!(
        !silenced.contains("SECURITY"),
        "--allow-same-uid should suppress the warning, got: {}",
        silenced
    );
    std::fs::remove_file(&p).ok();
}

#[test]
fn run_binds_writes_audit_config_load_and_shuts_down_on_sigterm() {
    // Exercises `cmd_run`'s success path end to end — independent of euid,
    // unlike the posture-warning test above — including the best-effort
    // config_load audit record and the graceful SIGTERM branch.
    let p = write_tmp(
        "run_happy",
        "- name: github\n  secret: ghp_x\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.github.com]\n",
    );
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();

    let (stderr, audit_path) = run_and_capture_stderr(&p, 18993, &["--allow-same-uid"]);
    assert!(
        stderr.contains("listening on") && stderr.contains("SIGTERM, shutting down"),
        "expected a clean startup and graceful shutdown, got: {}",
        stderr
    );

    let audit_contents = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        audit_contents.contains("config_load") && audit_contents.contains("github"),
        "expected a config_load audit record naming the credential, got: {}",
        audit_contents
    );
    std::fs::remove_file(&audit_path).ok();
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
    assert!(out.status.success(), "install-service failed: {:?}", out.status);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("/usr/local/bin/doormand"), "bin path missing:\n{}", s);
    assert!(s.contains("--config"), "missing --config:\n{}", s);
    assert!(s.contains("/etc/doorman/doorman.yaml"), "missing config path:\n{}", s);
    assert!(s.contains("--audit"), "missing --audit:\n{}", s);
    assert!(s.contains("/var/log/doorman/audit.log"), "missing audit path:\n{}", s);
}

#[test]
fn install_service_rejects_unknown_flag() {
    let out = doormand()
        .args(["install-service", "--nope"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown flag"), "stderr: {}", stderr);
}

#[test]
fn install_service_rejects_missing_bin_path_value() {
    let out = doormand()
        .args(["install-service", "--bin-path"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing value"), "stderr: {}", stderr);
}

#[test]
fn no_subcommand_prints_usage_and_succeeds() {
    let out = doormand().output().unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage:"), "stderr: {}", stderr);
}

#[test]
fn help_flags_print_usage_and_succeed() {
    for flag in ["-h", "--help"] {
        let out = doormand().arg(flag).output().unwrap();
        assert!(out.status.success(), "flag {} failed", flag);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("usage:"), "flag {}: stderr: {}", flag, stderr);
    }
}

#[test]
fn unknown_subcommand_prints_usage_and_fails() {
    let out = doormand().arg("bogus").output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown subcommand"), "stderr: {}", stderr);
    assert!(stderr.contains("usage:"), "stderr: {}", stderr);
}

#[test]
fn validate_config_rejects_unknown_flag() {
    let p = write_tmp("bad_flag", "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n");
    let out = doormand()
        .args(["validate-config", "--config"])
        .arg(&p)
        .arg("--insecure-skip-mode-check")
        .arg("--nope")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown flag"), "stderr: {}", stderr);
    std::fs::remove_file(&p).ok();
}

#[test]
fn validate_config_rejects_missing_config_value() {
    let out = doormand()
        .args(["validate-config", "--config"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing value"), "stderr: {}", stderr);
}

#[test]
fn run_rejects_unknown_flag() {
    let out = doormand().args(["run", "--nope"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown flag"), "stderr: {}", stderr);
}

#[test]
fn run_rejects_invalid_listen_value() {
    let p = write_tmp("run_bad_listen", "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
    let out = doormand()
        .args(["run", "--config"])
        .arg(&p)
        .args(["--listen", "not-an-addr"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--listen"), "stderr: {}", stderr);
    std::fs::remove_file(&p).ok();
}

#[test]
fn run_rejects_missing_flag_values() {
    for flag in ["--config", "--audit", "--listen"] {
        let out = doormand().args(["run", flag]).output().unwrap();
        assert!(!out.status.success(), "flag {} should require a value", flag);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("missing value"), "flag {}: stderr: {}", flag, stderr);
    }
}

#[test]
fn run_rejects_nonexistent_config_file() {
    let missing = std::env::temp_dir().join(format!("doorman_cli_missing_{}.yaml", std::process::id()));
    let out = doormand()
        .args(["run", "--config"])
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn fingerprint_rejects_missing_target() {
    let out = doormand().arg("fingerprint").output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing"), "stderr: {}", stderr);
}

#[test]
fn fingerprint_rejects_extra_arg() {
    let out = doormand()
        .args(["fingerprint", "example.com:443", "extra"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unexpected extra arg"), "stderr: {}", stderr);
}

#[test]
fn fingerprint_rejects_invalid_port() {
    let out = doormand()
        .args(["fingerprint", "example.com:notaport"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid port"), "stderr: {}", stderr);
}

#[test]
fn fingerprint_reports_dial_error_for_unreachable_host() {
    // Port 0 on loopback never accepts a connection, so this exercises the
    // dial-failure path without needing network access.
    let out = doormand()
        .args(["fingerprint", "127.0.0.1:1"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("dial"), "stderr: {}", stderr);
}

/// Spin up a bare TLS listener that accepts exactly one connection with a
/// throwaway self-signed leaf cert, matching what `fingerprint` is designed
/// to probe: it accepts any certificate and just reports the leaf's digest.
async fn spawn_one_shot_tls_server() -> (SocketAddr, [u8; 32]) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from("127.0.0.1".to_string()).unwrap())];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let digest = doorman::proxy::sha256(cert.der());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).expect("encode key");
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
            let _ = acceptor.accept(tcp).await;
        }
    });
    (addr, digest)
}

#[tokio::test]
async fn fingerprint_prints_matching_sha256_for_reachable_host() {
    let (addr, digest) = spawn_one_shot_tls_server().await;
    let expected = format!("sha256:{}", doorman::proxy::hex(&digest));

    let out = tokio::task::spawn_blocking(move || {
        doormand()
            .args(["fingerprint", &format!("127.0.0.1:{}", addr.port())])
            .output()
            .unwrap()
    })
    .await
    .unwrap();

    assert!(
        out.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), expected, "stdout: {}", stdout);
}

#[tokio::test]
async fn fingerprint_defaults_to_port_443_when_none_given() {
    // Binding 127.0.0.1:443 requires root/CAP_NET_BIND_SERVICE; skip
    // gracefully where that's not available rather than failing spuriously.
    let Ok(listener) = TcpListener::bind("127.0.0.1:443").await else {
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from("127.0.0.1".to_string()).unwrap())];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key).expect("self-sign");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let digest = doorman::proxy::sha256(cert.der());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).expect("encode key");
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
            let _ = acceptor.accept(tcp).await;
        }
    });

    let expected = format!("sha256:{}", doorman::proxy::hex(&digest));
    let out = tokio::task::spawn_blocking(|| doormand().args(["fingerprint", "127.0.0.1"]).output().unwrap())
        .await
        .unwrap();

    assert!(
        out.status.success(),
        "fingerprint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), expected, "stdout: {}", stdout);
}
