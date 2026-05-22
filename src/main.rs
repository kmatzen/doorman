// Entry point. Subcommands:
//
//   doormand install-service
//       Print a service definition tailored to this binary's path —
//       a systemd unit on Linux, a launchd plist on macOS. (Just prints;
//       the operator redirects it where they want it.)
//
//   doormand run [--config PATH] [--audit PATH] [--listen ADDR]
//       The actual proxy. Refuses to start if any of: config missing/looser
//       than 0400, audit log unwritable.
//
//   doormand validate-config [--config PATH] [--insecure-skip-mode-check]
//       Run the same config validation `run` does, then exit — without
//       binding the port, opening the audit log, or touching an upstream.
//       Lets setup flows catch a typo before restarting a live daemon.
//
//   doormand fingerprint <host[:port]>
//       Print `sha256:<hex>` of an upstream's leaf cert, for pasting into a
//       credential's `tls_pinned_sha256` field.
//
// Argument parsing is done by hand because the surface is tiny and the spec
// takes a hard line on dependency creep.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use doorman::{audit, config, proxy};

const DEFAULT_CONFIG: &str = "/etc/doorman/doorman.yaml";
const DEFAULT_AUDIT: &str = "/var/log/doorman/audit.log";
const DEFAULT_LISTEN: &str = "127.0.0.1:18443";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = &args[args.len().min(1)..];
    let result = match cmd {
        "install-service" => cmd_install_service(rest),
        "run" => cmd_run(rest),
        "validate-config" => cmd_validate_config(rest),
        "fingerprint" => cmd_fingerprint(rest),
        "" | "-h" | "--help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("doormand: unknown subcommand {:?}", other);
            print_usage();
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("doormand: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "doormand — an HTTP proxy that holds your API keys.\n\n\
         usage:\n  \
           doormand install-service [--bin-path PATH]\n  \
           doormand run [--config PATH] [--audit PATH] [--listen ADDR]\n  \
           doormand validate-config [--config PATH] [--insecure-skip-mode-check]\n  \
           doormand fingerprint <host[:port]>\n"
    );
}

fn cmd_install_service(args: &[String]) -> Result<(), String> {
    // Default to where the running binary lives. Packaging scripts override
    // with --bin-path so the emitted unit/plist points at the eventual
    // install location (e.g. /usr/local/bin/doormand) rather than wherever
    // the build artifact happens to sit.
    let mut bin = std::env::current_exe()
        .map_err(|e| format!("locate self: {}", e))?
        .display()
        .to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bin-path" => {
                bin = args
                    .get(i + 1)
                    .ok_or("missing value for --bin-path")?
                    .clone();
                i += 2;
            }
            other => return Err(format!("install-service: unknown flag {:?}", other)),
        }
    }
    if cfg!(target_os = "macos") {
        print_launchd_plist(&bin);
    } else {
        print_systemd_unit(&bin);
    }
    Ok(())
}

// Templates for the service definitions. Lifted from share/ at compile time
// so the binary has no runtime file dependency. The release pipeline reads
// the same files directly to bundle them into per-target tarballs (so a
// cross-compiled binary that can't execute on the build host still ships
// with the correct unit/plist).
const SYSTEMD_TEMPLATE: &str = include_str!("../share/doormand.service.in");
const LAUNCHD_TEMPLATE: &str = include_str!("../share/com.doorman.doormand.plist.in");

fn print_systemd_unit(bin: &str) {
    println!("# systemd unit (write to /etc/systemd/system/doormand.service):");
    print!("{}", SYSTEMD_TEMPLATE.replace("__BIN_PATH__", bin));
}

fn print_launchd_plist(bin: &str) {
    println!("<!-- launchd plist (write to /Library/LaunchDaemons/com.doorman.doormand.plist, owner root:wheel, mode 0644) -->");
    print!("{}", LAUNCHD_TEMPLATE.replace("__BIN_PATH__", bin));
}

/// `doormand fingerprint <host[:port]>` — open a TLS connection to the
/// upstream accepting any certificate, print `sha256:<hex>` for the leaf,
/// and exit. Output is meant to be pasted straight into a credential
/// entry's `tls_pinned_sha256` field. No audit log, no config — this is
/// an out-of-band helper for the bootstrap step where the operator decides
/// what to pin.
fn cmd_fingerprint(args: &[String]) -> Result<(), String> {
    let target = args.first().ok_or("fingerprint: missing <host[:port]>")?;
    if args.len() > 1 {
        return Err(format!("fingerprint: unexpected extra arg {:?}", args[1]));
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|e| format!("invalid port {:?}: {}", p, e))?,
        ),
        None => (target.clone(), 443),
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build runtime: {}", e))?;
    runtime.block_on(async move {
        use std::sync::Arc;
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        #[derive(Debug)]
        struct CaptureFirstCert {
            leaf: std::sync::Mutex<Option<Vec<u8>>>,
        }
        impl ServerCertVerifier for CaptureFirstCert {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                *self.leaf.lock().unwrap() = Some(end_entity.as_ref().to_vec());
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _m: &[u8],
                _c: &CertificateDer<'_>,
                _d: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = Arc::new(CaptureFirstCert {
            leaf: std::sync::Mutex::new(None),
        });
        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::clone(&verifier) as _)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("dial {}: {}", addr, e))?;
        let server_name: ServerName<'static> = ServerName::try_from(host.clone())
            .map_err(|e| format!("server name {:?}: {}", host, e))?;
        // We don't need to send anything — just complete the handshake so the
        // verifier sees the cert. `connect` returns once the handshake is
        // done; we drop the stream immediately.
        let _tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("tls connect: {}", e))?;
        let leaf = verifier
            .leaf
            .lock()
            .unwrap()
            .take()
            .ok_or("handshake completed but verifier captured no leaf")?;
        let digest = doorman::proxy::sha256(&leaf);
        println!("sha256:{}", doorman::proxy::hex(&digest));
        Ok::<(), String>(())
    })
}

/// `doormand validate-config [--config PATH] [--insecure-skip-mode-check]` —
/// load and validate the config, then exit. Runs exactly the checks `run`
/// does (YAML syntax, the `inject` template shape, host/method allowlists,
/// the `tls`/`tls_pinned_sha256` consistency rules, the mode-0400 gate) but
/// never binds the listen port, opens the audit log, or contacts an upstream.
/// Lets setup and bootstrap flows catch a typo'd config *before* tearing down
/// a running daemon. On success prints the loaded credential names — names
/// only, never secrets — and exits 0; any error exits non-zero.
fn cmd_validate_config(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut enforce_0400 = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = PathBuf::from(args.get(i + 1).ok_or("missing value for --config")?);
                i += 2;
            }
            "--insecure-skip-mode-check" => {
                enforce_0400 = false;
                i += 1;
            }
            other => return Err(format!("validate-config: unknown flag {:?}", other)),
        }
    }

    let cfg = config::load(&config_path, enforce_0400)?;
    let n = cfg.entries.len();
    println!(
        "config OK: {} ({} credential{})",
        config_path.display(),
        n,
        if n == 1 { "" } else { "s" }
    );
    for entry in &cfg.entries {
        println!("  {}", entry.name);
    }
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut audit_path = PathBuf::from(DEFAULT_AUDIT);
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|e| format!("default listen addr: {}", e))?;
    let mut enforce_0400 = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = PathBuf::from(args.get(i + 1).ok_or("missing value for --config")?);
                i += 2;
            }
            "--audit" => {
                audit_path = PathBuf::from(args.get(i + 1).ok_or("missing value for --audit")?);
                i += 2;
            }
            "--listen" => {
                let v = args.get(i + 1).ok_or("missing value for --listen")?;
                listen = v.parse().map_err(|e| format!("--listen {:?}: {}", v, e))?;
                i += 2;
            }
            "--insecure-skip-mode-check" => {
                enforce_0400 = false;
                i += 1;
            }
            other => return Err(format!("run: unknown flag {:?}", other)),
        }
    }

    let cfg = config::load(&config_path, enforce_0400)?;
    let upstream_tls = proxy::upstream_tls();
    let upstream_tls_pinned = proxy::upstream_tls_pinned(&cfg);
    let audit = Arc::new(audit::Audit::open(&audit_path)?);

    // Record the loaded config in the audit trail: a SHA-256 of the file plus
    // the credential names it defines (never the secrets). Config edits happen
    // out-of-band — the file is mode 0400 and, depending on install tier, the
    // owning uid can rewrite it — so this is where a change becomes visible.
    // Best-effort: a failure here is logged but doesn't block startup, since
    // per-request auditing is the fail-closed path.
    match std::fs::read(&config_path) {
        Ok(bytes) => {
            let fingerprint = proxy::hex(&proxy::sha256(&bytes));
            let names: Vec<String> = cfg.entries.iter().map(|e| e.name.clone()).collect();
            if let Err(e) = audit.write_config_load(&audit::ConfigLoad {
                ts: audit::now_rfc3339(),
                event: "config_load",
                config_sha256: &fingerprint,
                credentials: &names,
            }) {
                eprintln!("doormand: audit config_load write failed: {}", e);
            }
        }
        Err(e) => eprintln!("doormand: could not re-read config for audit fingerprint: {}", e),
    }

    let server = proxy::Server {
        config: Arc::new(cfg),
        audit: Arc::clone(&audit),
        upstream_tls,
        upstream_tls_pinned,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build runtime: {}", e))?;
    runtime.block_on(async move {
        let serve = proxy::run(server, listen);
        let sigterm = async {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
            sig.recv().await;
        };
        let sigint = async {
            tokio::signal::ctrl_c().await.ok();
        };
        // SIGHUP triggers an audit-log re-open so external rotators can move
        // the current log aside and have us pick up the new file.
        let audit_for_sighup = Arc::clone(&audit);
        let sighup = async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("install SIGHUP handler");
            while sig.recv().await.is_some() {
                match audit_for_sighup.reopen() {
                    Ok(()) => eprintln!("SIGHUP, audit log reopened"),
                    Err(e) => eprintln!("SIGHUP, audit reopen failed: {}", e),
                }
            }
        };
        tokio::select! {
            r = serve => { r }
            _ = sigterm => { eprintln!("SIGTERM, shutting down"); Ok(()) }
            _ = sigint => { eprintln!("SIGINT, shutting down"); Ok(()) }
            _ = sighup => { Ok(()) }
        }
    })
}
