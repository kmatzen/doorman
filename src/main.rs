// Entry point. Two subcommands:
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
           doormand run [--config PATH] [--audit PATH] [--listen ADDR]\n"
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
    let audit = Arc::new(audit::Audit::open(&audit_path)?);
    let upstream_tls = proxy::upstream_tls();

    let server = proxy::Server {
        config: Arc::new(cfg),
        audit: Arc::clone(&audit),
        upstream_tls,
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
