// Entry point. Three subcommands:
//
//   doormand init [--state-dir DIR]
//       Generate a fresh CA into DIR (default /etc/doorman). Prints the path
//       of the cert file the agent's trust store needs to import.
//
//   doormand install-service
//       Print a systemd unit / launchd plist tailored to this binary's path.
//       (Just prints; the operator is the one who installs.)
//
//   doormand run [--config PATH] [--state-dir DIR] [--audit PATH] [--listen ADDR]
//       The actual proxy. Refuses to start if any of: config missing/looser
//       than 0400, CA missing, audit log unwritable.
//
// Argument parsing is done by hand because the surface is tiny and the spec
// takes a hard line on dependency creep.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

mod audit;
mod ca;
mod config;
mod proxy;

const DEFAULT_STATE_DIR: &str = "/etc/doorman";
const DEFAULT_CONFIG_NAME: &str = "doorman.yaml";
const DEFAULT_AUDIT: &str = "/var/log/doorman/audit.log";
const DEFAULT_LISTEN: &str = "127.0.0.1:8443";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = &args[args.len().min(1)..];
    let result = match cmd {
        "init" => cmd_init(rest),
        "install-service" => cmd_install_service(),
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
        "doormand — an HTTPS proxy that holds your API keys.\n\n\
         usage:\n  \
           doormand init [--state-dir DIR]\n  \
           doormand install-service\n  \
           doormand run [--config PATH] [--state-dir DIR] [--audit PATH] [--listen ADDR]\n"
    );
}

fn cmd_init(args: &[String]) -> Result<(), String> {
    let mut state_dir = PathBuf::from(DEFAULT_STATE_DIR);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state-dir" => {
                state_dir = PathBuf::from(args.get(i + 1).ok_or("missing value for --state-dir")?);
                i += 2;
            }
            other => return Err(format!("init: unknown flag {:?}", other)),
        }
    }
    let crt = ca::generate(&state_dir)?;
    println!("CA written to {}", crt.display());
    println!("Add it to your agent's trust store, e.g.:");
    println!("  export SSL_CERT_FILE={}", crt.display());
    println!("Then write {}/{} (mode 0400) and run `doormand run`.", state_dir.display(), DEFAULT_CONFIG_NAME);
    Ok(())
}

fn cmd_install_service() -> Result<(), String> {
    let bin = std::env::current_exe().map_err(|e| format!("locate self: {}", e))?;
    println!("# systemd unit (write to /etc/systemd/system/doormand.service):");
    println!(
"[Unit]
Description=doorman HTTPS credential proxy
After=network.target

[Service]
ExecStart={} run
User=doorman
Group=doorman
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadWritePaths=/var/log/doorman
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target", bin.display());
    Ok(())
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let mut config_path: Option<PathBuf> = None;
    let mut state_dir = PathBuf::from(DEFAULT_STATE_DIR);
    let mut audit_path = PathBuf::from(DEFAULT_AUDIT);
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|e| format!("default listen addr: {}", e))?;
    let mut enforce_0400 = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(args.get(i + 1).ok_or("missing value for --config")?));
                i += 2;
            }
            "--state-dir" => {
                state_dir = PathBuf::from(args.get(i + 1).ok_or("missing value for --state-dir")?);
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
    let config_path = config_path.unwrap_or_else(|| state_dir.join(DEFAULT_CONFIG_NAME));

    let cfg = config::load(&config_path, enforce_0400)?;
    let ca = ca::Ca::load(&state_dir)?;
    let audit = audit::Audit::open(&audit_path)?;
    let upstream_tls = proxy::upstream_tls();

    let server = proxy::Server {
        config: Arc::new(cfg),
        ca: Arc::new(ca),
        audit: Arc::new(audit),
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
        tokio::select! {
            r = serve => { r }
            _ = sigterm => { eprintln!("SIGTERM, shutting down"); Ok(()) }
            _ = sigint => { eprintln!("SIGINT, shutting down"); Ok(()) }
        }
    })
}
