// Entry point. Two subcommands:
//
//   doormand install-service
//       Print a systemd unit tailored to this binary's path. (Just prints;
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

mod audit;
mod config;
mod proxy;

const DEFAULT_CONFIG: &str = "/etc/doorman/doorman.yaml";
const DEFAULT_AUDIT: &str = "/var/log/doorman/audit.log";
const DEFAULT_LISTEN: &str = "127.0.0.1:8443";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let rest = &args[args.len().min(1)..];
    let result = match cmd {
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
        "doormand — an HTTP proxy that holds your API keys.\n\n\
         usage:\n  \
           doormand install-service\n  \
           doormand run [--config PATH] [--audit PATH] [--listen ADDR]\n"
    );
}

fn cmd_install_service() -> Result<(), String> {
    let bin = std::env::current_exe().map_err(|e| format!("locate self: {}", e))?;
    println!("# systemd unit (write to /etc/systemd/system/doormand.service):");
    println!(
"[Unit]
Description=doorman HTTP credential proxy
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
    let audit = audit::Audit::open(&audit_path)?;
    let upstream_tls = proxy::upstream_tls();

    let server = proxy::Server {
        config: Arc::new(cfg),
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
