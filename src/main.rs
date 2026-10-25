// Entry point. Subcommands:
//
//   doormand install-service
//       Print a service definition tailored to this binary's path —
//       a systemd unit on Linux, a launchd plist on macOS. (Just prints;
//       the operator redirects it where they want it.)
//
//   doormand run [--config PATH] [--audit PATH] [--listen ADDR] [--allow-same-uid]
//       The actual proxy. Refuses to start if any of: config missing/looser
//       than 0400, audit log unwritable. Warns at startup if it is running
//       under a personal login uid (the same-UID exposure of issue #39);
//       --allow-same-uid silences that warning for the convenience tier.
//
//   doormand validate-config [--config PATH] [--insecure-skip-mode-check]
//       Run the same config validation `run` does, then exit — without
//       binding the port, opening the audit log, or touching an upstream.
//       Lets setup flows catch a typo before restarting a live daemon.
//
//   doormand inspect [--config PATH] [--json] [--with-inject]
//       Print the validated, non-sensitive policy. Secrets are never included;
//       the injection template is opt-in because it reveals the header name.
//
//   doormand audit tail [-n COUNT] [--audit PATH]
//   doormand audit last-error [--audit PATH]
//       Read recent audit activity while projecting records onto the known,
//       non-sensitive fields. Unknown fields are never echoed.
//
//   doormand list [--address ADDR] [--json]
//       Query the running daemon's loopback health endpoint and print its
//       loaded credential names.
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

use doorman::{audit, config, hardening, proxy};
use serde::Serialize;

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
        "inspect" => cmd_inspect(rest),
        "audit" => cmd_audit(rest),
        "list" => cmd_list(rest),
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
           doormand install-service [--user] [--bin-path PATH]\n  \
           doormand run [--config PATH] [--audit PATH] [--listen ADDR] [--allow-same-uid]\n  \
           doormand validate-config [--config PATH] [--insecure-skip-mode-check]\n  \
           doormand inspect [--config PATH] [--json] [--with-inject] [--insecure-skip-mode-check]\n  \
           doormand audit tail [-n COUNT] [--audit PATH]\n  \
           doormand audit last-error [--audit PATH]\n  \
           doormand list [--address ADDR] [--json]\n  \
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
    let mut user_scope = false;
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
            "--user" => {
                user_scope = true;
                i += 1;
            }
            other => return Err(format!("install-service: unknown flag {:?}", other)),
        }
    }
    if user_scope {
        let home = std::env::var("HOME")
            .map_err(|_| "install-service --user: HOME is not set".to_string())?;
        let config = PathBuf::from(&home).join(".config/doorman/doorman.yaml");
        let state = PathBuf::from(&home).join(".local/state/doorman");
        let audit = state.join("audit.log");
        if cfg!(target_os = "macos") {
            print_user_launchd_plist(&bin, &config, &state, &audit);
        } else {
            print_user_systemd_unit(&bin, &config, &audit);
        }
    } else if cfg!(target_os = "macos") {
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

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn print_user_systemd_unit(bin: &str, config: &std::path::Path, audit: &std::path::Path) {
    println!("# systemd user unit (write to ~/.config/systemd/user/doormand.service):");
    println!("[Unit]");
    println!("Description=doorman HTTP credential proxy (user service)");
    println!("After=network.target");
    println!();
    println!("[Service]");
    println!(
        "ExecStart={} run --config {} --audit {}",
        systemd_quote(bin),
        systemd_quote(&config.display().to_string()),
        systemd_quote(&audit.display().to_string())
    );
    println!("Restart=on-failure");
    println!("RestartSec=2s");
    println!("NoNewPrivileges=true");
    println!("PrivateTmp=true");
    println!();
    println!("[Install]");
    println!("WantedBy=default.target");
}

fn print_user_launchd_plist(
    bin: &str,
    config: &std::path::Path,
    state: &std::path::Path,
    audit: &std::path::Path,
) {
    let bin = xml_escape(bin);
    let config = xml_escape(&config.display().to_string());
    let state = xml_escape(&state.display().to_string());
    let audit = xml_escape(&audit.display().to_string());
    println!("<!-- launchd user agent (write to ~/Library/LaunchAgents/com.doorman.doormand.plist, mode 0644) -->");
    println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    println!("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
    println!("<plist version=\"1.0\">");
    println!("<dict>");
    println!("  <key>Label</key><string>com.doorman.doormand</string>");
    println!("  <key>ProgramArguments</key>");
    println!("  <array>");
    println!("    <string>{}</string>", bin);
    println!("    <string>run</string>");
    println!("    <string>--config</string><string>{}</string>", config);
    println!("    <string>--audit</string><string>{}</string>", audit);
    println!("  </array>");
    println!("  <key>RunAtLoad</key><true/>");
    println!("  <key>KeepAlive</key><true/>");
    println!(
        "  <key>StandardOutPath</key><string>{}/stdout.log</string>",
        state
    );
    println!(
        "  <key>StandardErrorPath</key><string>{}/stderr.log</string>",
        state
    );
    println!("  <key>ProcessType</key><string>Background</string>");
    println!("</dict>");
    println!("</plist>");
}

/// Parse a `fingerprint` CLI target into `(host, port)`. Bracketed IPv6
/// (`[fd00::5]` or `[fd00::5]:8443`) is required for IPv6 literals — bare
/// IPv6 is inherently ambiguous with the `:port` suffix, since the literal's
/// own colons collide with the separator. Everything else (hostnames, IPv4
/// literals) works as a bare `host` or `host:port`, matching the pre-IPv6
/// behavior exactly. Default port is 443.
fn parse_fingerprint_target(target: &str) -> Result<(String, u16), String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("{:?}: missing closing ']' for IPv6 literal", target))?;
        let port = match after.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|e| format!("invalid port {:?}: {}", p, e))?,
            None if after.is_empty() => 443,
            None => {
                return Err(format!(
                    "{:?}: unexpected characters after ']': {:?}",
                    target, after
                ))
            }
        };
        return Ok((host.to_string(), port));
    }
    Ok(match target.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|e| format!("invalid port {:?}: {}", p, e))?,
        ),
        None => (target.to_string(), 443),
    })
}

/// `doormand fingerprint <host[:port]>` — open a TLS connection to the
/// upstream accepting any certificate, print `sha256:<hex>` for the leaf,
/// and exit. Output is meant to be pasted straight into a credential
/// entry's `tls_pinned_sha256` field. No audit log, no config — this is
/// an out-of-band helper for the bootstrap step where the operator decides
/// what to pin.
///
/// An IPv6 target must use bracket notation (`[fd00::5]` or
/// `[fd00::5]:8443`) — bare IPv6 is ambiguous with the `:port` suffix (a
/// literal's own colons collide with the separator), the same reason URIs
/// require brackets there. Everything else (hostnames, IPv4 literals)
/// works as a bare `host` or `host:port`, as before.
fn cmd_fingerprint(args: &[String]) -> Result<(), String> {
    let target = args.first().ok_or("fingerprint: missing <host[:port]>")?;
    if args.len() > 1 {
        return Err(format!("fingerprint: unexpected extra arg {:?}", args[1]));
    }
    let (host, port) = parse_fingerprint_target(target)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build runtime: {}", e))?;
    runtime.block_on(async move {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};
        use std::sync::Arc;
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
        // (host, port) tuple form, not a formatted "host:port" string: for a
        // bare IPv6 literal, string concatenation would be ambiguous colon
        // soup. Rust's resolver accepts an unbracketed IPv4/IPv6/hostname
        // string as the host half of this tuple directly.
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| format!("dial {}:{}: {}", host, port, e))?;
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

#[derive(Serialize)]
struct InspectedEntry<'a> {
    name: &'a str,
    hosts: &'a [String],
    methods: &'a [String],
    port: u16,
    tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_pinned_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inject: Option<String>,
}

/// Print only the policy portions of a validated config. This deliberately
/// builds a separate serialization type with no `secret` field, rather than
/// serializing `config::Entry` and trying to redact it afterward.
fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut enforce_0400 = true;
    let mut json = false;
    let mut with_inject = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = PathBuf::from(args.get(i + 1).ok_or("missing value for --config")?);
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--with-inject" => {
                with_inject = true;
                i += 1;
            }
            "--insecure-skip-mode-check" => {
                enforce_0400 = false;
                i += 1;
            }
            other => return Err(format!("inspect: unknown flag {:?}", other)),
        }
    }

    let cfg = config::load(&config_path, enforce_0400)?;
    let policy: Vec<InspectedEntry<'_>> = cfg
        .entries
        .iter()
        .map(|entry| InspectedEntry {
            name: &entry.name,
            hosts: &entry.hosts,
            methods: &entry.methods,
            port: entry.port,
            tls: entry.tls,
            tls_pinned_sha256: entry.tls_pin.as_ref().map(|pin| proxy::hex(pin.as_slice())),
            inject: with_inject.then(|| {
                format!(
                    "{}: {}{{}}{}",
                    entry.header_name, entry.header_prefix, entry.header_suffix
                )
            }),
        })
        .collect();

    let output = if json {
        serde_json::to_string_pretty(&policy).map_err(|e| format!("serialize JSON: {}", e))?
    } else {
        serde_yaml::to_string(&policy).map_err(|e| format!("serialize YAML: {}", e))?
    };
    println!("{}", output.trim_end());
    Ok(())
}

fn cmd_audit(args: &[String]) -> Result<(), String> {
    use std::collections::VecDeque;
    use std::io::{BufRead, BufReader};

    let action = args
        .first()
        .ok_or("audit: expected 'tail' or 'last-error'")?;
    if action != "tail" && action != "last-error" {
        return Err(format!("audit: unknown action {:?}", action));
    }

    let mut audit_path = PathBuf::from(DEFAULT_AUDIT);
    let mut count: usize = 50;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--audit" => {
                audit_path = PathBuf::from(args.get(i + 1).ok_or("missing value for --audit")?);
                i += 2;
            }
            "-n" if action == "tail" => {
                let raw = args.get(i + 1).ok_or("missing value for -n")?;
                count = raw
                    .parse()
                    .map_err(|_| format!("audit tail: invalid count {:?}", raw))?;
                i += 2;
            }
            flag => return Err(format!("audit {}: unknown flag {:?}", action, flag)),
        }
    }

    let file = std::fs::File::open(&audit_path)
        .map_err(|e| format!("open audit log {}: {}", audit_path.display(), e))?;
    let mut selected = VecDeque::new();
    for (line_no, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| {
            format!(
                "read audit log {} line {}: {}",
                audit_path.display(),
                line_no + 1,
                e
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&line).map_err(|e| {
            format!(
                "parse audit log {} line {}: {}",
                audit_path.display(),
                line_no + 1,
                e
            )
        })?;
        if action == "last-error" && !audit_record_is_error(&value) {
            continue;
        }
        if count == 0 && action == "tail" {
            continue;
        }
        selected.push_back(safe_audit_record(&value));
        let keep = if action == "last-error" { 1 } else { count };
        while selected.len() > keep {
            selected.pop_front();
        }
    }

    if action == "last-error" && selected.is_empty() {
        return Err(format!(
            "audit last-error: no denied or non-2xx record in {}",
            audit_path.display()
        ));
    }
    for record in selected {
        println!(
            "{}",
            serde_json::to_string(&record).map_err(|e| format!("serialize audit record: {}", e))?
        );
    }
    Ok(())
}

fn audit_record_is_error(value: &serde_json::Value) -> bool {
    value.get("decision").and_then(|v| v.as_str()) == Some("deny")
        || value
            .get("status")
            .and_then(|v| v.as_u64())
            .is_some_and(|status| !(200..300).contains(&status))
}

/// Copy only the audit schema's documented diagnostic fields. This remains
/// safe even if a malformed or future audit producer adds a secret-bearing
/// field: unknown input fields are never reflected to stdout.
fn safe_audit_record(value: &serde_json::Value) -> serde_json::Value {
    const SAFE_FIELDS: &[&str] = &[
        "ts", "event", "cred", "host", "method", "path", "status", "decision", "reason", "protocol",
    ];
    let mut safe = serde_json::Map::new();
    for field in SAFE_FIELDS {
        if let Some(field_value) = value.get(*field) {
            safe.insert((*field).to_string(), field_value.clone());
        }
    }
    serde_json::Value::Object(safe)
}

fn cmd_list(args: &[String]) -> Result<(), String> {
    use std::io::{Read, Write};

    let mut address: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|e| format!("default daemon address: {}", e))?;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--address" => {
                let raw = args.get(i + 1).ok_or("missing value for --address")?;
                address = raw
                    .parse()
                    .map_err(|e| format!("--address {:?}: {}", raw, e))?;
                i += 2;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            other => return Err(format!("list: unknown flag {:?}", other)),
        }
    }
    if !address.ip().is_loopback() {
        return Err("list: --address must be a loopback address".into());
    }

    let mut stream = std::net::TcpStream::connect(address)
        .map_err(|e| format!("connect to doorman at {}: {}", address, e))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {}", e))?;
    let host = match address.ip() {
        std::net::IpAddr::V4(ip) => format!("{}:{}", ip, address.port()),
        std::net::IpAddr::V6(ip) => format!("[{}]:{}", ip, address.port()),
    };
    write!(
        stream,
        "GET /_doorman/health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    )
    .map_err(|e| format!("query doorman: {}", e))?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            // Some small HTTP servers close with a TCP reset after writing a
            // complete `Connection: close` response. Treat that as EOF only
            // after bytes have arrived; parsing below still validates that a
            // complete status line, headers, and JSON body were received.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() => {
                break;
            }
            Err(e) => return Err(format!("read doorman response: {}", e)),
        }
    }
    let response =
        String::from_utf8(response).map_err(|e| format!("response is not UTF-8: {}", e))?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("malformed response from doorman")?;
    if !head.starts_with("HTTP/1.1 200 ") {
        let status = head.lines().next().unwrap_or("unknown status");
        return Err(format!("health endpoint returned {}", status));
    }
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("parse health response: {}", e))?;
    if value.get("schema_version").and_then(|v| v.as_u64()) != Some(1)
        || value.get("ok").and_then(|v| v.as_bool()) != Some(true)
    {
        return Err("unsupported or unhealthy response from doorman".into());
    }
    let credentials = value
        .get("credentials")
        .and_then(|v| v.as_array())
        .ok_or("health response has no credentials array")?;
    if json {
        println!("{}", serde_json::json!({ "credentials": credentials }));
    } else {
        for credential in credentials {
            let name = credential
                .as_str()
                .ok_or("health response contains a non-string credential name")?;
            println!("{}", name);
        }
    }
    Ok(())
}

/// Loud one-shot warning when the unauthenticated proxy binds beyond loopback; pure so it is testable without binding a socket.
fn non_loopback_listen_warning(listen: SocketAddr) -> Option<String> {
    if listen.ip().is_loopback() {
        return None;
    }
    Some(format!(
        "SECURITY: --listen {} is not a loopback address, and the proxy has NO\n  \
         caller authentication.\n  \
         Every host that can reach this address can use every credential doorman holds —\n  \
         binding here hands your API keys to the whole LAN (on 0.0.0.0, to the world).\n  \
         Pin the listener to 127.0.0.1, or front it with firewalled, authenticated\n  \
         access you control.",
        listen
    ))
}

fn cmd_run(args: &[String]) -> Result<(), String> {
    let mut config_path = PathBuf::from(DEFAULT_CONFIG);
    let mut audit_path = PathBuf::from(DEFAULT_AUDIT);
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|e| format!("default listen addr: {}", e))?;
    let mut enforce_0400 = true;
    let mut allow_same_uid = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = PathBuf::from(args.get(i + 1).ok_or("missing value for --config")?);
                i += 2;
            }
            "--allow-same-uid" => {
                allow_same_uid = true;
                i += 1;
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

    // Clear the dumpable bit before touching any secret material: without
    // this, a normally started process defaults to dumpable, so a same-uid
    // `ptrace` or a crash dump could lift every decrypted secret straight out
    // of memory. Best-effort on Linux (a no-op on macOS, which has no
    // equivalent primitive); a failure is logged but does not block startup,
    // since it is defense-in-depth on top of the uid separation that's the
    // real boundary.
    if let Err(e) = hardening::disable_ptrace_and_core_dumps() {
        eprintln!("doormand: could not disable ptrace/core dumps: {}", e);
    }

    let cfg = config::load(&config_path, enforce_0400)?;

    // Posture check (issue #39): if the daemon is running under a personal
    // login uid, the plaintext config is readable by anything else sharing
    // that uid and the broker indirection is bypassed at rest. Warn loudly —
    // this goes to the service's stderr log on every start — unless the
    // operator has explicitly accepted the convenience-tier posture.
    if !allow_same_uid {
        if let Some(warning) = hardening::login_uid_warning(hardening::current_euid()) {
            eprintln!("doormand: {}", warning);
        }
    }

    // The network-side twin of the uid posture warning; loopback stays silent.
    if let Some(warning) = non_loopback_listen_warning(listen) {
        eprintln!("doormand: {}", warning);
    }

    let upstream_tls = proxy::upstream_tls();
    let upstream_tls_pinned = proxy::upstream_tls_pinned(&cfg);
    let audit = Arc::new(audit::Audit::open(&audit_path)?);

    // Record the loaded config in the audit trail: a SHA-256 of the file plus
    // the credential names it defines (never the secrets). Config edits happen
    // out-of-band — the file is mode 0400 and, depending on install tier, the
    // owning uid can rewrite it — so this is where a change becomes visible.
    // Best-effort: a failure here is logged but doesn't block startup, since
    // per-request auditing is the fail-closed path.
    audit_loaded_config(&audit, &config_path, &cfg);

    let policy = Arc::new(std::sync::RwLock::new(proxy::RuntimePolicy {
        config: cfg,
        upstream_tls_pinned,
    }));
    let server = proxy::Server {
        policy: Arc::clone(&policy),
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
        // SIGHUP reopens the audit log and attempts an atomic policy reload.
        // A failed validation leaves the last known-good policy untouched.
        let audit_for_sighup = Arc::clone(&audit);
        let policy_for_sighup = Arc::clone(&policy);
        let config_for_sighup = config_path.clone();
        let sighup = async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("install SIGHUP handler");
            while sig.recv().await.is_some() {
                match audit_for_sighup.reopen() {
                    Ok(()) => eprintln!("SIGHUP, audit log reopened"),
                    Err(e) => eprintln!("SIGHUP, audit reopen failed: {}", e),
                }
                match config::load(&config_for_sighup, enforce_0400) {
                    Ok(new_config) => {
                        let new_pinned = proxy::upstream_tls_pinned(&new_config);
                        let count = new_config.entries.len();
                        let config_for_audit = new_config.clone();
                        *policy_for_sighup.write().expect("policy lock poisoned") =
                            proxy::RuntimePolicy {
                                config: new_config,
                                upstream_tls_pinned: new_pinned,
                            };
                        audit_loaded_config(
                            &audit_for_sighup,
                            &config_for_sighup,
                            &config_for_audit,
                        );
                        eprintln!("SIGHUP, config reloaded ({} credentials)", count);
                    }
                    Err(e) => eprintln!(
                        "SIGHUP, config reload rejected; keeping previous policy: {}",
                        e
                    ),
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

fn audit_loaded_config(audit: &audit::Audit, config_path: &std::path::Path, cfg: &config::Config) {
    match std::fs::read(config_path) {
        Ok(bytes) => {
            let fingerprint = proxy::hex(&proxy::sha256(&bytes));
            let names: Vec<String> = cfg.entries.iter().map(|entry| entry.name.clone()).collect();
            if let Err(e) = audit.write_config_load(&audit::ConfigLoad {
                ts: audit::now_rfc3339(),
                event: "config_load",
                config_sha256: &fingerprint,
                credentials: &names,
            }) {
                eprintln!("doormand: audit config_load write failed: {}", e);
            }
        }
        Err(e) => eprintln!(
            "doormand: could not read config for audit fingerprint: {}",
            e
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_listens_get_no_security_warning() {
        // The default posture stays silent: both loopback families, any port.
        assert!(non_loopback_listen_warning("127.0.0.1:18443".parse().unwrap()).is_none());
        assert!(non_loopback_listen_warning("127.5.5.5:1".parse().unwrap()).is_none());
        assert!(non_loopback_listen_warning("[::1]:18443".parse().unwrap()).is_none());
    }

    #[test]
    fn non_loopback_listens_warn() {
        for addr in ["0.0.0.0:18443", "[::]:18443", "192.168.86.10:18443"] {
            let w = non_loopback_listen_warning(addr.parse().unwrap())
                .unwrap_or_else(|| panic!("{addr} should warn"));
            assert!(w.contains("SECURITY"), "got: {}", w);
            assert!(w.contains(addr), "warning should name the address: {}", w);
        }
    }

    #[test]
    fn fingerprint_target_bare_host_no_port() {
        assert_eq!(
            parse_fingerprint_target("api.github.com").unwrap(),
            ("api.github.com".to_string(), 443)
        );
    }

    #[test]
    fn fingerprint_target_bare_host_with_port() {
        assert_eq!(
            parse_fingerprint_target("192.168.86.1:8443").unwrap(),
            ("192.168.86.1".to_string(), 8443)
        );
    }

    #[test]
    fn fingerprint_target_bracketed_ipv6_no_port() {
        assert_eq!(
            parse_fingerprint_target("[fd00::5]").unwrap(),
            ("fd00::5".to_string(), 443)
        );
    }

    #[test]
    fn fingerprint_target_bracketed_ipv6_with_port() {
        assert_eq!(
            parse_fingerprint_target("[fd00::5]:8443").unwrap(),
            ("fd00::5".to_string(), 8443)
        );
    }

    #[test]
    fn fingerprint_target_rejects_unclosed_bracket() {
        let err = parse_fingerprint_target("[fd00::5").unwrap_err();
        assert!(err.contains("closing"), "got: {}", err);
    }

    #[test]
    fn fingerprint_target_rejects_garbage_after_bracket() {
        let err = parse_fingerprint_target("[fd00::5]garbage").unwrap_err();
        assert!(err.contains("unexpected characters"), "got: {}", err);
    }

    #[test]
    fn fingerprint_target_rejects_bad_port() {
        assert!(parse_fingerprint_target("host:notaport").is_err());
        assert!(parse_fingerprint_target("[fd00::5]:notaport").is_err());
    }
}
