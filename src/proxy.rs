// The proxy core. Plain HTTP/1.1 forward proxy: agents speak plaintext to
// doorman, doorman speaks TLS (or plaintext, per-credential) to the upstream.
// The agent's request URI may be in absolute form
// (`GET http://api.github.com/path HTTP/1.1`) or in origin form with a
// `Host:` header — both are accepted.
//
// Request flow:
//   - extract upstream host (from URI authority or `Host` header)
//   - locate the `{{name}}` placeholder in some request header
//   - look up the credential, validate host and method against the policy
//   - drop the placeholder header and any hop-by-hop headers; inject the
//     templated auth header per the credential's `inject` template
//   - dial the upstream on the credential's port; either TLS-handshake
//     (with webpki roots, or with a SHA-256 leaf pin when the credential
//     pins) or skip TLS entirely (when `tls: false`); stream the request
//     body through; stream the response body back; strip `Set-Cookie` and
//     `WWW-Authenticate` from the response
//   - write one audit-log line at end-of-stream (or on drop)
//
// WebSocket / HTTP-Upgrade requests (a `Connection: upgrade` + `Upgrade:`
// header pair) take a variant of the same path: the credential is injected on
// the handshake exactly as above, the host/method allowlist is enforced just
// like any other request, and if the upstream answers 101 the two connections
// are spliced byte-for-byte until either side closes. doorman does not parse
// WebSocket frames — once upgraded it's an opaque relay.
//
// What this module deliberately does NOT do:
//   - terminate TLS on the agent side (no CA, no per-host leaf certs)
//   - support HTTPS_PROXY / `CONNECT` (the agent must use HTTP_PROXY and
//     `http://` URLs; WebSockets go through the `Upgrade` path above, not
//     `CONNECT`)
//   - follow redirects (3xx returned to the agent verbatim)
//   - HTTP/2 (HTTP/1.1 only, on both sides)
//   - cache or pool upstream connections (one TLS handshake per request)

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::header::{HeaderName, HeaderValue, CONNECTION, HOST, UPGRADE};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use crate::audit::{self, Audit, Record};
use crate::config::{canonicalize_host, Config, Entry};

/// Headers stripped from every upstream response before it goes back to the
/// agent. Some upstreams put session material in these on auth errors.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &["set-cookie", "www-authenticate"];

/// Header the agent sets to name the credential it wants doorman to inject.
/// Doorman strips this header from the request before forwarding upstream.
const CRED_HEADER: &str = "x-doorman-cred";

#[derive(Clone)]
pub struct Server {
    pub config: Arc<Config>,
    pub audit: Arc<Audit>,
    /// `ClientConfig` used for credentials that do plain webpki chain
    /// validation (the historical default).
    pub upstream_tls: Arc<rustls::ClientConfig>,
    /// Per-credential `ClientConfig`s, populated only for entries that pin
    /// a leaf cert SHA-256. Each one carries a [`PinVerifier`] in place of
    /// webpki chain validation. Keyed by credential name.
    pub upstream_tls_pinned: Arc<HashMap<String, Arc<rustls::ClientConfig>>>,
}

impl Server {
    /// Pick the right TLS client config for an entry. Returns `None` for
    /// entries that don't do TLS at all (`tls: false`), which is a caller
    /// signal to dial plain TCP.
    fn tls_for(&self, entry: &Entry) -> Option<Arc<rustls::ClientConfig>> {
        if !entry.tls {
            return None;
        }
        if entry.tls_pin.is_some() {
            // The map is built from the same config at startup, so a missing
            // entry here is a programmer error — `expect` rather than fall
            // back to webpki, which would be a silent downgrade.
            let cfg = self
                .upstream_tls_pinned
                .get(&entry.name)
                .expect("pinned entry has no precomputed ClientConfig");
            return Some(Arc::clone(cfg));
        }
        Some(Arc::clone(&self.upstream_tls))
    }
}

type DynErr = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, DynErr>;

pub async fn run(server: Server, listen: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {}: {}", listen, e))?;
    eprintln!("doorman listening on {} (plain HTTP forward proxy)", listen);
    serve_listener(server, listener).await
}

/// Serve on a pre-bound listener. Tests use this to bind on `127.0.0.1:0`
/// and then learn the assigned port via `local_addr()`.
pub async fn serve_listener(server: Server, listener: TcpListener) -> Result<(), String> {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };
        let s = server.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(s, stream).await {
                eprintln!("connection {}: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(server: Server, stream: TcpStream) -> Result<(), String> {
    let svc = service_fn(move |req: Request<Incoming>| {
        let server = server.clone();
        async move { Ok::<_, Infallible>(serve(server, req).await) }
    });
    server_http1::Builder::new()
        .serve_connection(TokioIo::new(stream), svc)
        // `.with_upgrades()` lets a 101 response we return hand the raw
        // connection back to us for a WebSocket byte-splice. No effect on
        // ordinary request/response traffic.
        .with_upgrades()
        .await
        .map_err(|e| format!("h1: {}", e))
}

/// One inbound HTTP request from the agent. Returns either a doorman 4xx/5xx
/// or the streamed upstream response.
async fn serve(server: Server, mut req: Request<Incoming>) -> Response<ProxyBody> {
    let started = Instant::now();
    let method = req.method().clone();

    // CONNECT is the classic HTTPS_PROXY / wss:// misconfiguration: doorman
    // is a strict forward proxy that reads http:// requests and
    // re-originates TLS itself (see the "what this module deliberately does
    // NOT do" note above) — it was never going to tunnel one. Reject it here,
    // before any other processing: left to fall through, a CONNECT with no
    // cred header dies with a generic "missing X-Doorman-Cred" that doesn't
    // name the actual problem, and a CONNECT that happens to carry a valid
    // cred header for an allowlisted host would reach `send_upstream` and
    // forward a method doorman was never built to relay.
    if method == hyper::Method::CONNECT {
        return deny_connect_not_supported(&server, &req, started);
    }

    // Resolve target host: prefer the URI authority (absolute-form requests
    // sent to a forward proxy) and fall back to the `Host` header.
    let target_host = match resolve_target_host(&req) {
        Some(h) => h,
        None => {
            return deny_no_target(&server, &method, started);
        }
    };

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Detect an HTTP/1.1 Upgrade (WebSocket) request and, if it is one, take
    // the agent-side upgrade handle now — before the request is torn apart.
    // Holding it is harmless even if we go on to deny: the upgrade only
    // happens if this handler returns a 101.
    let agent_upgrade = if is_upgrade_request(req.headers()) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };
    let is_upgrade = agent_upgrade.is_some();

    let (mut parts, body) = req.into_parts();

    let cred_name = match find_credential(&parts.headers) {
        Ok(v) => v,
        Err(reason) => {
            return deny(
                &server,
                &target_host,
                method.as_str(),
                &path_and_query,
                None,
                StatusCode::FORBIDDEN,
                Some(reason),
                started,
            );
        }
    };

    let entry = match server.config.lookup(&cred_name) {
        Some(e) => e,
        None => {
            return deny(
                &server,
                &target_host,
                method.as_str(),
                &path_and_query,
                Some(&cred_name),
                StatusCode::FORBIDDEN,
                Some("unknown credential"),
                started,
            );
        }
    };

    if !entry.host_allowed(&target_host) {
        return deny(
            &server,
            &target_host,
            method.as_str(),
            &path_and_query,
            Some(&cred_name),
            StatusCode::FORBIDDEN,
            Some("host not allowlisted for credential"),
            started,
        );
    }
    if !entry.method_allowed(method.as_str()) {
        return deny(
            &server,
            &target_host,
            method.as_str(),
            &path_and_query,
            Some(&cred_name),
            StatusCode::FORBIDDEN,
            Some("method not allowlisted for credential"),
            started,
        );
    }

    // Rewrite headers (shared by the normal and the WebSocket-upgrade paths):
    // drop the cred-name header (a doorman-internal signal that must not leak
    // upstream), drop hop-by-hop headers, inject the templated auth header,
    // and set Host to the canonical target. For an upgrade request,
    // `Connection: upgrade` and `Upgrade` are left in place (doorman
    // deliberately re-establishes the handshake with the upstream rather
    // than tunneling) along with any `Sec-WebSocket-*` headers, which are
    // end-to-end, not hop-by-hop, and were never touched here.
    parts.headers.remove(CRED_HEADER);
    strip_hop_by_hop(&mut parts.headers, is_upgrade);
    let inject_name =
        HeaderName::try_from(entry.header_name.as_str()).expect("validated at config load");
    let inject_value = HeaderValue::try_from(entry.render()).expect("validated at config load");
    parts.headers.insert(inject_name, inject_value);
    parts.headers.insert(
        HOST,
        HeaderValue::try_from(host_header_value(&target_host)).expect("host header"),
    );

    // Force the outgoing URI to origin-form. Upstream HTTP/1.1 origin servers
    // expect `GET /path HTTP/1.1`, not `GET https://host/path HTTP/1.1`.
    parts.uri = match path_and_query.parse() {
        Ok(u) => u,
        Err(_) => {
            return deny(
                &server,
                &target_host,
                method.as_str(),
                &path_and_query,
                Some(&cred_name),
                StatusCode::BAD_REQUEST,
                Some("invalid request path"),
                started,
            );
        }
    };

    // WebSocket/Upgrade path: forward the handshake with an empty body and, on
    // a 101 from the upstream, splice the two connections byte-for-byte.
    if let Some(agent_upgrade) = agent_upgrade {
        let upstream_req = Request::from_parts(parts, Empty::<Bytes>::new());
        return relay_upgrade(
            &server,
            entry,
            target_host,
            cred_name,
            method.as_str().to_string(),
            path_and_query,
            upstream_req,
            agent_upgrade,
            started,
        )
        .await;
    }

    let bytes_in_counter = Arc::new(AtomicU64::new(0));
    let req_body = Counting {
        inner: body,
        counter: Arc::clone(&bytes_in_counter),
        on_end: None,
    };
    let upstream_req = Request::from_parts(parts, req_body);

    let upstream_response = match send_upstream(&server, &target_host, entry, upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            return deny(
                &server,
                &target_host,
                method.as_str(),
                &path_and_query,
                Some(&cred_name),
                StatusCode::BAD_GATEWAY,
                Some(&format!("upstream: {}", e)),
                started,
            );
        }
    };

    finish_response(
        &server,
        upstream_response,
        cred_name,
        target_host,
        method.as_str().to_string(),
        path_and_query,
        bytes_in_counter,
        started,
    )
}

/// True for an HTTP/1.1 Upgrade request: a `Connection` header that lists the
/// `upgrade` token together with an `Upgrade` header (e.g. `Upgrade: websocket`).
fn is_upgrade_request(headers: &hyper::HeaderMap) -> bool {
    let connection_lists_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"));
    connection_lists_upgrade && headers.contains_key(UPGRADE)
}

/// Headers that never cross a connection boundary regardless of what's being
/// relayed — RFC 9110 §7.6.1's connection-specific fields (minus `Connection`
/// and `Upgrade` themselves, handled separately below) plus the two
/// proxy-specific headers a forward proxy must never forward, plus
/// `content-length`/`transfer-encoding` (hyper recomputes body framing from
/// what it's given; copying either verbatim across a re-framed body is wrong).
const ALWAYS_STRIPPED_HOP_HEADERS: &[&str] = &[
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
];

/// Strip hop-by-hop headers from a request or response before it crosses a
/// connection boundary (agent -> doorman, or doorman -> upstream, and back).
///
/// Always removes [`ALWAYS_STRIPPED_HOP_HEADERS`], plus every header the
/// `Connection` header itself nominates — per RFC 9110 §7.6.1 an intermediary
/// must remove `Connection` and everything it lists before forwarding, and
/// without this an agent could smuggle an extra header past doorman's
/// rewrite by naming it in `Connection` instead of setting it directly.
///
/// For an Upgrade request/response (`is_upgrade` true), `Connection` and
/// `Upgrade` are left in place: doorman deliberately re-establishes the
/// handshake with the next hop rather than tunneling, so those two headers
/// are the mechanism, not hop-by-hop noise to discard. Any *other* header
/// nominated in `Connection` is still stripped even on an upgrade.
/// `Sec-WebSocket-*` headers are end-to-end, not hop-by-hop, and are never
/// touched here.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap, is_upgrade: bool) {
    // Collect nominated names before removing anything — removing headers
    // first would also destroy the Connection header we're reading from.
    let nominated: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|tok| tok.trim().to_ascii_lowercase())
        .filter(|tok| !tok.is_empty())
        .collect();

    for h in ALWAYS_STRIPPED_HOP_HEADERS {
        headers.remove(*h);
    }
    if !is_upgrade {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
    for name in nominated {
        if is_upgrade && name == "upgrade" {
            continue; // the handshake signal itself, not hop-by-hop noise
        }
        headers.remove(name.as_str());
    }
}

/// Relay a WebSocket/Upgrade handshake to the upstream. The credential has
/// already been validated against the host/method allowlist by `serve`. We
/// forward the (already-rewritten) request, and if the upstream answers 101 we
/// return our own 101 to the agent and splice the two upgraded connections
/// byte-for-byte until either side closes. Anything other than 101 from the
/// upstream is relayed back like a normal response.
#[allow(clippy::too_many_arguments)]
async fn relay_upgrade(
    server: &Server,
    entry: &Entry,
    target_host: String,
    cred_name: String,
    method: String,
    path: String,
    upstream_req: Request<Empty<Bytes>>,
    agent_upgrade: hyper::upgrade::OnUpgrade,
    started: Instant,
) -> Response<ProxyBody> {
    let mut upstream_response = match send_upstream(server, &target_host, entry, upstream_req).await
    {
        Ok(r) => r,
        Err(e) => {
            return deny(
                server,
                &target_host,
                &method,
                &path,
                Some(&cred_name),
                StatusCode::BAD_GATEWAY,
                Some(&format!("upstream: {}", e)),
                started,
            );
        }
    };

    if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Upstream declined the upgrade (404, 426, 401, …). Relay it back as a
        // normal response; the agent's upgrade simply never fires.
        return finish_response(
            server,
            upstream_response,
            cred_name,
            target_host,
            method,
            path,
            Arc::new(AtomicU64::new(0)),
            started,
        );
    }

    // 101 Switching Protocols. Take the upstream-side upgrade handle and copy
    // the handshake response headers back to the agent (minus the ones we
    // strip everywhere; `Connection`/`Upgrade` are kept since this response
    // *is* the handshake), then splice once both ends have upgraded.
    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
    let mut out_headers = upstream_response.headers().clone();
    for h in STRIPPED_RESPONSE_HEADERS {
        out_headers.remove(*h);
    }
    strip_hop_by_hop(&mut out_headers, true);

    let audit = Arc::clone(&server.audit);
    tokio::spawn(async move {
        let (agent_io, upstream_io) = match (agent_upgrade.await, upstream_upgrade.await) {
            (Ok(a), Ok(u)) => (a, u),
            (a, u) => {
                eprintln!(
                    "websocket upgrade did not complete (agent ok: {}, upstream ok: {})",
                    a.is_ok(),
                    u.is_ok()
                );
                return;
            }
        };
        let mut agent_io = TokioIo::new(agent_io);
        let mut upstream_io = TokioIo::new(upstream_io);
        // copy_bidirectional returns (a->b, b->a): (agent->upstream uploaded,
        // upstream->agent returned), matching bytes_in / bytes_out elsewhere.
        let (bytes_in, bytes_out) = match copy_bidirectional(&mut agent_io, &mut upstream_io).await
        {
            Ok(counts) => counts,
            Err(e) => {
                eprintln!("websocket relay ended with error: {}", e);
                (0, 0)
            }
        };
        let rec = Record {
            ts: audit::now_rfc3339(),
            cred: Some(&cred_name),
            host: &target_host,
            method: &method,
            path: &path,
            status: StatusCode::SWITCHING_PROTOCOLS.as_u16(),
            bytes_in,
            bytes_out,
            ms: started.elapsed().as_millis() as u64,
            decision: "allow",
            reason: None,
            protocol: Some("websocket"),
        };
        if let Err(e) = audit.write(&rec) {
            eprintln!("audit write failed for websocket relay: {}", e);
        }
    });

    let mut resp = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    if let Some(h) = resp.headers_mut() {
        *h = out_headers;
    }
    resp.body(empty_body()).expect("101 response build")
}

/// Relay an ordinary upstream response back to the agent: strip the sensitive
/// response headers, wrap the body so bytes are counted, and write the audit
/// line at end-of-stream. Shared by the normal request path and the
/// non-101 branch of an upgrade attempt.
#[allow(clippy::too_many_arguments)]
fn finish_response(
    server: &Server,
    upstream_response: Response<Incoming>,
    cred: String,
    host: String,
    method: String,
    path: String,
    bytes_in: Arc<AtomicU64>,
    started: Instant,
) -> Response<ProxyBody> {
    let (resp_parts, resp_body) = upstream_response.into_parts();
    let mut out_headers = resp_parts.headers.clone();
    for h in STRIPPED_RESPONSE_HEADERS {
        out_headers.remove(*h);
    }
    // This is always an ordinary (non-101) response, even when reached via
    // the "upstream declined the upgrade" branch of relay_upgrade.
    strip_hop_by_hop(&mut out_headers, false);
    let status = resp_parts.status;

    let bytes_out_counter = Arc::new(AtomicU64::new(0));
    let on_end = build_audit_callback(AuditCtx {
        audit: Arc::clone(&server.audit),
        started,
        cred,
        host,
        method,
        path,
        status: status.as_u16(),
        bytes_in,
        bytes_out: Arc::clone(&bytes_out_counter),
    });
    let resp_body = Counting {
        inner: resp_body,
        counter: bytes_out_counter,
        on_end: Some(on_end),
    };

    let mut resp = Response::builder().status(status);
    if let Some(h) = resp.headers_mut() {
        *h = out_headers;
    }
    resp.body(resp_body.boxed()).expect("response build")
}

/// An empty `ProxyBody`, used for the 101 response we hand back on a successful
/// WebSocket upgrade (the bytes after the handshake are spliced, not bodied).
fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|e: Infallible| match e {})
        .boxed()
}

/// Pull the upstream host out of an absolute-form URI authority, or fall
/// back to the `Host` header. Strips any port and any IPv6 brackets, then
/// canonicalizes (see [`canonicalize_host`]) so a bracketed or
/// differently-formatted IPv6 literal still matches the config allowlist.
fn resolve_target_host(req: &Request<Incoming>) -> Option<String> {
    resolve_target_host_from(req.uri(), req.headers())
}

/// The actual logic behind [`resolve_target_host`], taking the URI and
/// headers directly rather than a full `Request<Incoming>` — neither of
/// which unit tests can construct without a real hyper connection — so it's
/// testable in isolation.
fn resolve_target_host_from(uri: &hyper::Uri, headers: &hyper::HeaderMap) -> Option<String> {
    if let Some(host) = uri.host() {
        return Some(canonicalize_host(strip_v6_brackets(host)));
    }
    let host_hdr = headers.get(HOST)?.to_str().ok()?;
    let bare = if let Some(rest) = host_hdr.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally followed by `:port`.
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_hdr.split(':').next().unwrap_or(host_hdr)
    }
    .trim();
    if bare.is_empty() {
        return None;
    }
    Some(canonicalize_host(bare))
}

/// Strip the `[...]` an IPv6 literal wears in URI-authority and `Host`
/// syntax, when present. Any other input passes through unchanged.
fn strip_v6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

/// Format a host for the outgoing `Host` header. RFC 7230 requires an IPv6
/// literal to be wrapped in `[...]` there — unlike in config or in the
/// internal comparisons this module does throughout, which use the bare
/// canonical form. Anything else passes through unchanged.
fn host_header_value(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", host)
    } else {
        host.to_string()
    }
}

/// Look up the agent's credential selection — the `X-Doorman-Cred` header.
/// Exactly one such header must be present and non-empty.
fn find_credential(headers: &hyper::HeaderMap) -> Result<String, &'static str> {
    let mut iter = headers.get_all(CRED_HEADER).iter();
    let first = iter.next().ok_or("missing X-Doorman-Cred header")?;
    if iter.next().is_some() {
        return Err("multiple X-Doorman-Cred headers");
    }
    let s = first
        .to_str()
        .map_err(|_| "X-Doorman-Cred contains non-ASCII")?
        .trim();
    if s.is_empty() {
        return Err("empty X-Doorman-Cred value");
    }
    Ok(s.to_string())
}

async fn send_upstream<B>(
    server: &Server,
    target_host: &str,
    entry: &Entry,
    req: Request<B>,
) -> Result<Response<Incoming>, String>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<DynErr>,
{
    // Dial via the (host, port) tuple form rather than formatting a single
    // "host:port" string: for a bare IPv6 literal like `fd00::5`, string
    // concatenation would produce ambiguous colon soup ("fd00::5:8123").
    // Rust's resolver accepts a bare (unbracketed) IPv4/IPv6/hostname string
    // as the host half of this tuple directly.
    let tcp = TcpStream::connect((target_host, entry.port))
        .await
        .map_err(|e| format!("dial {}:{}: {}", target_host, entry.port, e))?;

    // Two transport paths. `entry.tls = true` is the historical case —
    // doorman wraps the TCP stream in TLS using either webpki roots or
    // (when the credential pins a SHA-256) the precomputed pinned config.
    // `entry.tls = false` is for LAN devices that expose plain HTTP;
    // we hand the raw TCP stream to hyper directly.
    match server.tls_for(entry) {
        Some(tls_cfg) => {
            let server_name: ServerName<'static> = ServerName::try_from(target_host.to_string())
                .map_err(|e| format!("server name {:?}: {}", target_host, e))?;
            let connector = TlsConnector::from(tls_cfg);
            let tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("tls connect: {}", e))?;
            let (mut sender, conn) = client_http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|e| format!("h1 handshake: {}", e))?;
            tokio::spawn(async move {
                let _ = conn.with_upgrades().await;
            });
            sender
                .send_request(req)
                .await
                .map_err(|e| format!("send: {}", e))
        }
        None => {
            let (mut sender, conn) = client_http1::handshake(TokioIo::new(tcp))
                .await
                .map_err(|e| format!("h1 handshake: {}", e))?;
            tokio::spawn(async move {
                let _ = conn.with_upgrades().await;
            });
            sender
                .send_request(req)
                .await
                .map_err(|e| format!("send: {}", e))
        }
    }
}

/// Special-case deny for "we couldn't even figure out where this request was
/// going" — neither absolute-form URI nor Host header.
fn deny_no_target(
    server: &Server,
    method: &hyper::Method,
    started: Instant,
) -> Response<ProxyBody> {
    deny(
        server,
        "<unknown>",
        method.as_str(),
        "<unknown>",
        None,
        StatusCode::BAD_REQUEST,
        Some("no target host (need absolute-form URI or Host header)"),
        started,
    )
}

/// Special-case deny for a CONNECT request. Doorman never tunnels, so this is
/// always a deterministic 405 naming the fix rather than whatever confusing
/// status the request would otherwise bottom out at.
fn deny_connect_not_supported(
    server: &Server,
    req: &Request<Incoming>,
    started: Instant,
) -> Response<ProxyBody> {
    let target_host = resolve_target_host(req).unwrap_or_else(|| "<unknown>".to_string());
    deny(
        server,
        &target_host,
        "CONNECT",
        &req.uri().to_string(),
        None,
        StatusCode::METHOD_NOT_ALLOWED,
        Some(
            "CONNECT is not supported; unset HTTPS_PROXY and use http:// URLs via \
             HTTP_PROXY (doorman re-originates TLS upstream)",
        ),
        started,
    )
}

#[allow(clippy::too_many_arguments)]
fn deny(
    server: &Server,
    target_host: &str,
    method: &str,
    path: &str,
    cred: Option<&str>,
    status: StatusCode,
    reason: Option<&str>,
    started: Instant,
) -> Response<ProxyBody> {
    let body = serde_json::json!({ "error": reason.unwrap_or("denied") }).to_string() + "\n";
    let body_bytes = Bytes::from(body);
    let bytes_out = body_bytes.len() as u64;

    let rec = Record {
        ts: audit::now_rfc3339(),
        cred,
        host: target_host,
        method,
        path,
        status: status.as_u16(),
        bytes_in: 0,
        bytes_out,
        ms: started.elapsed().as_millis() as u64,
        decision: "deny",
        reason,
        protocol: None,
    };
    if let Err(e) = server.audit.write(&rec) {
        return fail_closed_audit(e);
    }

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full_body(body_bytes))
        .unwrap()
}

fn fail_closed_audit(why: String) -> Response<ProxyBody> {
    eprintln!("audit unwritable, denying: {}", why);
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from_static(
            b"{\"error\":\"audit_unavailable\"}\n",
        )))
        .unwrap()
}

fn full_body(b: Bytes) -> ProxyBody {
    Full::new(b).map_err(|e: Infallible| match e {}).boxed()
}

/// Build the `rustls::ClientConfig` doorman uses to talk to upstreams that
/// don't pin a leaf cert. Roots come from `webpki-roots` (Mozilla's set,
/// statically linked) so there's no system-cert-store dependency.
pub fn upstream_tls() -> Arc<rustls::ClientConfig> {
    let _ = default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Build a per-credential `ClientConfig` for every entry that pins a leaf
/// cert. Pinned configs use [`PinVerifier`] in place of webpki chain
/// validation — the pin alone authenticates the upstream.
pub fn upstream_tls_pinned(config: &Config) -> Arc<HashMap<String, Arc<rustls::ClientConfig>>> {
    let _ = default_provider().install_default();
    let mut out = HashMap::new();
    for entry in &config.entries {
        if let Some(pin) = entry.tls_pin {
            let verifier = Arc::new(PinVerifier { pin });
            let cfg = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            out.insert(entry.name.clone(), Arc::new(cfg));
        }
    }
    Arc::new(out)
}

/// `ServerCertVerifier` that accepts exactly one specific leaf certificate,
/// identified by the SHA-256 of its DER encoding. Skips webpki chain
/// validation entirely — pin-or-fail is the whole point. Used for self-signed
/// LAN devices where the cert isn't issued by any public CA.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = sha256(end_entity.as_ref());
        if constant_time_eq(&actual, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "leaf cert SHA-256 does not match pin (got {})",
                hex(&actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Pinning binds the leaf identity; signature suites we accept are
        // whatever the (vetted) provider offers.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// SHA-256 of arbitrary bytes via ring (already in our dependency graph
/// through rustls). Returned as 32 raw bytes for direct comparison with
/// the pin.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(d.as_ref());
    buf
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// --------------------------------------------------------------------------
// Streaming body adapter: counts bytes as frames pass through, fires a
// once-only callback at end-of-stream or on drop.
// --------------------------------------------------------------------------

struct Counting<B> {
    inner: B,
    counter: Arc<AtomicU64>,
    on_end: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl<B> HttpBody for Counting<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Into<DynErr>,
{
    type Data = Bytes;
    type Error = DynErr;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let me = &mut *self;
        match Pin::new(&mut me.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    me.counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                if let Some(cb) = me.on_end.take() {
                    cb();
                }
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(None) => {
                if let Some(cb) = me.on_end.take() {
                    cb();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for Counting<B> {
    fn drop(&mut self) {
        if let Some(cb) = self.on_end.take() {
            cb();
        }
    }
}

struct AuditCtx {
    audit: Arc<Audit>,
    started: Instant,
    cred: String,
    host: String,
    method: String,
    path: String,
    status: u16,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
}

fn build_audit_callback(ctx: AuditCtx) -> Box<dyn FnOnce() + Send + Sync> {
    Box::new(move || {
        let rec = Record {
            ts: audit::now_rfc3339(),
            cred: Some(&ctx.cred),
            host: &ctx.host,
            method: &ctx.method,
            path: &ctx.path,
            status: ctx.status,
            bytes_in: ctx.bytes_in.load(Ordering::Relaxed),
            bytes_out: ctx.bytes_out.load(Ordering::Relaxed),
            ms: ctx.started.elapsed().as_millis() as u64,
            decision: "allow",
            reason: None,
            protocol: None,
        };
        if let Err(e) = ctx.audit.write(&rec) {
            eprintln!("audit write failed mid-stream: {}", e);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_host(value: &str) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(HOST, HeaderValue::try_from(value).unwrap());
        h
    }

    fn origin_form_uri() -> hyper::Uri {
        "/x".parse().unwrap()
    }

    #[test]
    fn strip_v6_brackets_removes_brackets_only_when_present() {
        assert_eq!(strip_v6_brackets("[fd00::5]"), "fd00::5");
        assert_eq!(strip_v6_brackets("fd00::5"), "fd00::5");
        assert_eq!(strip_v6_brackets("example.com"), "example.com");
        assert_eq!(
            strip_v6_brackets("[fd00::5"),
            "[fd00::5",
            "unclosed bracket left alone"
        );
    }

    #[test]
    fn host_header_value_brackets_only_ipv6() {
        assert_eq!(host_header_value("fd00::5"), "[fd00::5]");
        assert_eq!(host_header_value("::1"), "[::1]");
        assert_eq!(host_header_value("192.168.1.1"), "192.168.1.1");
        assert_eq!(host_header_value("api.github.com"), "api.github.com");
    }

    #[test]
    fn resolve_target_host_from_absolute_uri_strips_ipv6_brackets() {
        let uri: hyper::Uri = "http://[fd00::5]:8123/api/states".parse().unwrap();
        let headers = hyper::HeaderMap::new();
        assert_eq!(
            resolve_target_host_from(&uri, &headers),
            Some("fd00::5".to_string())
        );
    }

    #[test]
    fn resolve_target_host_from_host_header_bracketed_ipv6_with_port() {
        let headers = headers_with_host("[fd00::5]:8123");
        assert_eq!(
            resolve_target_host_from(&origin_form_uri(), &headers),
            Some("fd00::5".to_string())
        );
    }

    #[test]
    fn resolve_target_host_from_host_header_bracketed_ipv6_no_port() {
        let headers = headers_with_host("[fd00::5]");
        assert_eq!(
            resolve_target_host_from(&origin_form_uri(), &headers),
            Some("fd00::5".to_string())
        );
    }

    #[test]
    fn resolve_target_host_from_host_header_canonicalizes_ipv6() {
        // 0:0:0:0:0:0:0:1 and ::1 are the same address; the Host-header
        // fallback path must normalize the same way the URI-authority path
        // and the config loader do, so allowlist matching is consistent
        // regardless of which form the agent happened to send.
        let headers = headers_with_host("[0:0:0:0:0:0:0:1]:9000");
        assert_eq!(
            resolve_target_host_from(&origin_form_uri(), &headers),
            Some("::1".to_string())
        );
    }

    #[test]
    fn resolve_target_host_from_host_header_plain_hostname_with_port_unaffected() {
        // Pre-existing behavior for the common (non-IPv6) case must be
        // unchanged by any of this.
        let headers = headers_with_host("example.com:8080");
        assert_eq!(
            resolve_target_host_from(&origin_form_uri(), &headers),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn resolve_target_host_from_host_header_ipv4_with_port_unaffected() {
        let headers = headers_with_host("192.168.86.188:8123");
        assert_eq!(
            resolve_target_host_from(&origin_form_uri(), &headers),
            Some("192.168.86.188".to_string())
        );
    }
}
