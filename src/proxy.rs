// The proxy core. Listens on the configured TCP port, handles `CONNECT`,
// performs TLS interception with a per-host minted leaf cert, scans the inner
// request for a `{{name}}` placeholder, applies the inject template, and
// forwards to the upstream over a fresh TLS connection.
//
// Bodies stream through in both directions; doorman never buffers the
// payload. A small `Counting` body adapter wraps each direction so the audit
// log still gets accurate byte counts. The audit line for an allowed request
// is written when the response body finishes streaming to the agent (or, if
// the agent disconnects mid-stream, when the body wrapper is dropped).
//
// Things this module deliberately does NOT do, per spec §"How it works" and
// §"What I'd cut":
//   - follow redirects (3xx is returned to the agent verbatim)
//   - do anything with HTTP/2 (we negotiate http/1.1 only)
//   - cache or pool upstream connections (one TLS handshake per request;
//     boring is good)
//
// The one piece of clever response-side handling: stripping `Set-Cookie` and
// `WWW-Authenticate` from the response on the way back, because some
// upstreams reflect auth material in those.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderName, HeaderValue, HOST};
use hyper::server::conn::http1 as server_http1;
use hyper::client::conn::http1 as client_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::audit::{self, Audit, Record};
use crate::ca::Ca;
use crate::config::Config;

/// Headers stripped from every upstream response before it goes back to the
/// agent. The spec singles these out because some upstreams put session
/// material in them on auth errors.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &["set-cookie", "www-authenticate"];

/// Held by every connection handler. Cheap to clone (everything is Arc).
#[derive(Clone)]
pub struct Server {
    pub config: Arc<Config>,
    pub ca: Arc<Ca>,
    pub audit: Arc<Audit>,
    pub upstream_tls: Arc<rustls::ClientConfig>,
}

/// Unified outgoing-body type. Lets `serve` return either a streamed upstream
/// body or a small synchronous deny payload through the same signature.
type DynErr = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, DynErr>;

pub async fn run(server: Server, listen: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {}: {}", listen, e))?;
    eprintln!("doorman listening on {}", listen);
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
            if let Err(e) = handle_connection(s, stream, peer_addr).await {
                eprintln!("connection {}: {}", peer_addr, e);
            }
        });
    }
}

/// Read the agent's `CONNECT host:port HTTP/1.1` line, ack it, and hand the
/// underlying socket to the TLS-MITM path. Anything other than CONNECT gets a
/// 405 and the connection is closed; this proxy is HTTPS-only by design.
async fn handle_connection(
    server: Server,
    mut stream: TcpStream,
    _peer_addr: SocketAddr,
) -> Result<(), String> {
    let target = match read_connect_line(&mut stream).await? {
        Some(t) => t,
        None => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }
    };

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| format!("ack CONNECT: {}", e))?;

    let acceptor = TlsAcceptor::from(server.ca.server_config_for(&target.host)?);
    let tls = match acceptor.accept(stream).await {
        Ok(t) => t,
        Err(e) => return Err(format!("tls accept for {}: {}", target.host, e)),
    };

    let svc_target = Arc::new(target.clone());
    let svc_server = server.clone();
    let svc = service_fn(move |req: Request<Incoming>| {
        let server = svc_server.clone();
        let target = Arc::clone(&svc_target);
        async move { Ok::<_, Infallible>(serve(server, target, req).await) }
    });

    if let Err(e) = server_http1::Builder::new()
        .serve_connection(TokioIo::new(tls), svc)
        .await
    {
        // Clients drop connections all the time; demoted to a one-line note.
        eprintln!("inner http1 for {}: {}", target.host, e);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct Target {
    host: String,
    port: u16,
}

/// Pull the request line and headers off the wire and parse just enough to
/// confirm this is a `CONNECT host:port` and extract the target. Returns
/// `Ok(None)` if the method isn't CONNECT (caller should reject).
async fn read_connect_line(stream: &mut TcpStream) -> Result<Option<Target>, String> {
    let mut buf = [0u8; 8192];
    let mut n = 0;
    let header_end = loop {
        if n == buf.len() {
            return Err("CONNECT preamble too large".into());
        }
        let r = stream
            .read(&mut buf[n..])
            .await
            .map_err(|e| format!("read CONNECT: {}", e))?;
        if r == 0 {
            return Err("client closed before CONNECT".into());
        }
        n += r;
        if let Some(idx) = find_double_crlf(&buf[..n]) {
            break idx;
        }
    };

    let raw = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| "non-UTF8 CONNECT preamble".to_string())?;
    let first_line = raw.lines().next().ok_or("empty CONNECT preamble")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or("malformed request line")?;
    let target = parts.next().ok_or("malformed request line")?;
    let _version = parts.next().ok_or("malformed request line")?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Ok(None);
    }
    let (host, port) = parse_host_port(target)?;
    Ok(Some(Target {
        host: host.to_ascii_lowercase(),
        port,
    }))
}

fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    if let Some(idx) = s.rfind(':') {
        // IPv6 literals are wrapped in [], we don't bother supporting them.
        let host = &s[..idx];
        let port = s[idx + 1..]
            .parse::<u16>()
            .map_err(|_| format!("bad port in {:?}", s))?;
        if host.is_empty() {
            return Err(format!("empty host in {:?}", s));
        }
        Ok((host.to_string(), port))
    } else {
        Err(format!("CONNECT target {:?} has no port", s))
    }
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

/// One inner HTTP request. Returns whatever response the agent should see —
/// either a 4xx from doorman, or the (filtered) upstream response, streamed.
async fn serve(
    server: Server,
    target: Arc<Target>,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let started = Instant::now();
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let (mut parts, body) = req.into_parts();

    // Find the credential placeholder in the headers. We do this before
    // reading any body bytes so the deny path stays cheap.
    let (cred_name, placeholder_header) = match find_placeholder(&parts.headers) {
        Ok(v) => v,
        Err(reason) => {
            return deny(
                &server,
                &target,
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
                &target,
                method.as_str(),
                &path_and_query,
                Some(&cred_name),
                StatusCode::FORBIDDEN,
                Some("unknown credential"),
                started,
            );
        }
    };

    if !entry.host_allowed(&target.host) {
        return deny(
            &server,
            &target,
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
            &target,
            method.as_str(),
            &path_and_query,
            Some(&cred_name),
            StatusCode::FORBIDDEN,
            Some("method not allowlisted for credential"),
            started,
        );
    }

    // Rewrite headers in place: drop the agent's placeholder header (whatever
    // surrounding text it had is ignored — interpretation B), drop hop-by-hop
    // and length-shaped headers (hyper computes them from the body), then
    // inject the templated auth header and set Host.
    parts.headers.remove(&placeholder_header);
    for h in [
        "proxy-connection",
        "proxy-authorization",
        "transfer-encoding",
        "content-length",
    ] {
        parts.headers.remove(h);
    }
    let inject_name = HeaderName::try_from(entry.header_name.as_str())
        .expect("validated at config load");
    let inject_value = HeaderValue::try_from(entry.render())
        .expect("validated at config load");
    parts.headers.insert(inject_name, inject_value);
    parts.headers.insert(
        HOST,
        HeaderValue::try_from(target.host.as_str()).expect("host header"),
    );

    // Wrap the agent's request body so we count bytes as the upstream client
    // pulls them through; no buffering.
    let bytes_in_counter = Arc::new(AtomicU64::new(0));
    let req_body = Counting {
        inner: body,
        counter: Arc::clone(&bytes_in_counter),
        on_end: None,
    };
    let upstream_req = Request::from_parts(parts, req_body);

    let upstream_response = match send_upstream(&server, &target, upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            return deny(
                &server,
                &target,
                method.as_str(),
                &path_and_query,
                Some(&cred_name),
                StatusCode::BAD_GATEWAY,
                Some(format!("upstream: {}", e).leak()),
                started,
            );
        }
    };

    let (resp_parts, resp_body) = upstream_response.into_parts();
    let mut out_headers = resp_parts.headers.clone();
    for h in STRIPPED_RESPONSE_HEADERS {
        out_headers.remove(*h);
    }
    let status = resp_parts.status;

    // Wrap the upstream's response body so we count outbound bytes as hyper
    // streams them to the agent. The on_end callback writes one audit line
    // when the body is fully consumed (or the wrapper is dropped because the
    // agent went away).
    let bytes_out_counter = Arc::new(AtomicU64::new(0));
    let on_end = build_audit_callback(AuditCtx {
        audit: Arc::clone(&server.audit),
        started,
        cred: cred_name,
        host: target.host.clone(),
        method: method.as_str().to_string(),
        path: path_and_query,
        status: status.as_u16(),
        bytes_in: Arc::clone(&bytes_in_counter),
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

/// Locate the unique header value containing exactly one `{{name}}`
/// placeholder. Multiple placeholders, or none, is a deny.
fn find_placeholder(headers: &hyper::HeaderMap) -> Result<(String, HeaderName), &'static str> {
    let mut found: Option<(String, HeaderName)> = None;
    for (name, value) in headers.iter() {
        let v = match value.to_str() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let count = v.matches("{{").count();
        if count == 0 {
            continue;
        }
        if count > 1 {
            return Err("multiple placeholders in one header");
        }
        let Some(start) = v.find("{{") else {
            continue;
        };
        let Some(end_rel) = v[start + 2..].find("}}") else {
            return Err("malformed placeholder (missing '}}')");
        };
        let cred = v[start + 2..start + 2 + end_rel].trim();
        if cred.is_empty() {
            return Err("empty placeholder name");
        }
        if found.is_some() {
            return Err("multiple placeholders across headers");
        }
        found = Some((cred.to_string(), name.clone()));
    }
    found.ok_or("no credential placeholder in any header")
}

async fn send_upstream<B>(
    server: &Server,
    target: &Target,
    req: Request<B>,
) -> Result<Response<Incoming>, String>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<DynErr>,
{
    let addr = format!("{}:{}", target.host, target.port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("dial {}: {}", addr, e))?;
    let server_name: ServerName<'static> = ServerName::try_from(target.host.clone())
        .map_err(|e| format!("server name {:?}: {}", target.host, e))?;
    let connector = TlsConnector::from(Arc::clone(&server.upstream_tls));
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls connect: {}", e))?;
    let (mut sender, conn) = client_http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| format!("h1 handshake: {}", e))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| format!("send: {}", e))
}

#[allow(clippy::too_many_arguments)]
fn deny(
    server: &Server,
    target: &Target,
    method: &str,
    path: &str,
    cred: Option<&str>,
    status: StatusCode,
    reason: Option<&'static str>,
    started: Instant,
) -> Response<ProxyBody> {
    let body = match reason {
        Some(r) => format!("{{\"error\":\"{}\"}}\n", r),
        None => "{\"error\":\"denied\"}\n".to_string(),
    };
    let body_bytes = Bytes::from(body);
    let bytes_out = body_bytes.len() as u64;

    let rec = Record {
        ts: audit::now_rfc3339(),
        pid: -1,
        uid: -1,
        cred,
        host: &target.host,
        method,
        path,
        status: status.as_u16(),
        // We never read the request body on a deny — counting it here would
        // mean draining bytes from the agent that we're about to refuse.
        bytes_in: 0,
        bytes_out,
        ms: started.elapsed().as_millis() as u64,
        decision: "deny",
        reason,
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

/// Build the `rustls::ClientConfig` doorman uses to talk to upstreams.
/// Roots come from `webpki-roots` (Mozilla's set, statically linked) so
/// there's no system-cert-store dependency.
pub fn upstream_tls() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
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

/// Owned context an end-of-stream callback needs to write the audit line.
/// Pulled out so the closure isn't a wall of captures.
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
            pid: -1,
            uid: -1,
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
        };
        if let Err(e) = ctx.audit.write(&rec) {
            eprintln!("audit write failed mid-stream: {}", e);
        }
    })
}
