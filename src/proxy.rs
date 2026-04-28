// The proxy core. Plain HTTP/1.1 forward proxy: agents speak plaintext to
// doorman, doorman speaks TLS to the upstream. The agent's request URI may
// be in absolute form (`GET http://api.github.com/path HTTP/1.1`) or in
// origin form with a `Host:` header — both are accepted.
//
// Request flow:
//   - extract upstream host (from URI authority or `Host` header)
//   - locate the `{{name}}` placeholder in some request header
//   - look up the credential, validate host and method against the policy
//   - drop the placeholder header and any hop-by-hop headers; inject the
//     templated auth header per the credential's `inject` template
//   - TLS-connect to the upstream on port 443; stream the request body
//     through; stream the response body back; strip `Set-Cookie` and
//     `WWW-Authenticate` from the response
//   - write one audit-log line at end-of-stream (or on drop)
//
// What this module deliberately does NOT do:
//   - terminate TLS on the agent side (no CA, no per-host leaf certs)
//   - support HTTPS_PROXY / `CONNECT` (the agent must use HTTP_PROXY and
//     `http://` URLs)
//   - follow redirects (3xx returned to the agent verbatim)
//   - HTTP/2 (HTTP/1.1 only, on both sides)
//   - cache or pool upstream connections (one TLS handshake per request)

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
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use crate::audit::{self, Audit, Record};
use crate::config::Config;

/// Headers stripped from every upstream response before it goes back to the
/// agent. Some upstreams put session material in these on auth errors.
const STRIPPED_RESPONSE_HEADERS: &[&str] = &["set-cookie", "www-authenticate"];

/// Header the agent sets to name the credential it wants doorman to inject.
/// Doorman strips this header from the request before forwarding upstream.
const CRED_HEADER: &str = "x-doorman-cred";

/// Always-on TLS port for the upstream. The agent's URI port (if any) is
/// ignored; an MVP that talks to "real" APIs only ever needs 443. If you
/// need a different port per credential, add it to the config later.
const UPSTREAM_TLS_PORT: u16 = 443;

#[derive(Clone)]
pub struct Server {
    pub config: Arc<Config>,
    pub audit: Arc<Audit>,
    pub upstream_tls: Arc<rustls::ClientConfig>,
}

type DynErr = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = BoxBody<Bytes, DynErr>;

pub async fn run(server: Server, listen: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {}: {}", listen, e))?;
    eprintln!("doorman listening on {} (plain HTTP forward proxy)", listen);
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
        .await
        .map_err(|e| format!("h1: {}", e))
}

/// One inbound HTTP request from the agent. Returns either a doorman 4xx/5xx
/// or the streamed upstream response.
async fn serve(server: Server, req: Request<Incoming>) -> Response<ProxyBody> {
    let started = Instant::now();
    let method = req.method().clone();

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

    // Rewrite headers: drop the cred-name header (it's a doorman-internal
    // signal and must not leak upstream), drop hop-by-hop and length-shaped
    // headers (hyper computes them from the body), inject the templated auth
    // header, and set Host to the canonical target.
    parts.headers.remove(CRED_HEADER);
    for h in [
        "proxy-connection",
        "proxy-authorization",
        "transfer-encoding",
        "content-length",
    ] {
        parts.headers.remove(h);
    }
    let inject_name =
        HeaderName::try_from(entry.header_name.as_str()).expect("validated at config load");
    let inject_value =
        HeaderValue::try_from(entry.render()).expect("validated at config load");
    parts.headers.insert(inject_name, inject_value);
    parts.headers.insert(
        HOST,
        HeaderValue::try_from(target_host.as_str()).expect("host header"),
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

    let bytes_in_counter = Arc::new(AtomicU64::new(0));
    let req_body = Counting {
        inner: body,
        counter: Arc::clone(&bytes_in_counter),
        on_end: None,
    };
    let upstream_req = Request::from_parts(parts, req_body);

    let upstream_response = match send_upstream(&server, &target_host, upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            return deny(
                &server,
                &target_host,
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

    let bytes_out_counter = Arc::new(AtomicU64::new(0));
    let on_end = build_audit_callback(AuditCtx {
        audit: Arc::clone(&server.audit),
        started,
        cred: cred_name,
        host: target_host,
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

/// Pull the upstream host out of an absolute-form URI authority, or fall
/// back to the `Host` header. Strips any port. Lowercased.
fn resolve_target_host(req: &Request<Incoming>) -> Option<String> {
    if let Some(host) = req.uri().host() {
        return Some(host.to_ascii_lowercase());
    }
    let host_hdr = req.headers().get(HOST)?.to_str().ok()?;
    let bare = host_hdr.split(':').next().unwrap_or(host_hdr).trim();
    if bare.is_empty() {
        return None;
    }
    Some(bare.to_ascii_lowercase())
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
    req: Request<B>,
) -> Result<Response<Incoming>, String>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<DynErr>,
{
    let addr = format!("{}:{}", target_host, UPSTREAM_TLS_PORT);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("dial {}: {}", addr, e))?;
    let server_name: ServerName<'static> = ServerName::try_from(target_host.to_string())
        .map_err(|e| format!("server name {:?}: {}", target_host, e))?;
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

#[allow(clippy::too_many_arguments)]
fn deny(
    server: &Server,
    target_host: &str,
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
        };
        if let Err(e) = ctx.audit.write(&rec) {
            eprintln!("audit write failed mid-stream: {}", e);
        }
    })
}
