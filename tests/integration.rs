// Integration tests for the proxy. Spins up a mock TLS upstream that
// captures every request it sees, points doorman at it, and asserts that
// each path through `serve()` does what it should — the security boundary
// in particular: the cred header is stripped, the auth header comes from
// the inject template (not the agent), denies short-circuit before the
// upstream is touched, and the response stripping kicks in.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, Ia5String, IsCa, KeyPair,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use doorman::audit::Audit;
use doorman::config::{Config, Entry};
use doorman::proxy::{serve_listener, Server};

// --------------------------------------------------------------------------
// Test CA: mints a leaf cert for the mock upstream and gives doorman a
// rustls::ClientConfig that trusts it.
// --------------------------------------------------------------------------

struct TestCa {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl TestCa {
    fn generate() -> Self {
        // Safe to call repeatedly; subsequent installs return Err.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "doorman test CA");
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("ca keypair");
        let cert = params.self_signed(&key).expect("self-sign ca");
        Self { cert, key }
    }

    fn server_config_for(&self, hostname: &str) -> Arc<rustls::ServerConfig> {
        let leaf_key = KeyPair::generate().expect("leaf keypair");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName(
            Ia5String::try_from(hostname.to_string()).unwrap(),
        )];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .expect("sign leaf");
        let cert_der = CertificateDer::from(leaf.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der()).expect("encode key");
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        Arc::new(cfg)
    }

    fn client_config(&self) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.cert.der().to_vec()))
            .expect("trust ca");
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

// --------------------------------------------------------------------------
// Mock upstream: a real TLS HTTP/1.1 server that captures requests.
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

type Captured = Arc<Mutex<Vec<CapturedRequest>>>;

async fn spawn_mock_upstream(server_tls: Arc<rustls::ServerConfig>) -> (SocketAddr, Captured) {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured_for_server = Arc::clone(&captured);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = TlsAcceptor::from(server_tls.clone());
            let captured = captured_for_server.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let captured = captured.clone();
                    async move {
                        let (parts, _body) = req.into_parts();
                        let mut headers = HashMap::new();
                        for (k, v) in parts.headers.iter() {
                            headers.insert(
                                k.as_str().to_lowercase(),
                                v.to_str().unwrap_or("").to_string(),
                            );
                        }
                        captured.lock().unwrap().push(CapturedRequest {
                            method: parts.method.to_string(),
                            path: parts.uri.path().to_string(),
                            headers,
                        });
                        // Include headers we expect doorman to strip on the
                        // way back, plus a canary that should pass through.
                        let response = Response::builder()
                            .status(200)
                            .header("set-cookie", "session=secret")
                            .header("www-authenticate", "Bearer realm=fake")
                            .header("connection", "close")
                            .header("keep-alive", "timeout=5")
                            .header("x-canary", "untouched")
                            .body(Full::new(Bytes::from_static(b"upstream-ok")))
                            .unwrap();
                        Ok::<_, hyper::Error>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (addr, captured)
}

// --------------------------------------------------------------------------
// Doorman under test: bind on a random port, serve in a background task.
// --------------------------------------------------------------------------

async fn spawn_doorman(
    entries: Vec<Entry>,
    upstream_tls: Arc<rustls::ClientConfig>,
) -> SocketAddr {
    spawn_doorman_full(entries, upstream_tls, Arc::new(HashMap::new())).await
}

async fn spawn_doorman_full(
    entries: Vec<Entry>,
    upstream_tls: Arc<rustls::ClientConfig>,
    upstream_tls_pinned: Arc<HashMap<String, Arc<rustls::ClientConfig>>>,
) -> SocketAddr {
    static N: AtomicU64 = AtomicU64::new(0);
    let i = N.fetch_add(1, Ordering::Relaxed);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let audit_path = std::env::temp_dir()
        .join(format!("doorman_int_{}_{}.log", std::process::id(), i));
    let _ = std::fs::remove_file(&audit_path);
    let audit = Audit::open(&audit_path).expect("open audit log");
    let server = Server {
        config: Arc::new(Config { entries }),
        audit: Arc::new(audit),
        upstream_tls,
        upstream_tls_pinned,
    };
    tokio::spawn(async move {
        let _ = serve_listener(server, listener).await;
    });
    addr
}

fn entry(
    name: &str,
    secret: &str,
    header: &str,
    hosts: &[&str],
    methods: &[&str],
    port: u16,
) -> Entry {
    entry_full(name, secret, header, hosts, methods, port, true, None)
}

#[allow(clippy::too_many_arguments)]
fn entry_full(
    name: &str,
    secret: &str,
    header: &str,
    hosts: &[&str],
    methods: &[&str],
    port: u16,
    tls: bool,
    tls_pin: Option<[u8; 32]>,
) -> Entry {
    let inject = format!("{}: Bearer {{}}", header);
    let (header_name, prefix, suffix) = parse_inject(&inject);
    Entry {
        name: name.into(),
        secret: secret.into(),
        header_name,
        header_prefix: prefix,
        header_suffix: suffix,
        hosts: hosts.iter().map(|s| s.to_string()).collect(),
        methods: methods.iter().map(|s| s.to_uppercase()).collect(),
        port,
        tls,
        tls_pin,
    }
}

fn parse_inject(s: &str) -> (String, String, String) {
    let colon = s.find(':').unwrap();
    let name = s[..colon].trim().to_string();
    let value = s[colon + 1..].trim_start();
    let slot = value.find("{}").unwrap();
    (name, value[..slot].to_string(), value[slot + 2..].to_string())
}

// --------------------------------------------------------------------------
// Test client: sends an origin-form HTTP/1.1 request to doorman with a Host
// header. (Real agents typically send absolute-form via HTTP_PROXY; doorman
// accepts both, and origin-form is simpler to construct here.)
// --------------------------------------------------------------------------

async fn request(
    proxy_addr: SocketAddr,
    method: Method,
    target_host: &str,
    path: &str,
    extra_headers: Vec<(&str, &str)>,
) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, target_host);
    for (k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, body)
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[tokio::test]
async fn allow_path_injects_secret_and_strips_cred_header() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET_VALUE",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/some/path",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"upstream-ok");

    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/some/path");
    assert_eq!(req.headers.get("authorization").map(String::as_str), Some("Bearer SECRET_VALUE"));
    assert!(!req.headers.contains_key("x-doorman-cred"), "cred header must not leak");
}

#[tokio::test]
async fn connection_header_and_its_nominated_headers_are_stripped_from_requests() {
    // RFC 9110 §7.6.1: an intermediary must remove `Connection` and every
    // header it nominates before forwarding. Without this, an agent could
    // smuggle an extra header past doorman's rewrite by naming it in
    // `Connection` instead of setting it directly, or leave stale connection
    // management (`Connection: close`) on a request destined for a brand new
    // upstream connection.
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET_VALUE",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, _) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![
            ("X-Doorman-Cred", "test"),
            ("Connection", "close, X-Custom"),
            ("X-Custom", "should-not-leak"),
            ("Keep-Alive", "timeout=5"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert!(!req.headers.contains_key("connection"), "Connection must be stripped");
    assert!(
        !req.headers.contains_key("x-custom"),
        "a header only named via Connection must still be stripped"
    );
    assert!(!req.headers.contains_key("keep-alive"), "Keep-Alive must be stripped");
    // The credential header injection itself is unaffected by this.
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer SECRET_VALUE")
    );
}

#[tokio::test]
async fn agent_authorization_header_is_overwritten() {
    // Even if the agent sends its own Authorization header (no placeholder
    // syntax involved at all), doorman's inject template overwrites it.
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "REAL_SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, _) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![
            ("Authorization", "Bearer FAKE_INJECTED_BY_AGENT"),
            ("X-Doorman-Cred", "test"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert_eq!(req.headers.get("authorization").map(String::as_str), Some("Bearer REAL_SECRET"));
}

#[tokio::test]
async fn deny_unknown_credential() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "real",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "fake")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(std::str::from_utf8(&body).unwrap().contains("unknown credential"));
    assert!(captured.lock().unwrap().is_empty(), "upstream must not be contacted on deny");
}

#[tokio::test]
async fn deny_disallowed_host() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["allowed.example"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(std::str::from_utf8(&body).unwrap().contains("host not allowlisted"));
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deny_disallowed_method() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &["GET"],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::POST,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(std::str::from_utf8(&body).unwrap().contains("method not allowlisted"));
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deny_missing_cred_header() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(proxy, Method::GET, "localhost", "/x", vec![]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(std::str::from_utf8(&body).unwrap().contains("missing X-Doorman-Cred"));
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deny_connect_even_with_valid_credential() {
    // CONNECT is the classic HTTPS_PROXY / wss:// misconfiguration. Doorman
    // never tunnels, so this must be rejected deterministically — even when
    // the request carries a credential valid for an allowlisted host, which
    // would otherwise fall through to send_upstream and forward a method
    // doorman was never built to relay.
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::CONNECT,
        "localhost",
        "/",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(std::str::from_utf8(&body).unwrap().contains("CONNECT is not supported"));
    assert!(
        captured.lock().unwrap().is_empty(),
        "upstream must not be contacted for a CONNECT request"
    );
}

#[tokio::test]
async fn deny_connect_without_credential() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(proxy, Method::CONNECT, "localhost", "/", vec![]).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(std::str::from_utf8(&body).unwrap().contains("CONNECT is not supported"));
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deny_multiple_cred_headers() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "test"), ("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(std::str::from_utf8(&body).unwrap().contains("multiple"));
    assert!(captured.lock().unwrap().is_empty());
}

#[tokio::test]
async fn upstream_dial_failure_produces_valid_json_error_body() {
    // No listener on this port: send_upstream's dial fails and its OS error
    // text (which can contain arbitrary characters, e.g. quotes on some
    // platforms/paths) is interpolated into the deny reason. The body must
    // still be valid JSON, not hand-formatted with unescaped interpolation.
    let unused_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            unused_port,
        )],
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
            .into(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|e| panic!("body not valid JSON: {} ({:?})", e, body));
    assert!(parsed["error"].as_str().unwrap().contains("upstream"));
}

#[tokio::test]
async fn response_strips_set_cookie_and_www_authenticate() {
    let ca = TestCa::generate();
    let (upstream_addr, _) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, headers, _) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("set-cookie").is_none(), "set-cookie should be stripped");
    assert!(headers.get("www-authenticate").is_none(), "www-authenticate should be stripped");
    assert_eq!(
        headers.get("x-canary").map(|v| v.to_str().unwrap()),
        Some("untouched"),
        "non-sensitive headers must pass through"
    );
}

#[tokio::test]
async fn response_strips_hop_by_hop_headers() {
    // The mock upstream's response (spawn_mock_upstream) also carries
    // Connection: close and Keep-Alive: timeout=5 — connection-management
    // headers that describe doorman's connection to the *upstream*, not the
    // agent's connection to doorman, and must not be relayed through.
    let ca = TestCa::generate();
    let (upstream_addr, _) = spawn_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "test",
            "SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let (status, headers, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/x",
        vec![("X-Doorman-Cred", "test")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"upstream-ok", "body still relayed correctly");
    assert!(headers.get("connection").is_none(), "Connection should be stripped");
    assert!(headers.get("keep-alive").is_none(), "Keep-Alive should be stripped");
    assert_eq!(
        headers.get("x-canary").map(|v| v.to_str().unwrap()),
        Some("untouched"),
        "non-hop-by-hop headers must still pass through"
    );
}

// --------------------------------------------------------------------------
// Plaintext upstream (`tls: false`): the agent still talks loopback HTTP to
// doorman, but doorman dials the upstream over plain TCP and skips the TLS
// handshake. Models a LAN device like Home Assistant on http://host:8123.
// --------------------------------------------------------------------------

async fn spawn_plaintext_mock_upstream() -> (SocketAddr, Captured) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    spawn_plaintext_mock_upstream_on(listener)
}

/// Same mock as [`spawn_plaintext_mock_upstream`], but on a caller-supplied
/// listener — lets a test bind an IPv6 loopback listener itself and decide
/// what to do if that fails (some sandboxed environments have no IPv6
/// support at all), rather than this helper unconditionally binding IPv4.
fn spawn_plaintext_mock_upstream_on(listener: TcpListener) -> (SocketAddr, Captured) {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let addr = listener.local_addr().unwrap();
    let captured_for_server = Arc::clone(&captured);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let captured = captured_for_server.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let captured = captured.clone();
                    async move {
                        let (parts, _body) = req.into_parts();
                        let mut headers = HashMap::new();
                        for (k, v) in parts.headers.iter() {
                            headers.insert(
                                k.as_str().to_lowercase(),
                                v.to_str().unwrap_or("").to_string(),
                            );
                        }
                        captured.lock().unwrap().push(CapturedRequest {
                            method: parts.method.to_string(),
                            path: parts.uri.path().to_string(),
                            headers,
                        });
                        let response = Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from_static(b"plaintext-ok")))
                            .unwrap();
                        Ok::<_, hyper::Error>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, captured)
}

#[tokio::test]
async fn plaintext_upstream_injects_secret_and_skips_tls() {
    let (upstream_addr, captured) = spawn_plaintext_mock_upstream().await;
    let proxy = spawn_doorman(
        vec![entry_full(
            "hass",
            "ha_tok",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
            false,
            None,
        )],
        // upstream_tls is unused on this code path, but Server still needs
        // a placeholder. Use the default webpki one.
        doorman::proxy::upstream_tls(),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/api/states",
        vec![("X-Doorman-Cred", "hass")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"plaintext-ok");

    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/states");
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer ha_tok"),
        "secret must still be injected on plaintext upstream"
    );
    assert!(
        !req.headers.contains_key("x-doorman-cred"),
        "cred header must not leak even on plaintext upstream"
    );
}

#[tokio::test]
async fn ipv6_loopback_upstream_works_end_to_end() {
    // Requires the kernel/container to support IPv6 at all -- some
    // sandboxed environments disable it entirely (AF_INET6 unsupported),
    // in which case this skips rather than failing. Real hosts and typical
    // CI runners (including this repo's own ubuntu-latest/macos-latest)
    // have IPv6 loopback, so this exercises the real dial path there.
    let listener = match TcpListener::bind("[::1]:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "skipping ipv6_loopback_upstream_works_end_to_end: IPv6 unavailable ({})",
                e
            );
            return;
        }
    };
    let (upstream_addr, captured) = spawn_plaintext_mock_upstream_on(listener);

    let proxy = spawn_doorman(
        vec![entry_full(
            "hass6",
            "ha_tok_v6",
            "Authorization",
            &["::1"],
            &[],
            upstream_addr.port(),
            false,
            None,
        )],
        doorman::proxy::upstream_tls(),
    )
    .await;

    // The agent's Host header uses bracket notation, as real clients would
    // for an IPv6 literal (e.g. `curl http://[::1]:PORT/...`).
    let (status, _, body) = request(
        proxy,
        Method::GET,
        "[::1]",
        "/api/states",
        vec![("X-Doorman-Cred", "hass6")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"plaintext-ok");

    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer ha_tok_v6")
    );
    assert!(!req.headers.contains_key("x-doorman-cred"));
}

// --------------------------------------------------------------------------
// SHA-256 cert pinning: doorman skips webpki and accepts only the leaf
// whose DER hashes to the configured pin. Models a self-signed LAN device
// (UniFi, Hue bridge).
// --------------------------------------------------------------------------

/// Re-mint a fresh CA + leaf and return both the server config the upstream
/// should use and the leaf DER bytes so the test can compute the pin.
fn fresh_self_signed(hostname: &str) -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let leaf_key = KeyPair::generate().expect("leaf keypair");
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName(
        Ia5String::try_from(hostname.to_string()).unwrap(),
    )];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;
    let leaf = params.self_signed(&leaf_key).expect("self-sign leaf");
    let leaf_der = leaf.der().to_vec();
    let cert_der = rustls::pki_types::CertificateDer::from(leaf_der.clone());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
        .expect("encode key");
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config");
    (Arc::new(cfg), leaf_der)
}

fn sha256_hex(bytes: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[tokio::test]
async fn pinned_cert_allows_self_signed_upstream() {
    let (server_cfg, leaf_der) = fresh_self_signed("localhost");
    let (upstream_addr, captured) = spawn_mock_upstream(server_cfg).await;
    let pin = sha256_hex(&leaf_der);

    let entries = vec![entry_full(
        "unifi",
        "ui_tok",
        "X-API-Key",
        &["localhost"],
        &[],
        upstream_addr.port(),
        true,
        Some(pin),
    )];
    let mut pinned_map: HashMap<String, Arc<rustls::ClientConfig>> = HashMap::new();
    // Build the pinned ClientConfig the same way the production code does.
    let stub_cfg = Config {
        entries: entries.clone(),
    };
    let built = doorman::proxy::upstream_tls_pinned(&stub_cfg);
    for (k, v) in built.iter() {
        pinned_map.insert(k.clone(), Arc::clone(v));
    }
    let proxy = spawn_doorman_full(
        entries,
        doorman::proxy::upstream_tls(),
        Arc::new(pinned_map),
    )
    .await;

    let (status, _, body) = request(
        proxy,
        Method::GET,
        "localhost",
        "/proxy/network/api/s/default/stat/device",
        vec![("X-Doorman-Cred", "unifi")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"upstream-ok");

    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        req.headers.get("x-api-key").map(String::as_str),
        Some("Bearer ui_tok"),
    );
}

#[tokio::test]
async fn pinned_cert_rejects_mismatched_leaf() {
    // The upstream presents one self-signed cert; the credential pins a
    // different (random) SHA-256. Connection must fail upstream-side; agent
    // receives a 502.
    let (server_cfg, _real_leaf) = fresh_self_signed("localhost");
    let (upstream_addr, captured) = spawn_mock_upstream(server_cfg).await;
    let wrong_pin = [0xde; 32];

    let entries = vec![entry_full(
        "unifi",
        "ui_tok",
        "X-API-Key",
        &["localhost"],
        &[],
        upstream_addr.port(),
        true,
        Some(wrong_pin),
    )];
    let stub_cfg = Config {
        entries: entries.clone(),
    };
    let built = doorman::proxy::upstream_tls_pinned(&stub_cfg);
    let mut pinned_map: HashMap<String, Arc<rustls::ClientConfig>> = HashMap::new();
    for (k, v) in built.iter() {
        pinned_map.insert(k.clone(), Arc::clone(v));
    }
    let proxy = spawn_doorman_full(
        entries,
        doorman::proxy::upstream_tls(),
        Arc::new(pinned_map),
    )
    .await;

    // Use a short timeout so a hung handshake doesn't stall the test suite.
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        request(
            proxy,
            Method::GET,
            "localhost",
            "/x",
            vec![("X-Doorman-Cred", "unifi")],
        ),
    )
    .await
    .expect("timed out");
    assert_eq!(res.0, StatusCode::BAD_GATEWAY);
    assert!(
        captured.lock().unwrap().is_empty(),
        "no upstream request should be served on pin mismatch"
    );
}

// --------------------------------------------------------------------------
// WebSocket / HTTP Upgrade relay. doorman injects the credential on the
// handshake, forwards it, and once the upstream returns 101 it splices the two
// connections byte-for-byte. The mock upstream below speaks the handshake by
// hand and then echoes raw bytes — matching doorman's byte-splice model (it
// does not parse WS frames).
// --------------------------------------------------------------------------

/// A TLS upstream that completes an HTTP/1.1 Upgrade handshake (captures the
/// request head, replies 101) and then echoes every subsequent byte.
async fn spawn_ws_mock_upstream(server_tls: Arc<rustls::ServerConfig>) -> (SocketAddr, Captured) {
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captured_for_server = Arc::clone(&captured);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = TlsAcceptor::from(server_tls.clone());
            let captured = captured_for_server.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                // Read the request head (up to CRLFCRLF). The client waits for
                // the 101 before sending payload, so nothing trails the head.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match tls.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => return,
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&buf);
                let mut lines = text.split("\r\n");
                let mut request_line = lines.next().unwrap_or("").split_whitespace();
                let method = request_line.next().unwrap_or("").to_string();
                let path = request_line.next().unwrap_or("").to_string();
                let mut headers = HashMap::new();
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        headers.insert(k.trim().to_lowercase(), v.trim().to_string());
                    }
                }
                captured
                    .lock()
                    .unwrap()
                    .push(CapturedRequest { method, path, headers });

                let resp = "HTTP/1.1 101 Switching Protocols\r\n\
                            Upgrade: websocket\r\n\
                            Connection: Upgrade\r\n\
                            Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                            set-cookie: should-be-stripped=1\r\n\r\n";
                if tls.write_all(resp.as_bytes()).await.is_err() {
                    return;
                }
                // Echo until the client closes.
                loop {
                    match tls.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if tls.write_all(&tmp[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    (addr, captured)
}

/// Read from a raw socket until the HTTP head terminator, returning it as text.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

const WS_REQUEST_TMPL: &str = "GET {PATH} HTTP/1.1\r\n\
     Host: {HOST}\r\n\
     X-Doorman-Cred: {CRED}\r\n\
     Connection: Upgrade\r\n\
     Upgrade: websocket\r\n\
     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
     Sec-WebSocket-Version: 13\r\n\r\n";

fn ws_request(path: &str, host: &str, cred: &str) -> String {
    WS_REQUEST_TMPL
        .replace("{PATH}", path)
        .replace("{HOST}", host)
        .replace("{CRED}", cred)
}

#[tokio::test]
async fn websocket_upgrade_relays_splices_and_injects_credential() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_ws_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "wscred",
            "WS_SECRET",
            "Authorization",
            &["localhost"],
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(ws_request("/chat", "localhost", "wscred").as_bytes())
        .await
        .unwrap();

    // doorman returns 101, stripped of sensitive response headers.
    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 101"), "expected 101, got: {:?}", head);
    assert!(
        !head.to_lowercase().contains("set-cookie"),
        "set-cookie must be stripped from the 101: {:?}",
        head
    );

    // The byte-splice works in both directions.
    stream.write_all(b"hello-ws").await.unwrap();
    let mut echo = [0u8; 8];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello-ws");

    // The upstream saw the injected credential and not the cred header, and the
    // upgrade headers reached it intact.
    let req = captured.lock().unwrap().last().cloned().unwrap();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/chat");
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer WS_SECRET")
    );
    assert!(
        !req.headers.contains_key("x-doorman-cred"),
        "cred header must not leak upstream"
    );
    assert_eq!(
        req.headers.get("upgrade").map(String::as_str),
        Some("websocket")
    );
}

#[tokio::test]
async fn websocket_upgrade_to_disallowed_host_is_denied() {
    let ca = TestCa::generate();
    let (upstream_addr, captured) = spawn_ws_mock_upstream(ca.server_config_for("localhost")).await;
    let proxy = spawn_doorman(
        vec![entry(
            "wscred",
            "WS_SECRET",
            "Authorization",
            &["allowed.example"], // localhost is NOT allowlisted
            &[],
            upstream_addr.port(),
        )],
        ca.client_config(),
    )
    .await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(ws_request("/chat", "localhost", "wscred").as_bytes())
        .await
        .unwrap();

    let head = read_head(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 403"), "expected 403, got: {:?}", head);
    assert!(
        captured.lock().unwrap().is_empty(),
        "upstream must not be contacted when the host is denied"
    );
}
