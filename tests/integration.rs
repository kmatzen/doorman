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
