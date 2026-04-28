// CA generation and on-the-fly leaf cert minting.
//
// `doorman init` writes a CA key+cert under the state dir (mode 0400 on the
// key). At run time the proxy mints a leaf cert per upstream host on demand
// and caches the resulting `rustls::ServerConfig`, so that every CONNECT to
// the same host reuses one cert instead of generating a fresh keypair per
// request.
//
// Boring choices throughout: no EC negotiation knobs, no SAN wildcards, no
// per-cert expiry tuning. Leaf certs live one year and that's that.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const CA_CRT: &str = "ca.crt";
const CA_KEY: &str = "ca.key";

/// Generate a fresh self-signed CA and write the cert + key into `dir`.
/// The cert is world-readable (so the agent's trust store can load it); the
/// key is mode 0400 and owned by whoever ran `doorman init`.
pub fn generate(dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "doorman local CA");
    dn.push(DnType::OrganizationName, "doorman");
    params.distinguished_name = dn;

    let key = KeyPair::generate().map_err(|e| format!("ca keypair: {}", e))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("self-sign ca: {}", e))?;

    let crt_path = dir.join(CA_CRT);
    let key_path = dir.join(CA_KEY);
    fs::write(&crt_path, cert.pem()).map_err(|e| format!("write {}: {}", crt_path.display(), e))?;
    fs::write(&key_path, key.serialize_pem()).map_err(|e| format!("write {}: {}", key_path.display(), e))?;
    let mut perms = fs::metadata(&key_path).unwrap().permissions();
    perms.set_mode(0o400);
    fs::set_permissions(&key_path, perms)
        .map_err(|e| format!("chmod {}: {}", key_path.display(), e))?;

    Ok(crt_path)
}

/// Loaded CA and a cache of per-host TLS server configs.
pub struct Ca {
    issuer_cert: rcgen::Certificate,
    issuer_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl Ca {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let crt_pem = fs::read_to_string(dir.join(CA_CRT))
            .map_err(|e| format!("read ca cert: {}", e))?;
        let key_pem = fs::read_to_string(dir.join(CA_KEY))
            .map_err(|e| format!("read ca key: {}", e))?;
        let key = KeyPair::from_pem(&key_pem).map_err(|e| format!("parse ca key: {}", e))?;
        let params = CertificateParams::from_ca_cert_pem(&crt_pem)
            .map_err(|e| format!("parse ca cert: {}", e))?;
        let issuer_cert = params
            .self_signed(&key)
            .map_err(|e| format!("rebuild ca cert: {}", e))?;
        Ok(Ca {
            issuer_cert,
            issuer_key: key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Return a `ServerConfig` whose leaf cert is valid for `host`. The
    /// configs are cached so repeat CONNECTs to the same upstream don't pay
    /// keygen cost every time.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        let host_key = host.to_ascii_lowercase();
        if let Some(c) = self.cache.lock().unwrap().get(&host_key) {
            return Ok(Arc::clone(c));
        }
        let cfg = Arc::new(self.mint(&host_key)?);
        self.cache
            .lock()
            .unwrap()
            .insert(host_key, Arc::clone(&cfg));
        Ok(cfg)
    }

    fn mint(&self, host: &str) -> Result<rustls::ServerConfig, String> {
        let san = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            SanType::IpAddress(ip)
        } else {
            let dns = Ia5String::try_from(host.to_string())
                .map_err(|e| format!("invalid dns name {:?}: {}", host, e))?;
            SanType::DnsName(dns)
        };

        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![san];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate().map_err(|e| format!("leaf keypair: {}", e))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.issuer_cert, &self.issuer_key)
            .map_err(|e| format!("sign leaf: {}", e))?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = CertificateDer::from(self.issuer_cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| format!("encode leaf key: {}", e))?;

        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der, ca_der], key_der)
            .map_err(|e| format!("rustls config: {}", e))?;
        Ok(cfg)
    }
}
