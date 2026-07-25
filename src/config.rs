// Loads `/etc/doorman/doorman.yaml`. Every field of every entry is required
// up-front and the whole file is validated before any request is served — if
// the parse fails, the daemon refuses to start. That is one of the
// fail-closed defaults the spec calls out.

use std::collections::HashSet;
use std::fs;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde::Deserialize;

/// Normalize a host for the allowlist and for allowlist matching. A bare
/// (unbracketed) IPv6 literal is reparsed and reformatted through
/// [`Ipv6Addr`], which produces the RFC 5952 canonical compressed form —
/// this way `::1`, `0:0:0:0:0:0:0:1`, and `0:0::1` all normalize to the same
/// string and compare equal. Anything else (hostnames, IPv4 literals) is
/// just lowercased, as before.
pub fn canonicalize_host(host: &str) -> String {
    match host.parse::<Ipv6Addr>() {
        Ok(v6) => v6.to_string(),
        Err(_) => host.to_ascii_lowercase(),
    }
}

/// One credential the daemon holds in memory and may inject into outgoing
/// requests. The fields mirror the YAML one-to-one; everything else (parsed
/// header name, prefix, suffix) is computed in [`Entry::from_raw`].
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub secret: String,
    /// The header doorman sets on the outgoing request, e.g. `Authorization`.
    pub header_name: String,
    /// Text before the `{}` slot in the inject template.
    pub header_prefix: String,
    /// Text after the `{}` slot in the inject template.
    pub header_suffix: String,
    /// Canonicalized host allowlist (see [`canonicalize_host`]): lowercased
    /// hostnames/IPv4 literals, or RFC 5952 canonical form for bare IPv6
    /// literals (no brackets — those are only used on the wire, e.g. in the
    /// `Host` header, never in config or in the values this list holds).
    pub hosts: Vec<String>,
    /// Upper-cased method allowlist; empty means "any method".
    pub methods: Vec<String>,
    /// Upstream TCP port. Defaults to 443.
    pub port: u16,
    /// Whether doorman speaks TLS to the upstream. Default true. Set to
    /// false for LAN devices that only expose plain HTTP (e.g. a local
    /// Home Assistant on port 8123). The agent-to-doorman hop remains
    /// plaintext loopback either way; this only controls upstream transport.
    pub tls: bool,
    /// Optional SHA-256 (32 raw bytes) of the upstream leaf certificate (DER).
    /// When present, doorman pins to exactly this cert and skips webpki
    /// chain validation. Use for self-signed devices (UniFi, Hue bridge,
    /// etc.). Only meaningful when `tls = true`; configs that mix `tls:
    /// false` with a pin are rejected at load time.
    pub tls_pin: Option<[u8; 32]>,
}

impl Entry {
    /// Render the full header value the upstream will see. Pulled out so the
    /// proxy and the tests share one definition.
    pub fn render(&self) -> String {
        let mut s = String::with_capacity(
            self.header_prefix.len() + self.secret.len() + self.header_suffix.len(),
        );
        s.push_str(&self.header_prefix);
        s.push_str(&self.secret);
        s.push_str(&self.header_suffix);
        s
    }

    pub fn host_allowed(&self, host: &str) -> bool {
        self.hosts.contains(&canonicalize_host(host))
    }

    pub fn method_allowed(&self, method: &str) -> bool {
        if self.methods.is_empty() {
            return true;
        }
        let method = method.to_ascii_uppercase();
        self.methods.contains(&method)
    }
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    name: String,
    secret: String,
    inject: String,
    hosts: Vec<String>,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    tls_pinned_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub entries: Vec<Entry>,
}

impl Config {
    pub fn lookup(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

/// Read, validate, and return the config. With `enforce_mode_0400` true the
/// loader refuses any file whose permissions are looser than 0400 — the spec
/// makes this non-negotiable for production. Tests pass `false` because temp
/// files don't always honor restrictive modes.
pub fn load(path: &Path, enforce_mode_0400: bool) -> Result<Config, String> {
    let meta = fs::metadata(path).map_err(|e| format!("stat {}: {}", path.display(), e))?;
    if enforce_mode_0400 {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o400 {
            return Err(format!(
                "config {} must be mode 0400, got {:#o}",
                path.display(),
                mode
            ));
        }
    }
    let raw = fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            // The usual cause under a service: the config is owned by root (or
            // some other uid) but the daemon runs as a dedicated, unprivileged
            // uid that can't read it. Spell that out — it's exactly the failure
            // that otherwise shows up as a bare "exit 1" in the service log.
            format!(
                "read {}: {} — the config must be owned by and readable by the uid \
                 doorman runs as (under the systemd unit / launchd plist that is a \
                 dedicated uid, not root); check the file's owner and mode",
                path.display(),
                e
            )
        } else {
            format!("read {}: {}", path.display(), e)
        }
    })?;
    let entries: Vec<RawEntry> = serde_yaml::from_str(&raw).map_err(|e| format!("parse: {}", e))?;
    if entries.is_empty() {
        return Err("config has no entries; refusing to start".into());
    }

    let mut seen_names = HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for (i, raw) in entries.into_iter().enumerate() {
        let entry = parse_entry(i, raw)?;
        if !seen_names.insert(entry.name.clone()) {
            return Err(format!("duplicate credential name {:?}", entry.name));
        }
        out.push(entry);
    }
    Ok(Config { entries: out })
}

fn parse_entry(idx: usize, r: RawEntry) -> Result<Entry, String> {
    let where_ = || format!("entry[{}]", idx);
    if r.name.is_empty() {
        return Err(format!("{}: name is empty", where_()));
    }
    if !r.name.chars().all(is_name_char) {
        return Err(format!(
            "{}: name {:?} must be ASCII letters, digits, _, -, .",
            where_(),
            r.name
        ));
    }
    if r.secret.is_empty() {
        return Err(format!("{} {:?}: secret is empty", where_(), r.name));
    }
    if r.hosts.is_empty() {
        return Err(format!("{} {:?}: hosts list is empty", where_(), r.name));
    }
    let mut hosts = Vec::with_capacity(r.hosts.len());
    for h in &r.hosts {
        let invalid = || {
            format!(
                "{} {:?}: host {:?} must be a bare hostname, IPv4 literal, or bare IPv6 literal \
                 (no brackets, no scheme, no port, no path)",
                where_(),
                r.name,
                h
            )
        };
        if h.is_empty() || h.contains('/') {
            return Err(invalid());
        }
        // A colon only belongs here as part of a bare IPv6 literal (e.g.
        // `fd00::5`, no brackets, no port suffix — those are added on the
        // wire, never in config). Anything else containing one (a port
        // suffix, a scheme, bracket syntax) is rejected; hostnames and IPv4
        // literals never contain a colon.
        if h.contains(':') && h.parse::<Ipv6Addr>().is_err() {
            return Err(invalid());
        }
        hosts.push(canonicalize_host(h));
    }

    let methods: Vec<String> = r
        .methods
        .unwrap_or_default()
        .iter()
        .map(|m| m.to_ascii_uppercase())
        .collect();
    for m in &methods {
        if !is_valid_method(m) {
            return Err(format!(
                "{} {:?}: invalid HTTP method {:?}",
                where_(),
                r.name,
                m
            ));
        }
    }

    let (header_name, header_prefix, header_suffix) = parse_inject(&r.inject)
        .map_err(|e| format!("{} {:?}: inject {:?}: {}", where_(), r.name, r.inject, e))?;

    let port = r.port.unwrap_or(443);
    if port == 0 {
        return Err(format!("{} {:?}: port must be > 0", where_(), r.name));
    }

    let tls = r.tls.unwrap_or(true);
    let tls_pin = match r.tls_pinned_sha256.as_deref() {
        None | Some("") => None,
        Some(hex) => Some(parse_pin_hex(hex).map_err(|e| {
            format!(
                "{} {:?}: tls_pinned_sha256 {:?}: {}",
                where_(),
                r.name,
                hex,
                e
            )
        })?),
    };
    if !tls && tls_pin.is_some() {
        return Err(format!(
            "{} {:?}: tls_pinned_sha256 set but tls is false (a pin without TLS is meaningless)",
            where_(),
            r.name
        ));
    }

    Ok(Entry {
        name: r.name,
        secret: r.secret,
        header_name,
        header_prefix,
        header_suffix,
        hosts,
        methods,
        port,
        tls,
        tls_pin,
    })
}

/// Parse a SHA-256 pin as 64 lowercase-hex characters into 32 raw bytes.
/// Accepts upper or lower case but rejects whitespace, prefixes (`sha256:`),
/// and any non-hex character — keeping the surface tight makes audits easy.
fn parse_pin_hex(s: &str) -> Result<[u8; 32], &'static str> {
    if s.len() != 64 {
        return Err("must be 64 hex characters (32 bytes of SHA-256)");
    }
    let mut out = [0u8; 32];
    for (i, byte_chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(byte_chunk[0])?;
        let lo = hex_nibble(byte_chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("contains non-hex characters"),
    }
}

/// Parse a string like `Authorization: Bearer {}` into
/// `("Authorization", "Bearer ", "")`. Exactly one `{}` slot, exactly one
/// colon separating header name from value template.
fn parse_inject(s: &str) -> Result<(String, String, String), String> {
    let colon = s
        .find(':')
        .ok_or("missing ':' between header name and value")?;
    let name = s[..colon].trim();
    if name.is_empty() {
        return Err("header name is empty".into());
    }
    if !name.chars().all(is_header_name_char) {
        return Err("header name has invalid characters".into());
    }
    let value = s[colon + 1..].trim_start();

    let slot_count = value.matches("{}").count();
    if slot_count != 1 {
        return Err(format!(
            "value template must contain exactly one '{{}}' slot, found {}",
            slot_count
        ));
    }
    let slot = value.find("{}").unwrap();
    let prefix = &value[..slot];
    let suffix = &value[slot + 2..];

    // Reject any other braces; the template is dead-simple by design.
    if prefix.contains('{') || prefix.contains('}') || suffix.contains('{') || suffix.contains('}')
    {
        return Err("value template may only contain a single '{}' slot".into());
    }

    Ok((name.to_string(), prefix.to_string(), suffix.to_string()))
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

fn is_header_name_char(c: char) -> bool {
    // RFC 7230 token: very permissive but excludes whitespace/control/separators.
    c.is_ascii_graphic()
        && !matches!(
            c,
            '(' | ')'
                | ','
                | '/'
                | ':'
                | ';'
                | '<'
                | '='
                | '>'
                | '?'
                | '@'
                | '['
                | '\\'
                | ']'
                | '{'
                | '}'
                | '"'
        )
}

/// Any RFC 9110 token is a legitimate HTTP method name — this used to allow
/// only a fixed list of common verbs, which was stricter than the runtime
/// enforcement (an *omitted* `methods:` list allows every method), so an
/// operator could never narrow a credential to, say, WebDAV/CalDAV verbs
/// (`PROPFIND`, `REPORT`, `MKCOL`, ...) without the config load failing.
/// Restricting scope should never be harder than not restricting it.
///
/// `CONNECT` is rejected explicitly: doorman is a strict forward proxy that
/// never tunnels (see the "what this module deliberately does NOT do" note
/// in proxy.rs), so an allowlisted CONNECT could never do anything useful —
/// it would just be dead configuration that looks live.
fn is_valid_method(m: &str) -> bool {
    !m.is_empty() && m != "CONNECT" && m.chars().all(is_header_name_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(yaml: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let i = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let p = dir.join(format!("doorman_cfg_{}_{}.yaml", std::process::id(), i));
        std::fs::write(&p, yaml).unwrap();
        p
    }

    #[test]
    fn parses_minimal() {
        let p = write_tmp("- name: github\n  secret: ghp_x\n  inject: 'Authorization: Bearer {}'\n  hosts: [api.github.com]\n");
        let cfg = load(&p, false).unwrap();
        assert_eq!(cfg.entries.len(), 1);
        let e = &cfg.entries[0];
        assert_eq!(e.name, "github");
        assert_eq!(e.header_name, "Authorization");
        assert_eq!(e.header_prefix, "Bearer ");
        assert_eq!(e.header_suffix, "");
        assert_eq!(e.render(), "Bearer ghp_x");
        assert!(e.host_allowed("api.github.com"));
        assert!(e.host_allowed("API.GitHub.com"));
        assert!(!e.host_allowed("attacker.com"));
        assert!(e.method_allowed("GET"));
        assert!(e.method_allowed("anything")); // empty list = allow all
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_malformed_yaml_with_a_useful_location() {
        // An unclosed flow sequence — a genuine YAML syntax error, as
        // opposed to the semantic-validation errors the other rejects_*
        // tests exercise. Regression coverage for swapping the YAML backend
        // (serde_yaml -> serde_norway, see #47): the parser must still
        // surface a message pointing at where the problem is.
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com\n");
        let err = load(&p, false).unwrap_err();
        assert!(err.starts_with("parse:"), "got: {}", err);
        assert!(
            err.contains("line") && err.contains("column"),
            "got: {}",
            err
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_duplicate_names() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n- name: a\n  secret: y\n  inject: 'X: {}'\n  hosts: [b.com]\n");
        assert!(load(&p, false).unwrap_err().contains("duplicate"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_no_slot() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: literal'\n  hosts: [a.com]\n");
        assert!(load(&p, false).unwrap_err().contains("'{}'"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_two_slots() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {} {}'\n  hosts: [a.com]\n");
        assert!(load(&p, false).unwrap_err().contains("'{}'"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_host_with_scheme() {
        let p =
            write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: ['https://a.com']\n");
        assert!(load(&p, false).unwrap_err().contains("bare hostname"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn accepts_bare_ipv6_literal_host() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: ['fd00::5']\n");
        let cfg = load(&p, false).unwrap();
        let e = &cfg.entries[0];
        assert_eq!(e.hosts, vec!["fd00::5".to_string()]);
        assert!(e.host_allowed("fd00::5"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn ipv6_host_canonicalizes_equivalent_representations() {
        // ::1 and 0:0:0:0:0:0:0:1 are the same address; both the config
        // value and a runtime lookup must normalize to the same string so
        // an operator's chosen spelling doesn't accidentally fail to match.
        let p =
            write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: ['0:0:0:0:0:0:0:1']\n");
        let cfg = load(&p, false).unwrap();
        let e = &cfg.entries[0];
        assert_eq!(
            e.hosts,
            vec!["::1".to_string()],
            "should store RFC 5952 canonical form"
        );
        assert!(e.host_allowed("::1"));
        assert!(
            e.host_allowed("0:0:0:0:0:0:0:1"),
            "differently-formatted equivalent must still match"
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_bracketed_ipv6_host_in_config() {
        // Brackets are wire syntax (URI authority, Host header); config
        // hosts are bare, matching how a plain hostname is written.
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: ['[fd00::5]']\n");
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("bare hostname"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_hostname_with_explicit_port_in_config() {
        // A colon is only ever valid here as part of a bare IPv6 literal.
        // `api.example.com:443` isn't a valid IPv6 literal (or a hostname
        // doorman accepts a port suffix on) — config hosts never carry a
        // port, that's the separate `port:` field.
        let p = write_tmp(
            "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: ['api.example.com:443']\n",
        );
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("bare hostname"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn methods_uppercased_and_validated() {
        let p = write_tmp(
            "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  methods: [get, post]\n",
        );
        let cfg = load(&p, false).unwrap();
        let e = &cfg.entries[0];
        assert!(e.method_allowed("GET"));
        assert!(e.method_allowed("post"));
        assert!(!e.method_allowed("DELETE"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn accepts_non_standard_verbs_like_webdav_methods() {
        // An omitted `methods:` list allows every method at runtime, so
        // validation must not be stricter than that in the direction that
        // prevents an operator from *narrowing* a credential's scope.
        let p = write_tmp(
            "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  methods: [PROPFIND, REPORT]\n",
        );
        let cfg = load(&p, false).unwrap();
        let e = &cfg.entries[0];
        assert!(e.method_allowed("PROPFIND"));
        assert!(e.method_allowed("report"));
        assert!(!e.method_allowed("GET"));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_connect_method() {
        let p = write_tmp(
            "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  methods: [CONNECT]\n",
        );
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("invalid HTTP method"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_garbage_method() {
        let p = write_tmp(
            "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  methods: [\"GE T\"]\n",
        );
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("invalid HTTP method"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn defaults_tls_true_and_no_pin() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n");
        let cfg = load(&p, false).unwrap();
        assert!(cfg.entries[0].tls);
        assert!(cfg.entries[0].tls_pin.is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn accepts_tls_false_for_plaintext_upstream() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  tls: false\n  port: 8123\n");
        let cfg = load(&p, false).unwrap();
        assert!(!cfg.entries[0].tls);
        assert_eq!(cfg.entries[0].port, 8123);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn accepts_valid_pin_hex64() {
        let hex = "a".repeat(64);
        let yaml = format!(
            "- name: a\n  secret: x\n  inject: 'X: {{}}'\n  hosts: [a.com]\n  tls_pinned_sha256: '{}'\n",
            hex
        );
        let p = write_tmp(&yaml);
        let cfg = load(&p, false).unwrap();
        assert_eq!(cfg.entries[0].tls_pin.unwrap(), [0xaa; 32]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn pin_accepts_mixed_case_hex() {
        let hex = "Ab".repeat(32);
        let yaml = format!(
            "- name: a\n  secret: x\n  inject: 'X: {{}}'\n  hosts: [a.com]\n  tls_pinned_sha256: '{}'\n",
            hex
        );
        let p = write_tmp(&yaml);
        let cfg = load(&p, false).unwrap();
        assert_eq!(cfg.entries[0].tls_pin.unwrap(), [0xab; 32]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_pin_wrong_length() {
        let yaml = "- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  tls_pinned_sha256: 'abcd'\n";
        let p = write_tmp(yaml);
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("64 hex characters"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_pin_non_hex() {
        let bad = "z".repeat(64);
        let yaml = format!(
            "- name: a\n  secret: x\n  inject: 'X: {{}}'\n  hosts: [a.com]\n  tls_pinned_sha256: '{}'\n",
            bad
        );
        let p = write_tmp(&yaml);
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("non-hex"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_pin_with_tls_false() {
        let hex = "a".repeat(64);
        let yaml = format!(
            "- name: a\n  secret: x\n  inject: 'X: {{}}'\n  hosts: [a.com]\n  tls: false\n  tls_pinned_sha256: '{}'\n",
            hex
        );
        let p = write_tmp(&yaml);
        let err = load(&p, false).unwrap_err();
        assert!(err.contains("meaningless"), "got: {}", err);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn empty_pin_string_is_treated_as_none() {
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n  tls_pinned_sha256: ''\n");
        let cfg = load(&p, false).unwrap();
        assert!(cfg.entries[0].tls_pin.is_none());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn unreadable_config_explains_uid_permission() {
        // root ignores permission bits, so this scenario only holds for an
        // unprivileged uid — which is exactly how the daemon runs as a service.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let p = write_tmp("- name: a\n  secret: x\n  inject: 'X: {}'\n  hosts: [a.com]\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        // enforce_mode_0400 = false so we get past the mode gate to the read,
        // which then fails as PermissionDenied (the #10 failure mode).
        let err = load(&p, false).unwrap_err();
        // Restore perms so cleanup can remove the file.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).ok();
        std::fs::remove_file(&p).ok();
        assert!(
            err.contains("readable by the uid"),
            "expected a uid/permission hint, got: {}",
            err
        );
    }
}
