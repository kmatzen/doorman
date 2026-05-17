# doorman

[![ci](https://github.com/kmatzen/doorman/actions/workflows/ci.yml/badge.svg)](https://github.com/kmatzen/doorman/actions/workflows/ci.yml)
[![audit](https://github.com/kmatzen/doorman/actions/workflows/audit.yml/badge.svg)](https://github.com/kmatzen/doorman/actions/workflows/audit.yml)

An HTTP proxy that holds your API keys and refuses to send them anywhere they don't belong.

The agent process never sees the secret value. It names the credential it wants on each request (`X-Doorman-Cred: github`); doorman validates the destination against a per-credential allowlist, sets the auth header on the outgoing request, forwards it, and writes one audit-log line. If the agent tries to send a GitHub token to `attacker.com`, doorman returns 403 and the secret stays where it is.

## How it works

```
agent  ──HTTP_PROXY──▶  doormand  ──TLS────────▶  upstream API
   (plaintext)             │     ──TLS+pin────▶  self-signed LAN device
                           │     ──HTTP───────▶  plaintext LAN device
                           ├── reads doorman.yaml at startup
                           └── appends to audit.log per request
```

The agent talks to doorman over plaintext HTTP on loopback. Doorman talks to the upstream over TLS by default; per credential, the operator can either pin the upstream's self-signed cert (`tls_pinned_sha256`) or drop to plain HTTP (`tls: false`) for LAN devices that don't speak TLS at all.

Per request, doorman:

1. Resolves the upstream host from the URI authority or `Host` header.
2. Reads the `X-Doorman-Cred` header to pick a credential.
3. Looks up the credential. Validates the host and method against its allowlist.
4. Drops the `X-Doorman-Cred` header. Drops hop-by-hop headers. Inserts the templated auth header (e.g. `Authorization: Bearer <secret>`).
5. TLS-connects to the upstream on port 443 and streams the request body through.
6. Streams the response body back. Strips `Set-Cookie` and `WWW-Authenticate` from the response.
7. Appends one audit-log line at end of stream.

Any deny is a 403 with a one-line JSON error body, plus an audit entry.

## Install

### Homebrew (macOS / Linux)

```
brew tap kmatzen/doorman
brew install doorman
```

`brew info doorman` prints the config-file setup steps. Note: brew runs doorman under your user uid; for hardened production deployment with uid separation, use the systemd unit (Linux) or `install-darwin.sh` (macOS) — see [From a release tarball](#from-a-release-tarball) below.

### Quick install (curl)

```
curl -fsSL https://github.com/kmatzen/doorman/releases/latest/download/install.sh | sh
```

The script detects your platform, downloads the matching release tarball, verifies it against the published `SHA256SUMS` (and the sigstore attestation if `gh` is on PATH), and installs the binary to `/usr/local/bin/doormand`. To review before running:

```
curl -fsSL https://github.com/kmatzen/doorman/releases/latest/download/install.sh -o install.sh
less install.sh
sh install.sh
```

To override the version or install dir, place the env var on the **right** side of the pipe so it applies to `sh`, not `curl`:

```
curl -fsSL https://github.com/kmatzen/doorman/releases/latest/download/install.sh | DOORMAN_PREFIX=$HOME/.local/bin sh
```

`DOORMAN_VERSION` defaults to the latest release tag; `DOORMAN_PREFIX` defaults to `/usr/local/bin`.

### From a release tarball

Each release ships per-platform tarballs (`doorman-<version>-<target>.tar.gz`) with the binary, the README, the example config, and the appropriate service file. Releases starting with v0.1.3 also publish a `SHA256SUMS` file and a sigstore-signed build-provenance attestation for every artifact, recorded in the public Rekor transparency log.

Verify before installing:

```
# Provenance: confirms the tarball was built by this repo's release workflow.
# Requires gh ≥ 2.49.
gh attestation verify doorman-<version>-<target>.tar.gz \
  --repo kmatzen/doorman

# Integrity only (no provenance, but no gh required):
sha256sum -c SHA256SUMS --ignore-missing
```

Then install:

```
tar -xzf doorman-<version>-<target>.tar.gz
cd doorman-<version>-<target>
sudo install -m 0755 doormand /usr/local/bin/doormand
```

### From source

```
cargo build --release
sudo install -m 0755 target/release/doormand /usr/local/bin/doormand
```

To produce a tarball yourself: `make release`. Result lands in `dist/`.

### Configure and start

Write a config (mode 0400, owned by the doorman uid) — see [Config](#config). Then:

**Linux (systemd):**

```
doormand install-service | sudo tee /etc/systemd/system/doormand.service
sudo systemctl enable --now doormand
```

The unit runs doorman as `User=doorman`, with `NoNewPrivileges`, dropped capabilities, and `PR_SET_DUMPABLE=0`.

**macOS (launchd):** use the install script — it creates the `_doorman` user/group, the directories, and writes the plist:

```
sudo bash scripts/install-darwin.sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.doorman.doormand.plist
```

macOS's hardening primitives are weaker than systemd's; `_doorman` runs as a separate uid but you don't get the equivalent of `NoNewPrivileges` etc.

### Run directly (development)

```
doormand run \
  --config ./doorman.yaml \
  --audit /tmp/doorman.audit \
  --insecure-skip-mode-check
```

`--insecure-skip-mode-check` lets you use a config file that isn't mode 0400. Don't use it in production.

## Use

```
export HTTP_PROXY=http://127.0.0.1:18443
```

Use `http://` URLs in agent code even when the upstream is HTTPS — doorman terminates plaintext on its side and re-originates TLS to the upstream. Pick a credential by setting `X-Doorman-Cred: <name>` on the request:

```
curl --proxy http://127.0.0.1:18443 \
     -H 'X-Doorman-Cred: github' \
     http://api.github.com/repos/acme/widgets/issues
```

- Exactly one `X-Doorman-Cred` header per request. Zero, empty, or multiple → 403.
- Credential names must match config entries exactly (case-sensitive).
- Doorman overwrites the `Authorization` header (or whatever the `inject` template targets); the agent can't influence it.

## Config

`/etc/doorman/doorman.yaml`, mode 0400, owned by the doorman uid. A YAML list of entries:

```yaml
- name: github
  secret: ghp_xxxxxxxxxxxx
  inject: "Authorization: Bearer {}"
  hosts: [api.github.com]
  methods: [GET, POST, PATCH]              # optional; default = any method

- name: stripe_readonly
  secret: sk_live_xxxxxxxxxxxx
  inject: "Authorization: Bearer {}"
  hosts: [api.stripe.com]
  methods: [GET]

- name: stripe_writes
  secret: sk_live_xxxxxxxxxxxx
  inject: "Authorization: Bearer {}"
  hosts: [api.stripe.com]
  methods: [POST, DELETE]
```

Fields:

- **`name`**: what the agent puts in `X-Doorman-Cred`. Unique. ASCII alphanumeric plus `_`, `-`, `.`.
- **`secret`**: the literal string substituted into the inject template. Doorman doesn't interpret it.
- **`inject`**: a header template like `Header-Name: prefix {} suffix`. Exactly one `{}` slot.
- **`hosts`**: upstream-host allowlist. Bare hostnames; match is case-insensitive, exact.
- **`methods`**: optional HTTP method allowlist. Omitted = any method.
- **`port`**: optional upstream TCP port. Defaults to 443.
- **`tls`**: optional boolean. Default `true` — doorman speaks TLS to the upstream, validating the chain against `webpki-roots`. Set to `false` for LAN devices that expose only plain HTTP (e.g. Home Assistant on `http://host:8123`). The agent-to-doorman hop is plaintext loopback either way; this only controls upstream transport.
- **`tls_pinned_sha256`**: optional. 64 hex characters (32 raw bytes) of the SHA-256 of the upstream's leaf cert (DER). When present, doorman pins to exactly that cert and skips webpki chain validation. Use for self-signed LAN devices (UniFi gateway, Hue bridge, Hubitat). Only valid with `tls: true`; pairing it with `tls: false` is rejected at startup. Get the pin with `doormand fingerprint <host[:port]>`.

Two scopes for the same secret = two entries with different names.

### LAN-device examples

```yaml
# Home Assistant on plain HTTP, LAN only:
- name: hass
  secret: eyJhbGciOiJIUzI1NiIs...      # long-lived access token
  inject: "Authorization: Bearer {}"
  hosts: [192.168.86.188]
  port: 8123
  tls: false

# UniFi gateway with its built-in self-signed cert. Pin once with
# `doormand fingerprint 192.168.86.1` and paste the result here:
- name: unifi
  secret: 0123456789abcdef...           # X-API-Key from the UniFi UI
  inject: "X-API-Key: {}"
  hosts: [192.168.86.1]
  tls_pinned_sha256: a7b81034cd439551c50a29b54355254a84942a0a990c1a9e12856c855b64b65f
```

### Updating a pin after a cert rotation

Self-signed devices regenerate their cert on factory reset or some firmware updates. When that happens doorman will fail every request to that upstream with `tls connect: leaf cert SHA-256 does not match pin`. Re-run `doormand fingerprint <host>`, replace the value in the config, and `SIGHUP` is **not** enough — pinned configs are built once at startup, so restart the daemon.

## Audit log

One JSON line per request, fsync'd. Default path `/var/log/doorman/audit.log`, mode 0640.

```json
{"ts":"2026-04-27T14:22:01Z","cred":"github","host":"api.github.com","method":"GET","path":"/repos/acme/widgets/issues","status":200,"bytes_in":0,"bytes_out":8421,"ms":234,"decision":"allow"}
```

| field | meaning |
| --- | --- |
| `ts` | RFC 3339 UTC timestamp at request completion |
| `cred` | credential name used (omitted on cred-header-missing denies) |
| `host`, `method`, `path` | upstream destination |
| `status` | HTTP status returned to the agent |
| `bytes_in` | request body bytes uploaded |
| `bytes_out` | response body bytes returned |
| `ms` | total latency, accept to last byte |
| `decision` | `"allow"` or `"deny"` |
| `reason` | denial reason (denies only) |

No bodies, no headers, no secrets.

**Rotation.** Doorman handles `SIGHUP` by re-opening the audit log file at the same path, so external rotators (logrotate, newsyslog) can move the current file aside and signal doorman to start writing a fresh one. Example logrotate stanza:

```
/var/log/doorman/audit.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    postrotate
        /usr/bin/pkill -HUP -x doormand || true
    endscript
}
```

## Using doorman with coding agents

Doorman is for the case where an LLM agent generates network calls during tool use — `curl`, generated Python, shell commands — and some of those calls need credentials that you, the operator, don't want to hand to the agent directly. The agent retains full network access; doorman is not a network filter. Its job is to be the only path to *your* keys: the agent never holds them, so it can't leak them or send them to a host they aren't allowlisted for, no matter what the rest of its outbound traffic looks like.

Drop [`examples/agent-instructions.md`](examples/agent-instructions.md) into the file your agent reads as system instructions (`CLAUDE.md` for Claude Code, `.cursorrules` for Cursor, an `--read` file for Aider). It tells the agent which credentials doorman holds and how to invoke them via the proxy. The agent uses doorman when it needs one of those credentials, and calls the network directly otherwise.

## Threat model

**The adversary is the agent process itself.** Doorman assumes the agent may be compromised, prompt-injected, or buggy: it can issue any HTTP request, name any credential, parse any response. Doorman's job is to make sure that adversary cannot exfiltrate a secret it never directly sees.

**Assumed honest:** the host kernel, the doorman binary, the operator who wrote the config, and any process running as the doorman uid. If those are compromised, doorman cannot help.

### In scope

1. **Secret confidentiality from the agent.** The agent's process never holds the secret in memory, env, filesystem, or any response from doorman. It names credentials by label only.
2. **Destination binding.** A secret is only ever sent to a host (and optionally method) explicitly allowlisted for it. Host comes from the request URI authority or `Host` header, lowercased, and exact-matched against the allowlist. Redirects are not followed; 3xx responses are returned to the agent verbatim.
3. **Non-repudiation.** Every request — allow or deny — produces an audit-log line, fsync'd. Denies are logged before the response is sent; allows are logged at end-of-stream.
4. **Process isolation.** With the systemd unit, doorman runs under a different uid from the agent, with `NoNewPrivileges`, no ambient capabilities, and `PR_SET_DUMPABLE=0` (no core dumps, no ptrace from same-uid processes).
5. **Config confidentiality at rest.** The config file is mode 0400, owned by the doorman uid; doorman refuses to start otherwise (unless `--insecure-skip-mode-check`).

### Out of scope

1. **Misuse of legitimate access.** An allowed GitHub write can still open spam issues. Doorman is an authorization boundary, not a behavior monitor.
2. **Upstream echo.** If an upstream API includes the bearer token in a response body, doorman forwards it. Doorman strips `Set-Cookie` and `WWW-Authenticate` from responses but does not scrub bodies.
3. **Host compromise.** Kernel exploits, root, ptrace from a privileged uid, or a tampered doorman binary defeat everything. Verify release artifacts before installing.
4. **Allowlist enumeration.** The agent can probe credential/host pairs and observe allow/deny. Treat the allowlist itself as non-secret.
5. **Co-tenant processes.** Any process that can reach doorman's listening socket can issue requests as the agent. Pin the listener to loopback (default) and ensure only the agent uid can reach it.
6. **Network adversaries past doorman.** Doorman validates upstream TLS against Mozilla's `webpki-roots`, statically linked at build time. It does not pin certificates and does not consult the system trust store.
7. **Side channels.** Timing, response-size, and audit-volume side channels are not mitigated.

### macOS deployments

macOS's hardening primitives are weaker than systemd's. The `_doorman` user provides uid separation, but there is no equivalent of `NoNewPrivileges`, capability dropping, or `PR_SET_DUMPABLE=0`. Treat macOS as a development target; prefer Linux for production.

## Limitations

- **No peer-process identification in audit lines.** TCP sockets don't carry peer credentials. The intended deployment has one agent uid able to reach the proxy port.
- **Audit gaps on the allow path.** Audit writes for allowed requests happen at end-of-stream. A failed audit write logs to stderr and serves; the deny path is still pre-response and fail-closed.
- **Agent uses `http://` URLs even for HTTPS upstreams.** Doorman handles the TLS upgrade.
- **Upstream port comes from the credential's `port` field**, not the agent's URI. Defaults to 443.
- **HTTP/1.1 only**, both sides. No HTTP/2.
- **No upstream connection pooling.** One TLS handshake per upstream request, ~50ms cost.
- **No config hot-reload.** Restart to pick up changes; restarts are sub-second. (`SIGHUP` reopens the audit log only.)
- **`install-service` doesn't install.** It prints; you redirect.

## Testing

`cargo test` runs unit tests plus an integration suite (`tests/integration.rs`) that spins up doorman against a mock TLS upstream and exercises the full request path. Each branch of the security boundary has a named test:

| Test | Boundary it covers |
| --- | --- |
| `allow_path_injects_secret_and_strips_cred_header` | Templated auth header is injected; `X-Doorman-Cred` is dropped before the request leaves doorman. |
| `agent_authorization_header_is_overwritten` | An agent-supplied `Authorization` header cannot influence what doorman sends. |
| `deny_unknown_credential` | Unrecognized credential name → 403. |
| `deny_disallowed_host` | Credential used against a host outside its allowlist → 403. |
| `deny_disallowed_method` | Credential used with a method outside its allowlist → 403. |
| `deny_missing_cred_header` / `deny_multiple_cred_headers` | Zero or multiple `X-Doorman-Cred` headers → 403. |
| `response_strips_set_cookie_and_www_authenticate` | Sensitive response headers are stripped before reaching the agent. |

CI runs the full suite on Linux and macOS, with `clippy -D warnings`, on every push and PR. A separate audit workflow checks dependencies against the RustSec advisory DB on every Cargo manifest change and once a day on cron.

## Layout

```
src/main.rs       CLI dispatch (install-service / run)
src/config.rs     YAML loader
src/audit.rs      JSON-line audit writer, fsync per record
src/proxy.rs      HTTP/1.1 server, header rewrite, upstream TLS, body streaming
```
