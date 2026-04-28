# doorman

An HTTP proxy that holds your API keys and refuses to send them anywhere they don't belong.

The agent process never sees the secret value. It names the credential it wants on each request (`X-Doorman-Cred: github`); doorman validates the destination against a per-credential allowlist, sets the auth header on the outgoing request, forwards it, and writes one audit-log line. If the agent tries to send a GitHub token to `attacker.com`, doorman returns 403 and the secret stays where it is.

## How it works

```
agent  ──HTTP_PROXY──▶  doormand  ──TLS──▶  upstream API
   (plaintext)             │
                           ├── reads doorman.yaml at startup
                           └── appends to audit.log per request
```

The agent talks to doorman over plaintext HTTP on loopback. Doorman talks to the upstream over TLS.

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

### From a release tarball

Each release ships per-platform tarballs (`doorman-<version>-<target>.tar.gz`) with the binary, the README, the example config, and the appropriate service file.

```
tar -xzf doorman-0.1.0-aarch64-apple-darwin.tar.gz
cd doorman-0.1.0-aarch64-apple-darwin
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
  --listen 127.0.0.1:18443 \
  --insecure-skip-mode-check
```

`--insecure-skip-mode-check` lets you use a config file that isn't mode 0400. Don't use it in production.

## Use

```
export HTTP_PROXY=http://127.0.0.1:8443
```

Use `http://` URLs in agent code even when the upstream is HTTPS — doorman terminates plaintext on its side and re-originates TLS to the upstream. Pick a credential by setting `X-Doorman-Cred: <name>` on the request:

```
curl --proxy http://127.0.0.1:8443 \
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

Two scopes for the same secret = two entries with different names.

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

## Security model

Guarantees:

1. The agent's process never holds the secret in memory, env, filesystem, or any response from doorman.
2. A secret is only ever sent to a host explicitly allowlisted for it.
3. Every request — allow or deny — produces an audit-log line.
4. With the systemd unit, doorman runs under a different uid from the agent, with `NoNewPrivileges`, no ambient capabilities, and `PR_SET_DUMPABLE=0`.
5. The config file is readable only by the doorman uid.

Not guaranteed:

1. That the agent uses its allowed access wisely. An allowed GitHub write can still open spam issues.
2. That an upstream API doesn't echo a token in a response body. Doorman strips `Set-Cookie` and `WWW-Authenticate`; it doesn't scrub bodies.
3. That a kernel exploit, sandbox escape, or doorman-binary compromise doesn't defeat everything.
4. That the agent can't enumerate what's allowed by trial and error.
5. That a third party who can reach doorman's listening port can't issue requests as the agent. Pin the listener to loopback or a netns the agent shares.

## Limitations

- **No peer-process identification in audit lines.** TCP sockets don't carry peer credentials. The intended deployment has one agent uid able to reach the proxy port.
- **Audit gaps on the allow path.** Audit writes for allowed requests happen at end-of-stream. A failed audit write logs to stderr and serves; the deny path is still pre-response and fail-closed.
- **Agent uses `http://` URLs even for HTTPS upstreams.** Doorman handles the TLS upgrade.
- **Upstream port comes from the credential's `port` field**, not the agent's URI. Defaults to 443.
- **HTTP/1.1 only**, both sides. No HTTP/2.
- **No upstream connection pooling.** One TLS handshake per upstream request, ~50ms cost.
- **No config hot-reload.** Restart to pick up changes; restarts are sub-second. (`SIGHUP` reopens the audit log only.)
- **`install-service` doesn't install.** It prints; you redirect.

## Layout

```
src/main.rs       CLI dispatch (install-service / run)
src/config.rs     YAML loader
src/audit.rs      JSON-line audit writer, fsync per record
src/proxy.rs      HTTP/1.1 server, header rewrite, upstream TLS, body streaming
```
