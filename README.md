# doorman

An HTTPS proxy that holds your API keys and refuses to send them anywhere they don't belong.

The agent process never sees the secret. It addresses credentials by name (`{{github}}`); doorman substitutes the real value into the outgoing request, but only if the destination host is on the allowlist for that credential. Every request is logged.

This is the entire product. See [plan.md](plan.md) for the design rationale and the explicit list of non-goals.

## Install

Build from source:

```
cargo build --release
sudo install -m 0755 target/release/doormand /usr/local/bin/doormand
```

Generate a CA the first time:

```
sudo doormand init --state-dir /etc/doorman
```

This writes `/etc/doorman/ca.crt` (world-readable, what the agent trusts) and `/etc/doorman/ca.key` (mode 0400, what doorman signs leaf certs with). Add the cert to the agent's trust store — for most CLI tools `export SSL_CERT_FILE=/etc/doorman/ca.crt` is enough.

Write `/etc/doorman/doorman.yaml` (mode 0400) — see [Config](#config) below.

Print a systemd unit and pipe it where you want it:

```
doormand install-service | sudo tee /etc/systemd/system/doormand.service
sudo systemctl enable --now doormand
```

Or run it directly for development:

```
doormand run \
  --config ./doorman.yaml \
  --state-dir /tmp/doorman-state \
  --audit /tmp/doorman.audit \
  --listen 127.0.0.1:18443 \
  --insecure-skip-mode-check
```

## Use

Point the agent at the proxy and trust the CA:

```
export HTTPS_PROXY=http://127.0.0.1:8443
export SSL_CERT_FILE=/etc/doorman/ca.crt
```

In requests, refer to the credential by name with a `{{name}}` placeholder in any header. The placeholder header itself is dropped before the request goes upstream — only the templated `inject` header reaches the destination.

```
curl -H 'X-Cred: {{github}}' https://api.github.com/repos/acme/widgets/issues
```

There must be exactly one placeholder in the request. Zero is denied (no credential to use). More than one is denied (ambiguous).

## Config

`/etc/doorman/doorman.yaml`, mode 0400, owned by the doorman uid. A YAML list of entries; each entry has five fields:

```yaml
- name: github                              # placeholder name; agent uses {{github}}
  secret: ghp_xxxxxxxxxxxx                  # the actual secret
  inject: "Authorization: Bearer {}"        # header doorman sets; {} is the secret slot
  hosts: [api.github.com]                   # hostname allowlist
  methods: [GET, POST, PATCH]               # optional; default = any method

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

Two scopes for the same secret = two entries with different names. There are no conditionals, includes, or templating beyond the `{}` slot.

## Audit log

One JSON line per request, fsync'd. Default path `/var/log/doorman/audit.log`, mode 0640.

```json
{"ts":"2026-04-27T14:22:01Z","pid":-1,"uid":-1,"cred":"github","host":"api.github.com","method":"GET","path":"/repos/acme/widgets/issues","status":200,"bytes_in":0,"bytes_out":8421,"ms":234,"decision":"allow"}
```

Fields:

| field | meaning |
| --- | --- |
| `ts` | RFC 3339 UTC timestamp at request completion |
| `pid` / `uid` | OS peer credentials of the agent (currently always `-1`; see Limitations) |
| `cred` | credential name used (omitted on placeholder-not-found denies) |
| `host`, `method`, `path` | upstream destination |
| `status` | HTTP status returned to agent (403 on doorman denies, upstream status on allows) |
| `bytes_in` | request body bytes the agent uploaded |
| `bytes_out` | response body bytes returned to the agent |
| `ms` | total latency, accept to last byte |
| `decision` | `"allow"` or `"deny"` |
| `reason` | denial reason (only present on denies) |

No bodies, no headers, no secrets. The path is logged because operators need it to debug; if a path contains a token, that's an upstream design problem.

## Security model

What doorman guarantees:

1. The agent's process never holds the secret in memory, env, filesystem, or any response from doorman.
2. A secret is only sent to a host explicitly allowlisted for it.
3. Every request is logged.
4. Doorman runs as a different uid from the agent (when installed via the systemd unit), with `NoNewPrivileges`, dropped capabilities, and `PR_SET_DUMPABLE=0`. The agent cannot ptrace it.
5. The config file is unreadable by the agent uid.

What doorman does NOT guarantee:

1. That the agent uses its allowed access wisely. An allowed GitHub write can still open spam issues.
2. That an upstream API doesn't echo your token back in a body. (Headers, yes — `Set-Cookie` and `WWW-Authenticate` are stripped. Response bodies are not scrubbed.)
3. That a kernel exploit, sandbox escape, or compromise of the doorman binary itself doesn't defeat everything.
4. That the agent can't enumerate what's allowed by trial and error.

## Limitations

- **`pid` and `uid` are hardcoded to `-1`.** SO_PEERCRED works on Unix sockets, not TCP. The TCP listener is what the spec specifies, so audit lines don't carry real peer credentials. If you have multiple uids on the host that can reach `127.0.0.1:8443`, you can't tell them apart in the log.
- **Audit gaps on the allow path.** Audit writes for allowed requests happen at end-of-stream. If an audit write fails mid-day (disk full, etc.), the agent has already received the response — we log the failure to stderr and keep serving. Deny-path audit is still pre-response and hard fails closed.
- **No HTTP/2.** Only HTTP/1.1 inside the tunnel and to the upstream.
- **No connection pooling.** One TLS handshake per upstream request. Boring is good; this is a known cost.
- **No config hot-reload.** Restart the service to pick up changes. Restarts are sub-second.
- **No launchd plist.** `install-service` only emits the systemd unit. macOS users need to write the plist themselves.
- **`install-service` doesn't install.** It prints; you redirect.

## Layout

```
src/main.rs       CLI dispatch (init / install-service / run)
src/config.rs     YAML loader for /etc/doorman/doorman.yaml
src/ca.rs         CA generation and per-host leaf cert minting
src/audit.rs      JSON-line audit writer, fsync per record
src/proxy.rs      CONNECT handling, TLS interception, header rewrite,
                  upstream forwarding, body streaming
```

About 1300 lines total.
