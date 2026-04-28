# doorman

An HTTP proxy that holds your API keys and refuses to send them anywhere they don't belong.

## What problem this solves

You're running an agent — an LLM, a script, a job runner, anything that takes instructions from somewhere you don't fully trust and then makes API calls. If you ship that agent the literal value of `GITHUB_TOKEN`, then any prompt injection, any malicious tool output, any rogue dependency in the agent's process can read it out of memory or env. The blast radius is "every API the token can reach, forever, until you rotate it."

Doorman holds the secret in a different process under a different uid. The agent never sees the value — it refers to the credential by name (`{{github}}`) when it makes a request. Doorman validates the destination against a per-credential allowlist, substitutes the real secret into the outgoing header, forwards the request, and writes one audit-log line. If the agent tries to send a GitHub token to `attacker.com`, doorman returns 403, logs the attempt, and the secret stays where it is.

The blast radius drops from "everything the token can do" to "everything the policy lets the token do on the hosts you allowlisted." The hostile-content paths into the agent are unchanged — what's changed is what they can reach.

## What it isn't

Not a secrets manager (it pulls from a YAML file you write; if you want Vault, put Vault behind that file). Not an authorization layer for the agent's *capabilities* — an allowed GitHub write can still open spam issues; that problem lives one layer up. Not OAuth-aware. Not a sandbox. The whole product fits in ~1100 lines because everything else got cut.

See [plan.md](plan.md) for the full design rationale and the explicit list of non-goals.

## How it works at a glance

```
agent  ──HTTP_PROXY──▶  doormand  ──TLS──▶  upstream API
   (plaintext)             │
                           ├── reads doorman.yaml at startup
                           └── appends to audit.log per request
```

The agent talks to doorman over plaintext HTTP on loopback. Doorman talks to the upstream over TLS. There is no CA to install, no `HTTPS_PROXY` ceremony, no per-host cert minting — just a forward HTTP proxy with one trick.

Per request, doorman:

1. Resolves the upstream host from the URI authority or `Host` header.
2. Finds the `{{name}}` placeholder in some request header.
3. Looks up the credential. Validates the host and method against the policy.
4. Drops the placeholder header. Drops hop-by-hop headers. Inserts the templated auth header (e.g. `Authorization: Bearer <secret>`).
5. TLS-connects to the upstream on port 443 and streams the request body through.
6. Streams the response body back. Strips `Set-Cookie` and `WWW-Authenticate` from the response (some upstreams reflect auth material in those on errors).
7. Appends one audit-log line at end of stream.

Any deny along the way is a 403 with a one-line JSON error body, plus an audit entry.

## Install

Build:

```
cargo build --release
sudo install -m 0755 target/release/doormand /usr/local/bin/doormand
```

Write a config (mode 0400, owned by the doorman uid) — see [Config](#config). Then for production:

```
doormand install-service | sudo tee /etc/systemd/system/doormand.service
sudo systemctl enable --now doormand
```

`install-service` prints a systemd unit tailored to the binary's path; it doesn't write anything itself. The unit it prints runs doorman as `User=doorman`, with `NoNewPrivileges`, dropped capabilities, and `PR_SET_DUMPABLE=0` so the agent can't ptrace it.

For development, skip systemd and run directly:

```
doormand run \
  --config ./doorman.yaml \
  --audit /tmp/doorman.audit \
  --listen 127.0.0.1:18443 \
  --insecure-skip-mode-check
```

The `--insecure-skip-mode-check` flag lets you use a config file that isn't mode 0400 — fine for testing, never use it in production.

## Use

Point the agent at the proxy:

```
export HTTP_PROXY=http://127.0.0.1:8443
```

In agent code, use `http://` URLs even when the upstream is HTTPS. Doorman receives the request in cleartext on loopback and upgrades to TLS for the upstream connection itself. Yes, the URL in your code looks "wrong" — that's the price of not having a CA.

Refer to a credential by name with a `{{name}}` placeholder in any request header. Doorman drops that header (whatever surrounding text you put around the placeholder is ignored — only the credential's `inject` template defines what actually goes upstream).

```
curl --proxy http://127.0.0.1:8443 \
     -H 'X-Cred: {{github}}' \
     http://api.github.com/repos/acme/widgets/issues
```

A few rules that are easy to get wrong:

- Exactly one placeholder per request. Zero is denied (no credential to use). More than one is denied (ambiguous).
- The header you put the placeholder in doesn't matter — `X-Cred`, `Authorization`, `X-Whatever`. Doorman finds the `{{name}}` token, drops the carrier header, and writes the auth header from the credential's `inject` template.
- The placeholder is `{{name}}` literally — no whitespace tricks, no nested braces, no Jinja-style filters.

## Config

`/etc/doorman/doorman.yaml`, mode 0400, owned by the doorman uid. A YAML list of entries; each entry has five fields:

```yaml
- name: github                              # placeholder name; agent uses {{github}}
  secret: ghp_xxxxxxxxxxxx                  # the actual secret
  inject: "Authorization: Bearer {}"        # header doorman sets; {} is the secret slot
  hosts: [api.github.com]                   # upstream hostname allowlist
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

Field-by-field:

- **`name`** is what the agent puts inside `{{...}}`. Must be unique. ASCII alphanumeric plus `_`, `-`, `.`.
- **`secret`** is the literal string doorman substitutes. Doorman does nothing to interpret it — base64, JWT, opaque token, all the same.
- **`inject`** is a header template like `Header-Name: prefix {} suffix`. Exactly one `{}` slot. Doorman writes this header on the outgoing request with `{}` replaced by the secret.
- **`hosts`** is the upstream-host allowlist for this credential. Bare hostnames (no scheme, no port). The match is exact and case-insensitive.
- **`methods`** is an optional HTTP method allowlist. If omitted, any method is allowed.

There are no conditionals, includes, environments, or templating beyond the `{}` slot. If you want two scopes for the same secret (read-only vs. writes; one team's quota vs. another's), declare two entries with different names.

## Audit log

One JSON line per request, fsync'd before the next request is served. Default path `/var/log/doorman/audit.log`, mode 0640.

```json
{"ts":"2026-04-27T14:22:01Z","pid":-1,"uid":-1,"cred":"github","host":"api.github.com","method":"GET","path":"/repos/acme/widgets/issues","status":200,"bytes_in":0,"bytes_out":8421,"ms":234,"decision":"allow"}
```

| field | meaning |
| --- | --- |
| `ts` | RFC 3339 UTC timestamp at request completion |
| `pid` / `uid` | OS peer credentials of the agent (currently always `-1`; see Limitations) |
| `cred` | credential name used (omitted on placeholder-not-found denies) |
| `host`, `method`, `path` | upstream destination |
| `status` | HTTP status returned to the agent (403 on doorman denies, upstream status on allows) |
| `bytes_in` | request body bytes uploaded to the upstream |
| `bytes_out` | response body bytes returned to the agent |
| `ms` | total latency, accept to last byte |
| `decision` | `"allow"` or `"deny"` |
| `reason` | denial reason (only present on denies) |

No bodies. No headers. No secrets. The path is logged because operators need it to debug; if a path contains a token, that's an upstream design problem, not doorman's to scrub.

The audit log is the source of truth for what flowed through doorman. Ship it to a central collector and alert on it the same way you'd alert on any auth-decision log: spike in denies, unexpected `cred`/`host` pairings, anomalous `bytes_out`, requests outside business hours from a service that runs 9–5.

## Security model

What doorman guarantees:

1. The agent's process never holds the secret in memory, env, filesystem, or any response from doorman.
2. A secret is only ever sent to a host explicitly allowlisted for that secret.
3. Every request — allow or deny — produces an audit-log line.
4. With the systemd unit, doorman runs under a different uid from the agent, with `NoNewPrivileges`, no ambient capabilities, and `PR_SET_DUMPABLE=0`. The agent cannot ptrace doorman or read its memory.
5. The config file is readable only by the doorman uid; the agent cannot read it.

What doorman does NOT guarantee:

1. That the agent uses its allowed access wisely. An allowed GitHub write can still open spam issues — capability scoping and human review live one layer up.
2. That an upstream API doesn't echo your token back in a body. Doorman strips `Set-Cookie` and `WWW-Authenticate` from response headers, but does not scrub bodies. If an API does this, don't put it behind doorman.
3. That a kernel exploit, sandbox escape, or compromise of the doorman binary itself doesn't defeat everything.
4. That the agent can't enumerate what's allowed by trial and error. (It can. That's recon, not credential leakage.)
5. That a third party who can reach doorman's listening port can't issue requests as the agent. Pin the listener to loopback or a netns the agent shares — that is the entire transport-layer security for the agent-side connection.

The threat model assumes the agent process is hostile from the moment it starts: full code execution, full read of its own memory, full write to its filesystem, full ability to ingest and act on attacker-controlled content. Doorman exists to constrain what such an agent can *send*, not what it can think.

## Limitations

- **`pid` and `uid` in audit lines are always `-1`.** TCP sockets don't carry peer credentials the way Unix sockets do. If multiple uids on the host can reach the proxy port, you can't distinguish them in the log. The intended deployment has exactly one uid (the agent) able to reach `127.0.0.1:8443`; enforce that with a netns or firewall.
- **Audit gaps on the allow path.** Audit writes for allowed requests happen at end-of-stream. If an audit write fails mid-day (disk full, etc.), the agent has already received the response — doorman logs the failure to stderr and keeps serving. Deny-path audit is still pre-response and hard fails closed.
- **Agent must use `http://` URLs.** Even though the upstream is HTTPS, the agent addresses doorman with `http://` scheme. This trades familiarity for a much smaller proxy and no trust-store install.
- **Upstream port is always 443.** Any port in the agent's URI is ignored. Add a `port` field to the config if you need something else.
- **No HTTP/2, no WebSockets, no SSE keep-alives in any clever way.** HTTP/1.1 only, on both sides. Streaming responses work; they just go through HTTP/1.1 chunked encoding.
- **No upstream connection pooling.** One TLS handshake per upstream request. Adds ~50ms to each request. Boring is good; this is a known cost.
- **No config hot-reload.** Restart the service to pick up changes. Restarts are sub-second; in-flight requests are dropped.
- **No launchd plist.** `install-service` only emits the systemd unit. macOS users write the plist themselves.
- **`install-service` doesn't install.** It prints; you redirect.

## Layout

```
src/main.rs       CLI dispatch (install-service / run)
src/config.rs     YAML loader for /etc/doorman/doorman.yaml
src/audit.rs      JSON-line audit writer, fsync per record
src/proxy.rs      HTTP/1.1 server, header rewrite, upstream TLS, body streaming
```

About 1100 lines total. The whole thing fits on a screen-and-a-half if you `cat src/*.rs`.
