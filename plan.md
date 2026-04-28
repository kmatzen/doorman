# Doorman — v1

## What it does

Holds static credentials. Injects them into outgoing HTTP requests bound for allowed hosts. Logs every request. Nothing else.

## What it does not do

No OAuth, no refresh, no signing, no capabilities, no approval flows, no sandbox helpers, no per-agent identity beyond OS uid, no secrets-manager integration, no SDK, no web UI, no hosted mode, no MCP, no plugins. No TLS interception, no CA, no trust-store install ritual.

If you find yourself adding any of these, it's a different project. Fork it.

## Architecture

One binary. One config file. One socket.

```
agent  ──HTTP_PROXY──▶  doormand  ──TLS──▶  upstream API
   (plaintext)             │
                           ├── reads creds.yaml at startup
                           └── appends to audit.log
```

The agent runs as one uid. `doormand` runs as another. The agent's only network egress is through the proxy. That's the entire security model.

Doorman is a plain HTTP forward proxy on the agent side and a TLS client on the upstream side. The agent talks to it in cleartext over loopback (or a netns boundary), so doorman can read and rewrite headers without the gymnastics of a TLS-intercepting MITM. The agent uses `http://api.github.com/...` URLs in code; doorman upgrades to TLS for the upstream connection.

## Config

One file, `/etc/doorman/doorman.yaml`, mode `0400`, owned by the doorman uid:

```yaml
- name: github
  secret: ghp_xxxxxxxxxxxx
  inject: "Authorization: Bearer {}"
  hosts: [api.github.com]

- name: slack
  secret: xoxb-xxxxxxxxxxxx
  inject: "Authorization: Bearer {}"
  hosts: [slack.com]

- name: stripe
  secret: sk_live_xxxxxxxxxxxx
  inject: "Authorization: Bearer {}"
  hosts: [api.stripe.com]
  methods: [GET]
```

Five fields. `name` is what the agent puts in `X-Doorman-Cred` to select this credential. `secret` is the string. `inject` is the header template doorman writes on the outgoing request. `hosts` is the allowlist. `methods` is optional and defaults to all.

That's the whole config language. No conditionals, no templating beyond `{}`, no includes, no environments. If you need two scopes for the same secret, you write two entries.

## How it works

Agent sets `HTTP_PROXY=http://127.0.0.1:8443`. Agent writes a request like:

```
GET http://api.github.com/repos/acme/widgets/issues HTTP/1.1
Host: api.github.com
X-Doorman-Cred: github
```

(Either absolute-form URI or origin-form with a `Host` header is fine; doorman accepts both. The agent uses the `http://` scheme — the actual HTTPS upgrade happens on the upstream side.)

Doorman:

1. Resolves the upstream host from the URI authority or the `Host` header. No host → 400, log, drop.
2. Reads the `X-Doorman-Cred` header (must be present, exactly one, non-empty). Looks up the named credential in the config. Not found → 403, log, drop.
3. Checks resolved host against the credential's `hosts`. Not allowed → 403, log, drop.
4. Checks method against `methods`. Not allowed → 403, log, drop.
5. Drops the `X-Doorman-Cred` header (it must not leak upstream). Drops hop-by-hop headers. Inserts the templated header (`Authorization: Bearer ghp_xxxxxxxxxxxx`), overwriting any auth header the agent set.
6. TLS-connects to the upstream on port 443 and forwards the request, body streamed.
7. Returns the response, body streamed back. Strips `Set-Cookie` and `WWW-Authenticate` from the response.
8. Appends one line to the audit log when the response body finishes streaming.

Step 7 is the one piece of "smart" behavior worth keeping, because some upstreams reflect auth material in error responses and the agent shouldn't see it. Everything else passes through untouched.

## Audit log

One line per request, JSON, append-only:

```json
{"ts":"2026-04-27T14:22:01Z","cred":"github","host":"api.github.com","method":"GET","path":"/repos/acme/widgets/issues","status":200,"bytes_in":0,"bytes_out":8421,"ms":234,"decision":"allow"}
```

No bodies. No headers. No secret. No peer pid or uid — TCP listening means there's no `SO_PEERCRED` to read, and a field that's always the same value is noise. The intended deployment is one agent uid per doorman; if you have multiple agents whose traffic you want to separate, run multiple daemons. The path is logged because operators need to debug; if a path contains a secret (it shouldn't, but APIs are weird), that's an upstream problem, not doorman's.

## Security properties

These are the things doorman guarantees, stated plainly:

1. The agent's process never holds the secret in memory, env, filesystem, or any response from doorman.
2. A secret is only ever sent to a host explicitly allowlisted for it.
3. Every request is logged.
4. Doorman runs as a different uid from the agent, with `NoNewPrivileges`, dropped capabilities, and `PR_SET_DUMPABLE=0`. The agent cannot ptrace it or read its memory.
5. The config file is unreadable by the agent uid.

These are the things doorman does *not* guarantee, also stated plainly:

1. That the agent uses its allowed access wisely. An allowed GitHub write can still open spam issues.
2. That an upstream API doesn't echo your token back in a body. (Headers, yes; bodies, no.)
3. That a kernel exploit, sandbox escape, or compromise of the doorman binary itself doesn't defeat everything.
4. That the agent can't enumerate what's allowed by trial and error.
5. That a third party who can reach doorman's listening port can't issue requests as the agent. Pin the listener to loopback or a netns the agent shares; nothing more clever than that.

## Implementation

Rust. One crate, no plugins, no dynamic loading. Dependencies: `tokio`, `hyper`, `rustls`, `serde`, `serde_yaml`. That's it. No `reqwest` (use `hyper` directly), no async runtime gymnastics, no feature flags.

Target: 800–1200 lines. If it grows past 1500, something has crept in that doesn't belong.

There is no non-trivial piece. No CA, no per-host leaf cert minting, no TLS server side. Just an HTTP/1.1 server, a header rewriter, and a TLS client. Boring is the goal.

## Install and run

```
brew install doorman
$EDITOR /etc/doorman/doorman.yaml
sudo doorman install-service    # writes systemd unit or launchd plist
sudo systemctl start doorman
```

Agent side:

```
export HTTP_PROXY=http://127.0.0.1:8443
```

Use `http://` URLs in agent code (e.g. `http://api.github.com/...`). Doorman upgrades to TLS for the upstream.

Five minutes, one config file, one env var. If it takes longer than that, the install story is wrong and that's the bug to fix before adding anything else.

## What "extremely well" means

Three things, and they're the ones to obsess over:

**Correctness of the security boundary.** The `inject` substitution must be impossible to trick. The host allowlist must match the actual upstream after redirects (don't follow redirects across hosts; return the 3xx to the agent and let it decide). The audit log must flush on every line, not buffer. The config reload must not race with in-flight requests. These are unsexy and they are the entire job.

**Operational quietness.** Doorman should be the boring service in the rack. No surprises on restart. No memory growth. No log spam. No required updates. If someone forgets it's running for six months, that's success.

**Failure modes that fail closed.** Config unparseable → refuse to start. Upstream cert invalid → 502, don't fall back. Allowlist match ambiguous → deny. Audit log unwritable → refuse to serve. Every fork in the road, the safe direction is the default.

## What I'd cut from this if pushed further

If "simple" gets pushed harder, the things that go next are:

- The `Set-Cookie` / `WWW-Authenticate` response header stripping. Document the risk and let the operator deal with upstreams that reflect creds.
- The method-scoping field. Hosts only; if you want method-level control, use two credential entries with different names.
- The `install-service` subcommand. Document the systemd unit in the README.

What does *not* get cut, ever:

- The audit log.
- The host allowlist.
- The uid separation.
- The single-binary, single-config-file install.

## Things explicitly already cut

These were in earlier drafts and were dropped:

- **Unix socket mode.** HTTP forward-proxy only, on TCP loopback.
- **HTTPS_PROXY / CONNECT / TLS interception.** Plain HTTP between agent and doorman; the CA, leaf-cert minting, and trust-store install ritual all went with it. Doorman still TLS-connects to the upstream.
- **OAuth, refresh, approval flows, capabilities, SDKs.** Out of scope from the start.

## The pitch in one line

Doorman is an HTTP proxy that holds your API keys and refuses to send them anywhere they don't belong. That's it.
