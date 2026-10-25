# Migrating from doorman to nono

Doorman is deprecated for new deployments and is in maintenance mode. Existing
deployments remain supported and will continue to receive critical security and
compatibility fixes, but
[nono](https://github.com/nolabs-ai/nono) is the recommended starting point for
new agent-security deployments.

There is no scheduled doorman end-of-life date. Migrate only after validating
your workload: nono covers a broader problem and is not a drop-in replacement
for doorman's protocol or deployment model.

## Decide whether to migrate

Prefer nono when you need more than credential forwarding, including:

- filesystem and process restrictions around an agent;
- domain- and path-level network policy;
- separate policies for tools launched by an agent;
- credential providers such as an OS keyring, 1Password, or Bitwarden;
- rate limiting, HTTP/2, OAuth, or AWS request signing.

Keep doorman for now when a required deployment depends on:

- a small, independently supervised proxy running under a dedicated uid;
- an audit record flushed for each completed request;
- the existing `X-Doorman-Cred` request protocol;
- plaintext LAN upstreams or pinned self-signed upstream certificates; or
- behavior that has not yet passed a nono compatibility test.

Doorman protects credentials but does not restrict an agent's other network or
filesystem access. Nono's broader sandbox can reduce that ambient authority, but
it is a capability boundary rather than a VM or separate-kernel boundary. Read
nono's [security model](https://github.com/nolabs-ai/nono/blob/main/docs/cli/internals/security-model.mdx)
before selecting the deployment boundary.

## Concept mapping

| doorman | nono | Migration note |
| --- | --- | --- |
| `X-Doorman-Cred` | credential route and a session-scoped phantom token | Client configuration changes are required; the header protocol is not compatible. |
| `hosts` | credential `upstream` plus domain policy | Confirm redirects and every required hostname explicitly. |
| `methods` | credential `endpoint_rules` | Add method/path rules; do not silently replace a narrow method list with unrestricted paths. |
| `inject` | `inject_header` and `credential_format` | Test the exact header syntax expected by the upstream. |
| literal `secret` in mode-0400 YAML | `credential_key` backed by a supported provider | Move the value into a keyring or secret provider; never copy it into a committed profile. |
| `tls_pinned_sha256` | no assumed equivalent | Keep doorman unless certificate-pinning behavior has been independently verified. |
| `tls: false` for a LAN device | HTTP is limited by nono's current upstream rules | Keep doorman for non-local plaintext upstreams; never weaken transport merely to complete migration. |
| dedicated doorman uid | nono supervisor outside the child sandbox | These are different process boundaries. Validate against your threat model. |
| per-request JSONL plus `fsync` | nono session audit and ledger | Nono documents finalization-time durability; test forced termination if forensic completeness matters. |

See nono's current documentation for
[credential injection](https://github.com/nolabs-ai/nono/blob/main/docs/cli/features/credential-injection.mdx),
[networking and standalone proxy mode](https://github.com/nolabs-ai/nono/blob/main/docs/cli/features/networking.mdx),
and [audit behavior](https://github.com/nolabs-ai/nono/blob/main/docs/cli/features/audit.mdx).
Because nono is pre-1.0, use the documentation from the exact release you test,
not an unpinned `main` branch, when writing production policy.

## Example policy translation

This doorman entry allows a GitHub credential only on `GET` requests:

```yaml
- name: github_readonly
  secret: REPLACE_ME
  inject: "Authorization: Bearer {}"
  hosts: [api.github.com]
  methods: [GET]
```

A corresponding nono profile starts with a custom credential and an endpoint
rule. The credential itself belongs in the referenced provider, not in the
profile:

```json
{
  "meta": { "name": "agent-with-github-readonly" },
  "network": {
    "network_profile": "minimal",
    "credentials": ["github_readonly"],
    "custom_credentials": {
      "github_readonly": {
        "upstream": "https://api.github.com",
        "credential_key": "keyring://nono/github",
        "env_var": "GH_TOKEN",
        "inject_header": "Authorization",
        "credential_format": "Bearer {}",
        "endpoint_rules": [
          { "method": "GET", "path": "/**" }
        ]
      }
    }
  }
}
```

Treat this as a translation example, not a production-ready universal profile.
Validate it against the schema and documentation shipped with your pinned nono
release. In particular, verify how the selected client discovers the generated
base URL and phantom credential; existing calls that set `X-Doorman-Cred` will
not work unchanged.

## Staged migration runbook

### 1. Inventory

For every doorman credential, record:

- upstream host and port;
- allowed methods and required paths;
- injection header and format;
- TLS mode, including pins and plaintext exceptions;
- calling clients, including WebSocket and redirect behavior;
- audit retention and durability requirements; and
- the rollback owner.

Do not put secret values in the inventory.

### 2. Pin and prepare

Choose an explicit nono release, verify its release artifacts, and record the
version with the deployment configuration. Create a local profile and move each
secret from `doorman.yaml` into a supported credential provider. Keep the
existing doorman service and configuration intact for rollback.

Do not route a request through both proxies. Chaining them obscures which policy
authorized the request, complicates auditing, and creates ambiguous failure
modes. Instead, select one proxy per client or isolated test workload.

### 3. Pilot in isolation

Run a non-production agent or client under nono and exercise both allowed and
denied cases. At minimum, verify:

- the child cannot read the real credential;
- expected hosts, methods, and paths succeed;
- unlisted hosts, methods, and paths fail closed;
- direct connections cannot bypass the proxy where that guarantee is required;
- redirects cannot move a credential to another origin;
- client-specific HTTP, HTTP/2, and WebSocket behavior;
- DNS failure and TLS failure remain fail-closed; and
- audit records contain the required attribution without secret material.

Repeat the test on every supported operating system. Nono's Linux, macOS, and
WSL2 enforcement characteristics differ.

### 4. Cut over one workload

Stop the selected client, switch its launcher and client configuration to the
pinned nono profile, then restart it. Keep doorman available to other workloads;
do not share or duplicate live traffic between proxies. Monitor denials,
upstream errors, latency, and missing audit events for an agreed observation
window.

Rollback means stopping the client, restoring its previous proxy/header
configuration, and restarting it against the unchanged doorman service. Do not
copy a secret out of its provider as part of rollback.

### 5. Retire deliberately

A deployment can remove doorman only after all of the following are true:

- every credential route has an owner and a tested nono policy;
- positive and negative policy tests pass on supported platforms;
- LAN, certificate, WebSocket, redirect, and client-specific requirements pass;
- audit durability and retention meet operational requirements;
- rollback has been exercised; and
- no remaining client uses `X-Doorman-Cred`.

Project-wide archival is a separate decision. It should happen only after known
deployments have migrated or explicitly accepted remaining on a final
maintenance release, and after an end-of-life date has been announced with an
appropriate notice period.
