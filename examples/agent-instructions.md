# Instructions to give your coding agent

Drop this content (adapted to your `doorman.yaml`) into whichever file your
agent reads as system instructions:

| Tool | File |
| --- | --- |
| Claude Code | `CLAUDE.md` (project) or `~/.claude/CLAUDE.md` (global) |
| Cursor | `.cursorrules` |
| Aider | a markdown file passed via `aider --read agent-net.md` |
| Custom system prompt | paste into the prompt directly |

Below is the content to drop in. Edit the credential list to match your
own `doorman.yaml`.

---

## Using credentials held by the operator

The operator stores API keys for certain services with **doorman**, a
local HTTP proxy. You do not have those keys directly. When you need to
call one of those services, route the request through doorman and it
will inject the key for you. For any other network access, use the
network as you normally would — doorman is not a network filter.

**Proxy:** `http://127.0.0.1:8443`

**Credentials available** (selected by `X-Doorman-Cred` header):

- `github` — GitHub API at `api.github.com`. Allowed methods: any.
- `github_readonly` — GitHub API, GET only. Prefer this for reads.
- `stripe` — Stripe API at `api.stripe.com`, GET only.
- `slack` — Slack API at `slack.com`.

You name a credential by label. Doorman holds the secret and injects the
auth header. If you target a host the credential is not allowed for,
doorman returns 403 — pick a different credential or stop and ask.

When going through doorman, the URL must use `http://` even though the
upstream is HTTPS — doorman handles the TLS upgrade. Set
`X-Doorman-Cred` on every request; do not set `Authorization` yourself
(doorman overwrites it).

### curl

```sh
curl --proxy http://127.0.0.1:8443 \
     -H 'X-Doorman-Cred: github_readonly' \
     http://api.github.com/repos/acme/widgets/issues
```

### Python (httpx)

```python
import httpx
r = httpx.get(
    "http://api.github.com/repos/acme/widgets/issues",
    headers={"X-Doorman-Cred": "github_readonly"},
    proxy="http://127.0.0.1:8443",
)
```

### Node (undici)

```js
import { fetch, ProxyAgent } from "undici";
const r = await fetch(
  "http://api.github.com/repos/acme/widgets/issues",
  {
    headers: { "X-Doorman-Cred": "github_readonly" },
    dispatcher: new ProxyAgent("http://127.0.0.1:8443"),
  },
);
```

### Don't

- Don't try to read or echo the secret. Doorman never reveals it; only
  the credential's label is meaningful to you.
- Don't set `Authorization` yourself when going through doorman. It will
  be overwritten.
