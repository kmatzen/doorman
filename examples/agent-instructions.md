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

## Network access

You have outbound network access only via doorman, an HTTP forward proxy
running locally. Direct connections to the internet will fail. Use the
proxy for any shell command, generated code, or tool call that needs to
reach the network.

**Proxy:** `http://127.0.0.1:8443`

**Credentials available** (selected by `X-Doorman-Cred` header):

- `github` — GitHub API at `api.github.com`. Allowed methods: any.
- `github_readonly` — GitHub API, GET only. Prefer this for reads.
- `stripe` — Stripe API at `api.stripe.com`, GET only.
- `slack` — Slack API at `slack.com`.

You name a credential by label. Doorman holds the secret and injects the
auth header. If you target a host the credential is not allowed for,
doorman returns 403 — pick a different credential or stop and ask.

The URL must use `http://` even when the upstream is HTTPS — doorman
handles the TLS upgrade. Set `X-Doorman-Cred` on every request; do not
add an `Authorization` header (doorman overwrites it).

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

### What not to do

- Do not attempt to reach the network without the proxy; it will not work.
- Do not try to read or echo the secret. Doorman never reveals it.
- Do not set `Authorization` yourself. Doorman overwrites it.
