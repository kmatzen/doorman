#!/usr/bin/env node
// doorman MCP server — stdio, no dependencies, Node >= 18.
//
// Lets agents use doorman without knowing the curl plumbing:
//   doorman_credentials  — which credentials exist and where they may go (never secrets)
//   doorman_request      — issue a request through the proxy correctly
//
// Policy comes ONLY from `doormand inspect --json` (doorman >= 0.1.11) —
// always fresh, never any secret value. The 0400 daemon-owned config isn't
// readable by the agent's uid, so set DOORMAN_INSPECT_SUDO=1 with a NOPASSWD
// sudoers line for just that command. The old file-based fallback is
// deleted: its sed redaction only stripped line-leading "secret:" lines, so
// flow-style YAML entries leaked real keys into a file this server read.
// Env: DOORMAN_PROXY, DOORMAN_INSPECT_SUDO.

import { existsSync } from "node:fs";
import { spawnSync, spawn } from "node:child_process";
import path from "node:path";

const PROXY = process.env.DOORMAN_PROXY || "http://127.0.0.1:18443";
const MAX_BODY = 64 * 1024;

// Only policy source: `doormand inspect --json` (doorman >= 0.1.11).
// Needs either a readable config or passwordless sudo (DOORMAN_INSPECT_SUDO=1).
// Returns the parsed payload, or null (recording the reason in `inspectError`).
let inspectError = "";
function inspectPolicy() {
  // PATH first (test fakes, custom installs), then common install dirs.
  const doormand =
    process.env.DOORMAND_PATH ||
    (process.env.PATH || "")
      .split(path.delimiter)
      .map((d) => path.join(d, "doormand"))
      .concat("/opt/homebrew/bin/doormand", "/usr/local/bin/doormand", "/usr/bin/doormand")
      .find((p) => existsSync(p));
  if (!doormand) {
    inspectError = "doormand not found";
    return null;
  }
  const variants = process.env.DOORMAN_INSPECT_SUDO === "1"
    ? [ ["sudo", "-n", doormand, "inspect", "--json"],
        [doormand, "inspect", "--json"] ]
    : [ [doormand, "inspect", "--json"] ];
  for (const cmd of variants) {
    const r = spawnSync(cmd[0], cmd.slice(1), { encoding: "utf8", timeout: 10000 });
    if (r.status === 0) {
      try { return JSON.parse(r.stdout); } catch { inspectError = "unparsable inspect output"; }
    } else {
      inspectError = (r.stderr || `${cmd.join(" ")} exited ${r.status}`).trim();
    }
  }
  return null;
}

// Payload contract: {"credentials":[{name,hosts,methods,port,tls},...]}; a bare
// array is tolerated for robustness. Never contains secret values.
function loadPolicy() {
  const p = inspectPolicy();
  if (!p) {
    throw new Error(
      `cannot read policy: ${inspectError}. Requires doormand >= 0.1.11 with ` +
        "`doormand inspect --json`; the config is 0400 daemon-owned, so add a " +
        "sudoers line `<user> ALL=(root) NOPASSWD: /usr/local/bin/doormand inspect --json` " +
        "and set DOORMAN_INSPECT_SUDO=1.",
    );
  }
  return Array.isArray(p) ? p : p.credentials;
}

// --- tools ---------------------------------------------------------------

async function toolCredentials() {
  const entries = loadPolicy().map((e) => ({
    name: e.name,
    hosts: e.hosts,
    methods: Array.isArray(e.methods) && e.methods.length ? e.methods : "(any)",
    ...(e.port && e.port !== 443 ? { port: Number(e.port) } : {}),
    ...(e.tls === false || e.tls === "false" ? { tls: false } : {}),
  }));
  return {
    proxy: PROXY,
    credentials: entries,
    usage: [
      "Call doorman_request with a credential name — it handles the proxy and X-Doorman-Cred header.",
      "Or use curl yourself: curl --proxy " + PROXY + " -H 'X-Doorman-Cred: <name>' http://<host>/...",
      "Always use http:// URLs through the proxy (doorman re-originates TLS). Never set Authorization yourself.",
      "A 403 means the credential's allowlist rejects the host or method.",
    ],
  };
}

function curlViaProxy(cred, url, method, headers, body) {
  const u = url.replace(/^https:\/\//, "http://");
  const args = [
    "-sS",
    "--proxy", PROXY,
    "--max-time", "60",
    "-X", method,
    "-H", `X-Doorman-Cred: ${cred}`,
    "-D", "-", // headers on stdout first
    "-w", "\n__STATUS__:%{http_code}",
  ];
  for (const [k, v] of Object.entries(headers || {})) args.push("-H", `${k}: ${v}`);
  if (body !== undefined) args.push("--data-binary", "@-");
  args.push(u);
  return new Promise((resolve, reject) => {
    const p = spawn("curl", args, { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", reject);
    p.on("close", (code) =>
      code === 0 ? resolve({ out, err }) : reject(new Error(err || `curl exited ${code}`)),
    );
    if (body !== undefined) p.stdin.end(body);
    else p.stdin.end();
  });
}

async function toolRequest({ url, credential, method = "GET", headers, body }) {
  const { out } = await curlViaProxy(credential, url, method, headers, body);
  const statusLine = out.match(/\n__STATUS__:(\d+)$/)?.[1];
  const stripped = out.replace(/\n__STATUS__:\d+$/, "");
  const sep = stripped.indexOf("\r\n\r\n");
  const head = sep >= 0 ? stripped.slice(0, sep) : stripped;
  let text = sep >= 0 ? stripped.slice(sep + 4) : "";
  let truncated = false;
  if (text.length > MAX_BODY) {
    text = text.slice(0, MAX_BODY);
    truncated = true;
  }
  return {
    status: Number(statusLine) || null,
    headers: head.split("\r\n").filter(Boolean),
    body: text,
    ...(truncated ? { truncated: true, note: `body cut to ${MAX_BODY} bytes` } : {}),
  };
}

const TOOLS = [
  {
    name: "doorman_credentials",
    description:
      "List the credentials doorman holds: name, allowed hosts, allowed methods. " +
      "Never returns secrets. Call this before doorman_request to pick a credential.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "doorman_request",
    description:
      "Send an HTTP request through the doorman proxy. doorman injects the named " +
      "credential's auth header and enforces its host/method allowlist (403 otherwise). " +
      "Use an http(s):// URL to the real upstream; doorman handles the proxy hop.",
    inputSchema: {
      type: "object",
      required: ["url", "credential"],
      properties: {
        url: { type: "string", description: "Upstream URL, e.g. https://api.example.com/v1/x" },
        credential: { type: "string", description: "Credential name from doorman_credentials" },
        method: { type: "string", default: "GET", description: "HTTP method (default GET)" },
        headers: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "Extra request headers (do not set Authorization — doorman overwrites it)",
        },
        body: { type: "string", description: "Request body (POST/PUT/PATCH/DELETE)" },
      },
    },
  },
];

// --- MCP over stdio (newline-delimited JSON-RPC 2.0) -----------------------

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function handle(msg) {
  const { id, method, params } = msg;
  if (method === "initialize") {
    return {
      protocolVersion: params.protocolVersion || "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "doorman", version: "0.1.0" },
    };
  }
  if (method === "ping") return {}; // spec: must be answered, empty result
  if (method === "tools/list") return { tools: TOOLS };
  if (method === "tools/call") {
    const { name, arguments: args = {} } = params;
    try {
      let result;
      if (name === "doorman_credentials") result = await toolCredentials();
      else if (name === "doorman_request") result = await toolRequest(args);
      else throw new Error(`unknown tool: ${name}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (e) {
      return {
        content: [{ type: "text", text: `doorman error: ${e.message}` }],
        isError: true,
      };
    }
  }
  return undefined; // unhandled: reply -32601 if it has an id, else notification (silent)
}

let buf = "";
let inflight = 0;
process.stdin.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.method === "notifications/initialized") continue;
    inflight++;
    handle(msg).then(
      (result) => {
        if (msg.id === undefined) return; // notifications get no reply
        if (result === undefined) {
          send({
            jsonrpc: "2.0",
            id: msg.id,
            error: { code: -32601, message: `method not found: ${msg.method}` },
          });
        } else {
          send({ jsonrpc: "2.0", id: msg.id, result });
        }
      },
      (e) =>
        send({
          jsonrpc: "2.0",
          id: msg.id,
          error: { code: -32000, message: e.message },
        }),
    ).finally(() => {
      inflight--;
      if (stdinClosed && inflight === 0) process.exit(0);
    });
  }
});
let stdinClosed = false;
process.stdin.on("close", () => {
  stdinClosed = true;
  if (inflight === 0) process.exit(0);
});
