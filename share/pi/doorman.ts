/**
 * doorman pi extension — teaches agents to use doorman consistently.
 *
 * 1. Registers the doorman MCP server (share/mcp/doorman-mcp.mjs) so agents
 *    get doorman_credentials / doorman_request tools.
 * 2. Appends a short system-prompt section with the usage rules.
 *
 * Install: symlink or copy into ~/.pi/agent/extensions/. The MCP script is
 * resolved from the DOORMAN_MCP env var, the sibling share/mcp/ path
 * (relative to this file), or ~/git/doorman/share/mcp/doorman-mcp.mjs.
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const candidates = [
  process.env.DOORMAN_MCP,
  path.join(here, "..", "mcp", "doorman-mcp.mjs"),
  path.join(os.homedir(), "git", "doorman", "share", "mcp", "doorman-mcp.mjs"),
].filter((p): p is string => Boolean(p));
const mcpPath = candidates.find((p) => existsSync(p));

const GUIDANCE = `# doorman

Some credentials (API keys) are held by the local doorman proxy, not by you.
To call a service that needs one: call \`doorman_credentials\` to list
credential names and their allowed hosts/methods, then \`doorman_request\`
with the credential — it handles the proxy hop. If you use curl directly:
\`curl --proxy http://127.0.0.1:18443 -H 'X-Doorman-Cred: <name>' http://<host>/...\`
Always use http:// URLs through the proxy; never set Authorization yourself;
a 403 means the credential's allowlist rejects the host or method.
Doorman is not a network filter — use the network normally for everything else.`;

export default function doorman(pi: ExtensionAPI) {
	if (mcpPath) {
		const env: Record<string, string> = { DOORMAN_INSPECT_SUDO: "1" };
		if (process.env.DOORMAN_PROXY) env.DOORMAN_PROXY = process.env.DOORMAN_PROXY;
		pi.registerMcpServer("doorman", {
			command: "node",
			args: [mcpPath],
			...(Object.keys(env).length ? { env } : {}),
		});
	}
	pi.on("before_agent_start", (event) => {
		event.systemPromptOptions.sections.doorman = GUIDANCE;
	});
}
