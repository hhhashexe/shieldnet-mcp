# 🛡️ ShieldNet MCP — Security Scanner for AI Agents

> **Bring security governance to any AI agent deployment via MCP.**
>
> Track: **Secure & Govern MCP** | [MCP_HACK//26](https://aihackathon.dev)

<div align="center">

[![npm](https://img.shields.io/npm/v/shieldnet.svg)](https://www.npmjs.com/package/shieldnet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-75%20passing-brightgreen.svg)](./test/)
[![Node &ge; 18](https://img.shields.io/badge/node-%3E%3D%2018-green.svg)](https://nodejs.org)
[![MCP Server](https://img.shields.io/badge/MCP-Server-blueviolet)](https://modelcontextprotocol.io)

</div>

---

## What It Does

ShieldNet MCP is a **zero-trust guardrail** for AI agents. Before your agent connects to any external endpoint (API, webhook, third-party service), ShieldNet scans it and returns an **ALLOW / WARN / BLOCK** decision — with full findings and severity ratings.

- **Scan URLs** for 50+ checks across 7 security modules
- **Governance decisions** — auto-gate agent connections with ALLOW/WARN/BLOCK
- **Security headers audit** — quick compliance check
- **Side-by-side comparisons** — which endpoint is safer?
- **Session history** — track all scans with grades and scores
- **Pre-built prompts** — security audit & pre-deployment check workflows

## Why It Matters

AI agents increasingly interact with external APIs and services. Without security governance:

- An agent could connect to a compromised endpoint
- Sensitive data could leak through misconfigured CORS
- Injection attacks could manipulate agent behavior

ShieldNet acts as a **security guardrail** — scan first, connect later.

## Architecture

```
┌──────────┐       ┌───────────────────────┐
│          │       │    agentgateway       │
│  AI Agent│──────▶│  ┌─────────────────┐  │      ┌────────═══════┐
│ (Claude, │       │  │  🔗 ShieldNet   │  │      │  External     │
│  GPT,    │◀──────│  │  MCP Server     │──┼─────▶│  Service      │
│  etc.)   │       │  │                 │  │      │  (target URL) │
│          │       │  │  ┌───────────┐  │  │      │               │
└──────────┘       │  │  │ Scanners  │  │  │      └───────────────┘
                   │  └──┼───────────┼──┘  │
                   │     │              │  │
                   │  ┌──▼──┐ ┌───────▼──┐ │
                   │  │Headers│ │Injection │ │
                   │  │ TLS  │ │Info Disc │ │
                   │  │ Auth │ │Misconfig  │ │
                   │  │Rate  │ │          │ │
                   │  │Limit │ │          │ │
                   │  └──────┘ └──────────┘ │
                   │  ALLOW / WARN / BLOCK  │
                   └────────────────────────┘
```

**Flow:**
1. AI agent requests external connection
2. **agentgateway** routes to ShieldNet MCP
3. **ShieldNet** runs 7 scanner modules in parallel
4. Returns **ALLOW/WARN/BLOCK** + detailed findings
5. agentgateway enforces the decision

### Scanner Modules (7)

| # | Module | What It Checks |
|---|--------|----------------|
| 1 | `security_headers` | HSTS, CSP, X-Frame-Options, Cookie flags, CORS wildcards, info disclosure |
| 2 | `injection` | Reflected XSS, SQLi, SSTI, Command Injection, Path Traversal, SSRF, Open Redirect |
| 3 | `info_disclosure` | 25 sensitive paths (.env, .git, package.json, swagger, backups, server-status) |
| 4 | `tls` | HTTP vs HTTPS, SSL/TLS redirect enforcement |
| 5 | `auth` | JWT exposure, JWT `alg:none`, API keys in source, email harvesting |
| 6 | `misconfiguration` | CORS origin reflection, TRACE method, version disclosure in error pages |
| 7 | `rate_limiting` | 20-request burst test (aggressive mode only) |

## Quick Start

### 1. Install

```bash
git clone https://github.com/hhhashexe/shieldnet-mcp.git
cd shieldnet-mcp
npm install
```

### 2. Run a demo scan (no setup needed)

```bash
bash demo.sh https://example.com
```

This launches the MCP server, discovers available tools via `tools/list`, runs a live scan, and pretty-prints the results with colors. 🤙

### 3. Run the test suite

```bash
npm test
```

75 integration tests covering all 6 MCP tools, 6 tools + 3 resources + 2 prompts.

### 4. Use as an MCP Server

#### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shieldnet": {
      "command": "node",
      "args": ["/path/to/shieldnet-mcp/src/index.js"]
    }
  }
}
```

#### With agentgateway

```yaml
targets:
  - name: shieldnet-security
    provider:
      type: mcp
      config:
        command: node
        args: ["src/index.js"]
```

See [agentgateway.yaml](./agentgateway.yaml) for full configuration.

#### Raw JSON-RPC (stdio)

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"my-agent","version":"0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_url","arguments":{"url":"https://example.com"}}}' | node src/index.js
```

## MCP Tools

| Tool | Description |
|------|-------------|
| [`scan_url`](#) | Comprehensive scan — 7 modules, 50+ checks, A-F grade |
| [`assess_risk`](#) | Scan + governance decision (ALLOW/WARN/BLOCK) with confidence score |
| [`check_headers`](#) | Quick security headers audit — PASS/WARN/FAIL verdict |
| [`scan_history`](#) | Session scan history with grades |
| [`compare_scans`](#) | Side-by-side comparison of two URLs |
| [`governance_policy`](#) | View policy or evaluate a score against thresholds |

## MCP Resources

| Resource | Description |
|----------|-------------|
| `shieldnet://attack-vectors` | Full attack vector database |
| `shieldnet://scan-history` | Session scan history |
| `shieldnet://governance-policy` | ALLOW/WARN/BLOCK thresholds |

## MCP Prompts

| Prompt | Description |
|--------|-------------|
| `security_audit` | Full audit with executive report |
| `pre_deployment_check` | Gate check before deployment |

## Security Governance

ShieldNet makes ALLOW/WARN/BLOCK decisions based on:

```
ALLOW  → Score ≥ 70, no critical findings
WARN   → Score 50-69, or high-severity findings
BLOCK  → Score < 50, or any critical vulnerabilities
```

### Real-World Proof

ShieldNet has been used in production security audits:

- **3 CVEs** discovered and responsibly disclosed
- **PayLock.xyz audit**: 36 verified findings (4 Critical, 17 High)
- Published on npm as `shieldnet` (v0.3.2)

## License

MIT — see [LICENSE](./LICENSE)

## Links

- [npm: shieldnet](https://www.npmjs.com/package/shieldnet)
- [GitHub: ShieldNet](https://github.com/hhhashexe/shieldnet)
