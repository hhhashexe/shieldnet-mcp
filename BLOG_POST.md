# I Built a Security Scanner for AI Agents Using MCP — Here's How It Works

> AI agents are connecting to the wild internet with zero guardrails. I built something to fix that.

---

## The Problem Is Real

Here's a scenario that keeps me up at night: your AI agent, happily powered by Claude or GPT, is told to fetch data from an external API. It constructs a URL, sends a request, and starts processing the response. But what if that endpoint is compromised? What if it has open redirects, exposed `.env` files, or worse — what if it's actively returning injected payloads that the agent blindly trusts?

AI agents are the fastest-growing class of software deployment. Every day, new agentic systems are wired up to third-party APIs, webhooks, and cloud services. **And almost none of them have any security validation before making a connection.**

Think about that. We put more security checks on a Docker container pulling an image than we do on an AI agent making its first HTTP call.

Last month, I decided to build something about it. The result is **ShieldNet MCP** — a zero-trust security guardrail for AI agents, built on the Model Context Protocol (MCP) and written in Node.js.

---

## What ShieldNet Does

ShieldNet is an MCP server that exposes security scanning tools to any MCP-compatible AI agent. Before your agent connects to any external endpoint, ShieldNet scans it and returns an **ALLOW / WARN / BLOCK** decision — with full findings, severity ratings, and remediation advice.

Here's what it checks across **7 scanner modules** with **50+ individual security checks**:

| Module | What It Checks |
|--------|---------------|
| **Security Headers** | HSTS, CSP, X-Frame-Options, CORS wildcards, cookie flags (HttpOnly, Secure, SameSite) |
| **Injection** | Reflected XSS, SQLi (boolean/UNION), Server-Side Template Injection, Command Injection, Path Traversal, SSRF, Open Redirect |
| **Info Disclosure** | 25 sensitive paths: `.env`, `.git/config`, `.git/HEAD`, `swagger.json`, `backup.sql`, `server-status`, `phpinfo.php`, and more |
| **TLS Configuration** | HTTP vs HTTPS, redirect enforcement, SSL availability |
| **Authentication Issues** | JWT exposure, JWT `alg:none` vulnerability, API keys in page source, password leakage, email harvesting |
| **Misconfigurations** | CORS origin reflection, TRACE method, version disclosure in error pages |
| **Rate Limiting** | 20-request burst test (aggressive mode) |

After scanning, ShieldNet computes a weighted security score (0-100) and assigns a letter grade (A through F), then applies a governance policy:

- **ALLOW**: Score ≥ 70, no critical findings — the agent can proceed.
- **WARN**: Score 50–69 or high-severity findings — proceed with caution.
- **BLOCK**: Score < 50 or any critical vulnerabilities — the agent must not connect.

---

## How It Works: MCP + agentgateway Integration

ShieldNet runs as a standard MCP server over stdio. That means any MCP-compatible client — Claude Desktop, Cursor, or any custom agent — can discover and call its tools with zero network configuration.

```
┌──────────┐       ┌───────────────────────┐
│  AI Agent│─────▶ │    agentgateway       │
│ (Claude, │       │  ┌─────────────────┐  │
│  GPT,    │◀─────│  │  🛡️ ShieldNet   │  │──▶ External Service
│  etc.)   │       │  │  MCP Server     │  │   (target URL)
└──────────┘       │  └─────────────────┘  │
                   └───────────────────────┘
```

The flow is simple:

1. Your AI agent requests a connection to an external URL.
2. **agentgateway** (Solo.io's AI-native proxy) routes the request through ShieldNet MCP.
3. ShieldNet runs all 7 scanner modules in parallel (using `Promise.allSettled` — yes, it's fast).
4. The agent receives an ALLOW, WARN, or BLOCK decision with supporting evidence.
5. agentgateway enforces the decision — the agent only connects if cleared.

### Kubernetes Integration

For production deployments, ShieldNet integrates natively with [agentgateway](https://github.com/solo-io/agentgateway) as an `AgentgatewayBackend`:

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: shieldnet-security
spec:
  mcp:
    targets:
      - name: shieldnet-scanner
        static:
          host: shieldnet-mcp-scanner.default.svc.cluster.local
          port: 80
          protocol: StreamableHTTP
```

It also works as a `RemoteMCPServer` in [kagent](https://github.com/kagent-dev/kagent), making it a first-class security tool for Kubernetes-native AI agents.

---

## Code Examples

ShieldNet uses the standard MCP JSON-RPC 2.0 protocol over stdio. Here are the two most important tools in action.

### Scanning a URL

The `scan_url` tool runs all 7 modules and returns a full security report:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "scan_url",
    "arguments": {
      "url": "https://example.com",
      "mode": "aggressive"
    }
  }
}
```

You can run it directly from your terminal:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"my-agent","version":"0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_url","arguments":{"url":"https://example.com"}}}' | node src/index.js
```

No API keys, no external services, no configuration. It just works.

### Using the Governance Gate

The `assess_risk` tool is the real star — it's the guardrail that actually tells your agent what to do:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "assess_risk",
    "arguments": {
      "url": "https://api.untrusted-service.com",
      "context": "pre-deployment"
    }
  }
}
```

This returns a structured governance assessment:

```json
{
  "decision": "BLOCK",
  "confidence": 0.95,
  "score": 32,
  "grade": "F",
  "url": "https://api.untrusted-service.com",
  "reasoning": "3 critical + 5 high-severity findings. Deployment BLOCKED.",
  "blocking_issues": [
    { "severity": "critical", "vector": "info_disclosure", "detail": "Environment file — may contain API keys, DB credentials: /.env" },
    { "severity": "critical", "vector": "sqli", "detail": "Potential SQL Injection (boolean-based) in parameter 'id'" },
    { "severity": "critical", "vector": "cors_wildcard", "detail": "CORS reflects arbitrary origin — full CSRF possible" },
    { "severity": "high", "vector": "tls_config", "detail": "Site uses HTTP — all traffic is unencrypted" }
  ],
  "recommendations": [
    "URGENT: Fix all critical vulnerabilities before any deployment",
    "HIGH: Address high-severity findings within 48 hours",
    "MEDIUM: Schedule medium-severity fixes in next sprint"
  ],
  "policy": "ShieldNet Governance Policy v1.0"
}
```

Your agent reads this JSON, sees `"decision": "BLOCK"`, and knows not to connect. No human in the loop needed.

### Side-by-Side Comparison

Evaluating two endpoints? The `compare_scans` tool runs both in parallel and tells you which is safer:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "compare_scans",
    "arguments": {
      "url1": "https://api-v1.example.com",
      "url2": "https://api-v2.example.com"
    }
  }
}
```

Returns which URL has the higher score and by how much. Useful for migration decisions.

---

## Real Scan Output

Here's what an actual scan against `https://example.com` looks like:

```
URL:    https://example.com
Grade:  D
Score:  54
Duration: 2.3s

Security Summary:
  Critical: 0
  High:     0
  Medium:   12
  Low:      2
  Info:     2

Governance Decision: WARN
  12 medium-severity findings detected. Proceed with caution.

Modules Run: security_headers, injection, info_disclosure,
             tls, auth, misconfiguration
```

Even `example.com` — a site maintained by IANA — scores a D. It's missing HSTS, CSP, X-Frame-Options, and a dozen other headers. This is the internet for you: everything has at least *some* exposure.

When you scan an unhardened dev server or misconfigured API, you'll see grades of F with critical findings like exposed `.env` files, SQL injection vectors, or CORS credentials with wildcard origins. Those are the scans that actually block deployments.

---

## Available Tools and Resources

ShieldNet exposes **6 MCP tools**, **3 resources**, and **2 prompts**:

### Tools
- **`scan_url`** — Full 7-module security scan with A-F grade
- **`assess_risk`** — Governance gate: ALLOW/WARN/BLOCK decision
- **`check_headers`** — Quick security headers audit (PASS/WARN/FAIL)
- **`scan_history`** — Session scan history with grades
- **`compare_scans`** — Side-by-side comparison of two URLs
- **`governance_policy`** — View policy or evaluate a score

### Resources
- `shieldnet://attack-vectors` — Full attack vector database
- `shieldnet://scan-history` — Session scan history
- `shieldnet://governance-policy` — Governance thresholds

### Prompts
- **`security_audit`** — Full audit with executive report
- **`pre_deployment_check`** — Gate check before deployment

---

## Getting Started

Installation takes 30 seconds:

```bash
git clone https://github.com/hhhashexe/shieldnet-mcp.git
cd shieldnet-mcp
npm install
```

Run a demo scan immediately:

```bash
bash demo.sh https://example.com
```

Or integrate with Claude Desktop by adding to your `claude_desktop_config.json`:

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

The test suite has **75 passing tests** covering all 6 tools, 3 resources, and 2 prompts:

```bash
npm test
```

---

## Why I Built This

The AI agent ecosystem is moving fast. MCP is becoming the standard way for agents to talk to tools and services. But nobody was building the security layer.

ShieldNet was built for the [MCP_HACK//26 hackathon](https://aihackathon.dev) by Solo.io and the CNCF, targeting the "Secure & Govern MCP" track. But it's not just a hackathon project — the architecture is designed for production. It works with [agentgateway](https://github.com/solo-io/agentgateway) as a native MCP backend, integrates with [kagent](https://github.com/kagent-dev/kagent) as a security ToolServer, and runs standalone as a simple Node.js process.

It's already been used in real security audits — 3 CVEs discovered and responsibly disclosed, 36 verified findings on a production audit.

---

## Open Source

ShieldNet MCP is **MIT licensed** and available on:

- **GitHub**: [https://github.com/hhhashexe/shieldnet-mcp](https://github.com/hhhashexe/shieldnet-mcp)
- **npm**: [shieldnet](https://www.npmjs.com/package/shieldnet)
- **Node.js**: v18+, zero dependencies (just `@modelcontextprotocol/sdk`)

The entire server is a single file (`src/index.js`, ~650 lines) — readable, auditable, hackable. No magic, no black boxes.

---

## What's Next

- Docker container for easy Kubernetes deployment
- OTel/OpenTelemetry tracing integration
- Custom policy engine (per-organization ALLOW/WARN/BLOCK rules)
- Prompt injection detection for inbound agent inputs
- Integration with more agent frameworks (LangChain, AutoGen, CrewAI)

If any of these sound interesting — **contribute**. The code is clean, well-documented with JSDoc, and has a comprehensive test suite. Pull requests are welcome.

---

## Bottom Line

AI agents shouldn't connect to the internet blindly. ShieldNet MCP gives you a security guardrail that runs natively in the agent's tool ecosystem — no infrastructure changes, no sidecar proxies, no complex configuration.

Scan first. Connect later. Deploy with confidence.

**Star the repo, try a scan, and let's build safer AI agents together.** 🛡️
