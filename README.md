# 🛡️ ShieldNet MCP — Security Scanner for AI Agents

**MCP Server that brings security governance to AI agent deployments via agentgateway.**

> Track: **Secure & Govern MCP** | MCP_HACK//26

## What It Does

ShieldNet MCP exposes security scanning as MCP tools, enabling any AI agent to:

- **Scan URLs** for 26 attack vectors (XSS, SQLi, SSRF, CORS, info disclosure, etc.)
- **Make governance decisions** (ALLOW / WARN / BLOCK) before connecting to external services
- **Check security headers** for compliance
- **Compare security** of two endpoints side-by-side
- **Enforce security policy** as a guardrail in agentgateway

## Why It Matters

AI agents increasingly interact with external APIs and services. Without security governance:
- An agent could connect to a compromised endpoint
- Sensitive data could be leaked through misconfigured CORS
- Injection attacks could manipulate agent behavior

ShieldNet acts as a **security guardrail** — scan first, connect later.

## Quick Start

```bash
# Install
npm install

# Run as MCP server (stdio)
node src/index.js

# Or use with Claude Desktop / any MCP client
```

### Claude Desktop Configuration

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

### With agentgateway

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

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_url` | Comprehensive security scan (26 vectors) |
| `assess_risk` | Scan + governance decision (ALLOW/WARN/BLOCK) |
| `check_headers` | Quick security headers audit |
| `scan_history` | View previous scans |
| `compare_scans` | Side-by-side security comparison |
| `governance_policy` | View/evaluate security policy |

## MCP Resources

| Resource | Description |
|----------|-------------|
| `shieldnet://attack-vectors` | Full attack vector database |
| `shieldnet://scan-history` | Session scan history |
| `shieldnet://governance-policy` | Current policy config |

## MCP Prompts

| Prompt | Description |
|--------|-------------|
| `security_audit` | Full audit with report |
| `pre_deployment_check` | Gate check before deploy |

## Security Governance

ShieldNet makes ALLOW/WARN/BLOCK decisions based on:

```
ALLOW  → Score ≥ 70, no critical findings
WARN   → Score 50-69, or high-severity findings
BLOCK  → Score < 50, or any critical vulnerabilities
```

### agentgateway Integration

When used as a guardrail in agentgateway:
1. Agent requests external connection
2. agentgateway routes to ShieldNet MCP
3. ShieldNet scans the target
4. Returns ALLOW/WARN/BLOCK decision
5. agentgateway enforces the decision

This creates a **zero-trust security layer** for AI agent interactions.

## Attack Vectors (26)

Injection: XSS (reflected/stored), SQLi (basic/blind), SSRF, Command Injection, NoSQL Injection, XXE, CRLF, Path Traversal, Open Redirect, Prototype Pollution

Auth: JWT None Algorithm, Authentication Bypass, Broken Auth, CSRF

Config: CORS, Security Headers, TLS, Missing Rate Limiting

Info Leak: API Exposure, Verbose Errors, Sensitive Data

Access: IDOR, Mass Assignment

## Real-World Proof

ShieldNet has been used in production security audits:
- **3 CVEs** discovered and responsibly disclosed
- **PayLock.xyz audit**: 36 verified findings (4 Critical, 17 High)
- Published on npm as `shieldnet` (v0.3.2)

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  AI Agent    │────▶│  agentgateway    │────▶│  External   │
│  (Claude,    │     │  ┌────────────┐  │     │  Service    │
│   GPT, etc.) │     │  │ ShieldNet  │  │     │             │
│              │◀────│  │ MCP Guard  │  │◀────│             │
└─────────────┘     │  └────────────┘  │     └─────────────┘
                    │  ALLOW/WARN/BLOCK │
                    └──────────────────┘
```

## License

MIT

## Links

- [npm: shieldnet](https://www.npmjs.com/package/shieldnet)
- [GitHub: ShieldNet](https://github.com/hhhashexe/shieldnet)
- [MCP_HACK//26](https://aihackathon.dev)
