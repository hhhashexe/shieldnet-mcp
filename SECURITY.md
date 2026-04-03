# Security Policy

ShieldNet MCP is itself a security tool. We take the security of the project extremely seriously — a vulnerable scanner creates a false sense of safety, which is worse than no scanner at all.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x | ✅ Yes |
| 0.3.x | ⚠️ Best-effort (security fixes only) |
| < 0.3 | ❌ No |

We recommend always running the latest release.

---

## Reporting a Vulnerability

If you discover a security vulnerability in ShieldNet MCP:

| | |
|---|---|
| **Email** | [security@bughunt.tech](mailto:security@bughunt.tech) |
| **Expected response** | Acknowledgment within **24 hours** |
| **Triage** | Assessment within **72 hours** |

### What to include

- A description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Impact assessment — what an attacker could achieve
- Your suggested severity (we'll validate it)

### What NOT to do

- ❌ Do **not** open a public GitHub Issue for security bugs
- ❌ Do **not** post the vulnerability on social media before coordinated disclosure
- ❌ Do **not** test vulnerabilities against systems you don't own or have permission to test

### Safe harbor

We will not pursue legal action against researchers who report vulnerabilities in good faith according to this policy.

---

## Scope

### ✅ In Scope

- The ShieldNet MCP server (`src/index.js`)
- MCP tool input validation and sanitization
- Scanner module logic (false negatives, bypasses)
- The NPM package (`shieldnet` / `shieldnet-mcp`)
- The demo script (`demo.sh`)
- CI/CD pipeline configuration

### ❌ Out of Scope

- Vulnerabilities in **target systems** that ShieldNet scans (those are the target owner's responsibility)
- Vulnerabilities in upstream dependencies (report to those projects directly)
- DDoS / abuse of demo endpoints
- Social engineering attacks against team members

---

## Response Timeline

| Phase | Timeframe | What Happens |
|-------|-----------|-------------|
| **Acknowledgment** | 24 hours | You receive confirmation that your report was received |
| **Triage** | 72 hours | The team assesses severity and reproduces the issue |
| **Fix Development** | 7–14 days | A patch is developed and internally tested |
| **Release** | 14–21 days | Security fix is released (version bump, release notes) |
| **Disclosure** | 30 days | Public disclosure (CVE if applicable), reporter credited |

Timelines may shift based on severity — critical issues move faster.

---

## Hall of Fame

We publicly recognize researchers who responsibly disclose vulnerabilities. Thank you! 🙏

| Researcher | Vulnerability | Date |
|------------|--------------|------|
| *(Your name here)* | — | — |

*To be listed, include your desired name/handle in your disclosure email. We respect anonymity too.*

---

## Best Practices for Contributors

If you're contributing a scanner module or MCP tool:

1. **Validate all inputs** — never trust data from MCP tool calls
2. **Don't log sensitive data** — no URLs with credentials, no response bodies containing secrets
3. **Use `rejectUnauthorized: false` intentionally** — document why and where
4. **Limit response body sizes** — use `MAX_BODY_BYTES` to prevent memory exhaustion
5. **Test boundary conditions** — empty bodies, malformed headers, extremely long URLs

---

## Contact

- **Security reports:** [security@bughunt.tech](mailto:security@bughunt.tech)
- **General questions:** [GitHub Issues](https://github.com/hhhashexe/shieldnet-mcp/issues)
- **NPM:** [shieldnet](https://www.npmjs.com/package/shieldnet) | [shieldnet-mcp](https://www.npmjs.com/package/shieldnet-mcp)
