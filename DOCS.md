# ShieldNet MCP — Quick Docs

> Security scanner for AI agents via MCP. 7 modules, 50+ checks, ALLOW/WARN/BLOCK governance.

---

## 1. Installation

**npx (no install):**
```bash
npx shieldnet
```

**npm global:**
```bash
npm install -g shieldnet
shieldnet
```

**From source:**
```bash
git clone https://github.com/hhhashexe/shieldnet-mcp.git
cd shieldnet-mcp && npm install
node src/index.js
```

Requires **Node ≥ 18**.

---

## 2. MCP Tools

### `scan_url`
Full security scan — 7 modules, 50+ checks, A-F grade.
- **Params:** `url` (required), `mode` ("standard" | "aggressive")
- **Example:** `{"tool":"scan_url","arguments":{"url":"https://api.example.com","mode":"aggressive"}}`

### `assess_risk`
Scan + governance decision (ALLOW/WARN/BLOCK) with confidence score.
- **Params:** `url` (required), `context` (optional, e.g. "pre-deployment")
- **Example:** `{"tool":"assess_risk","arguments":{"url":"https://webhook.thirdparty.io"}}`

### `check_headers`
Quick security headers audit — HSTS, CSP, CORS, cookie flags. Returns PASS/WARN/FAIL.
- **Params:** `url` (required)
- **Example:** `{"tool":"check_headers","arguments":{"url":"https://login.example.com"}}`

### `scan_history`
View scan history for this session with grades and scores.
- **Params:** `limit` (optional, default 10, max 100)
- **Example:** `{"tool":"scan_history","arguments":{"limit":5}}`

### `compare_scans`
Side-by-side comparison of two URLs — which is safer?
- **Params:** `url1` (required), `url2` (required)
- **Example:** `{"tool":"compare_scans","arguments":{"url1":"https://a.com","url2":"https://b.com"}}`

### `governance_policy`
View policy thresholds or evaluate a score against ALLOW/WARN/BLOCK.
- **Params:** `action` ("view" | "evaluate"), `score` (required when action=evaluate)
- **Example:** `{"tool":"governance_policy","arguments":{"action":"evaluate","score":42}}`

---

## 3. Resources

| URI | Returns |
|-----|---------|
| `shieldnet://attack-vectors` | Full attack vector database — all 7 modules with individual checks |
| `shieldnet://scan-history` | All scans from this session (grades, scores, timestamps) |
| `shieldnet://governance-policy` | ALLOW/WARN/BLOCK thresholds and auto-block rules |

---

## 4. Prompts

### `security_audit`
**When:** Full security audit with executive report. Gives step-by-step: scan → assess → write severity-ranked report with remediation.
**Args:** `url` (required), `context` (optional)

### `pre_deployment_check`
**When:** Gate check before deploying to production. Runs aggressive scan + headers + risk assessment. Strict production gate.
**Args:** `url` (required)

---

## 5. Governance — ALLOW / WARN / BLOCK

| Decision | Trigger | Action |
|----------|---------|--------|
| **ALLOW** | Score ≥ 70, zero criticals | Safe to connect |
| **WARN** | Score 50–69, or high findings | Proceed with caution, log concerns |
| **BLOCK** | Score < 50, any critical, or >2 high findings | Block connection, fix first |

Criticals auto-BLOCK at 0.95 confidence. BLOCK means: do not connect until issues resolved.

---

## 6. Claude Desktop Config

```json
{
  "mcpServers": {
    "shieldnet": {
      "command": "node",
      "args": ["/absolute/path/to/shieldnet-mcp/src/index.js"]
    }
  }
}
```

Or for global install:
```json
{
  "mcpServers": {
    "shieldnet": {
      "command": "shieldnet"
    }
  }
}
```

Config file: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
