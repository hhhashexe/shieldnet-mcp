# Contributing to ShieldNet MCP

Thank you for your interest in contributing! ShieldNet MCP is a zero-trust security guardrail for AI agents, and every contribution helps make the ecosystem safer.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Setting Up the Dev Environment](#setting-up-the-dev-environment)
- [Running Tests](#running-tests)
- [Adding a New Scanner Module](#adding-a-new-scanner-module)
- [Adding a New MCP Tool](#adding-a-new-mcp-tool)
- [Code Style Guidelines](#code-style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Templates](#issue-templates)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct v2.1](CODE_OF_CONDUCT.md). By participating, you agree to uphold it. Report violations to **security@bughunt.tech**.

---

## Getting Started

### Prerequisites

- **Node.js ≥ 18** (LTS recommended)
- **npm ≥ 9** (ships with Node 18+)
- **Git**
- A Unix-like environment (Linux, macOS, WSL2 on Windows)

### Setting Up the Dev Environment

```bash
# 1. Fork & clone
git clone https://github.com/hhhashexe/shieldnet-mcp.git
cd shieldnet-mcp

# 2. Install dependencies
npm install

# 3. Verify everything works
npm test
```

You should see **75 passing tests**. If not, open an issue — the CI on `main` must always be green.

### Dev Workflow

```bash
# Run the MCP server in watch mode (auto-restarts on file changes)
npm run dev

# Run a live demo scan against any URL
bash demo.sh https://example.com

# Run the full test suite
npm test
```

---

## Running Tests

```bash
npm test
```

The test suite (`test/test.js`) covers:

- All **6 MCP tools** (scan_url, assess_risk, check_headers, scan_history, compare_scans, governance_policy)
- All **3 resources** (attack-vectors, scan-history, governance-policy)
- All **2 prompts** (security_audit, pre_deployment_check)
- Input validation & error handling

Tests run against real HTTP endpoints, so you need network access. To focus on a specific area, grep the test file and temporarily `.skip` tests you aren't working on — but **revert before submitting**.

---

## Adding a New Scanner Module

ShieldNet's scanner modules live inside `src/index.js` as functions. Each module returns an array of **findings** (`{ id, severity, title, description, evidence, remediation }`).

### Steps

1. **Define your scanner function** near the other scanners in `src/index.js`. Each scanner receives the HTTP response from the target URL:

```js
/**
 * Your scanner description.
 * @param {object} response - HTTP response { status, headers, body, url }
 * @param {object} [options] - Extra options
 * @returns {Array<object>} Findings array
 */
function myNewScanner(response, options = {}) {
  const findings = [];

  // Your scanning logic here
  if (/* detection condition */) {
    findings.push({
      id: "my_scanner/vuln_001",
      severity: "HIGH",         // CRITICAL, HIGH, MEDIUM, LOW, INFO
      title: "Short title of the issue",
      description: "What's wrong and why it matters",
      evidence: "The actual evidence from the response",
      remediation: "How to fix it"
    });
  }

  return findings;
}
```

2. **Register it in the main scan pipeline** — add your scanner to the `scanURL` function so it runs alongside the existing 7 modules:

```js
const scannerResults = await Promise.allSettled([
  securityHeadersScan(response),
  injectionScan(response),
  infoDisclosureScan(response),
  tlsScan(url, response),
  authScan(response),
  misconfigurationScan(response),
  rateLimitScan(response),
  myNewScanner(response),   // ← add here
]);
```

3. **Write tests** for your scanner in `test/test.js`. At minimum:
   - Test that your scanner detects the vulnerability when present
   - Test that it produces **no false positives** on clean responses
   - Test edge cases (empty body, malformed headers, etc.)

4. **Update the README** scanner table with your new module.

### Scanner Naming Conventions

- File/function names: `camelCase` (e.g., `myNewScanner`)
- Finding IDs: `<module_name>/<short_id>` (e.g., `my_new_scanner/vuln_001`)
- Severity: one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

## Adding a New MCP Tool

MCP tools are defined in the `tools` array passed to `setRequestHandler(ListToolsRequestSchema, ...)`.

### Steps

1. **Define the tool** in the tools list:

```js
{
  name: "my_new_tool",
  description: "What this tool does and when to use it.",
  inputSchema: {
    type: "object",
    properties: {
      someParam: {
        type: "string",
        description: "Description of someParam",
      },
      count: {
        type: "number",
        description: "An optional numeric param",
      },
    },
    required: ["someParam"],
  },
}
```

2. **Handle the tool call** in the `CallToolRequestSchema` handler:

```js
if (name === "my_new_tool") {
  const { someParam, count } = params.arguments || {};
  // Validate inputs
  if (!someParam) {
    return errorResponse("someParam is required");
  }
  // Do the work
  const result = await doTheWork(someParam, count);
  return {
    content: [{
      type: "text",
      text: JSON.stringify(result, null, 2),
    }],
  };
}
```

3. **Validate all inputs** — use the existing `validateUrl()` pattern. Never trust user input.

4. **Write tests** in `test/test.js` covering:
   - Happy path with valid inputs
   - Missing required parameters
   - Invalid / malformed inputs

5. **Update the README** MCP Tools table.

---

## Code Style Guidelines

### General

- **Language:** JavaScript (ES Modules, Node 18+)
- **Indentation:** 2 spaces
- **Quotes:** Double quotes (consistent with codebase)
- **Semicolons:** Yes, always
- **Line length:** Soft limit of ~120 characters
- **No unused variables** — the codebase is tight; keep it that way

### Naming

| Thing | Convention | Example |
|-------|-----------|---------|
| Functions / variables | `camelCase` | `validateUrl`, `scanHistory` |
| Constants | `UPPER_SNAKE_CASE` | `DEFAULT_TIMEOUT_MS` |
| File names | `kebab-case` (where applicable) | `test.js` |
| Finding IDs | `snake_case/slug` | `info_disclosure/env_exposed` |
| MCP tool names | `snake_case` | `scan_url`, `assess_risk` |

### Documentation

- JSDoc comments for **all public functions**: `@param`, `@returns`
- Comment *why*, not *what* — the code should be self-evident
- Update README tables and architecture docs when adding features

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scanner): add TLS certificate expiry check
fix(malware): handle empty body without crashing
docs(readme): update scanner module table
test(rate_limit): add false positive test case
ci: pin Node version in workflow
```

---

## Pull Request Process

1. **Open an issue first** (unless it's a trivial fix) — discuss the change before coding.
2. **Fork the repo** and create a feature branch:
   ```bash
   git checkout -b feat/my-new-scanner
   ```
3. **Write tests** — no PRs without test coverage for new functionality.
4. **Ensure CI passes**:
   ```bash
   npm test
   ```
5. **Update documentation** (README, DOCS.md, this file) as needed.
6. **Open the PR** on GitHub with:
   - A clear description of **what** changed and **why**
   - Link to the related issue
   - Screenshots / output examples if UI-relevant
7. **Respond to reviews** — be patient and constructive.
8. **Squash & merge** — maintainers will squash-merge to `main`.

### PR Checklist

- [ ] Tests added / updated and passing
- [ ] README updated (tools table, scanner table, usage examples)
- [ ] JSDoc comments on new functions
- [ ] Commit messages follow Conventional Commits
- [ ] No secrets / API keys / credentials in the diff

---

## Issue Templates

### 🐛 Bug Report

```
### What happened?
Describe the bug clearly.

### How to reproduce
Steps to reproduce:
1. Run `...`
2. Scan `...`
3. See `...`

### Expected behavior
What should have happened?

### Environment
- Node version: `node -v`
- ShieldNet MCP version: `npx shieldnet-mcp --version` (or commit hash)
- OS: Linux / macOS / Windows

### Logs / Output
Paste relevant CLI output or error stack traces.
```

### ✨ Feature Request

```
### What problem are you solving?
Explain the use case.

### Proposed solution
How should it work? Any design ideas?

### Alternatives considered
What other approaches exist and why not those?

### Additional context
Links, prior art, anything helpful.
```

### 📋 Scanner Addition Request

```
### What should this scanner detect?
(e.g., "Missing Content-Security-Policy header")

### Why is this important?
Explain the security impact and real-world relevance.

### How to detect it
Technical description of the detection logic.

### Severity
What severity level would findings from this scanner typically be? (CRITICAL / HIGH / MEDIUM / LOW / INFO)
```

---

## Security Vulnerability Reporting

If you discover a security vulnerability **in ShieldNet MCP itself**, please **do NOT** open a public issue.

- **Email:** [security@bughunt.tech](mailto:security@bughunt.tech)
- **Expect:** Acknowledgment within 24 hours, triage within 72 hours
- **Scope:** See [SECURITY.md](SECURITY.md) for full details

We take security seriously — ShieldNet is a security tool, so trust matters even more.

See our [Hall of Fame](SECURITY.md#hall-of-fame) for contributors who've responsibly disclosed vulnerabilities.

---

## License

By contributing, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.
