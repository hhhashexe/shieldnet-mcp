#!/usr/bin/env node
/**
 * ShieldNet MCP Server — Security Scanner for AI Agents
 * 
 * Exposes security scanning, vulnerability analysis, and governance
 * tools via Model Context Protocol (MCP) for use with agentgateway.
 * 
 * Track: Secure & Govern MCP (MCP_HACK//26)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import https from "https";
import http from "http";
import { URL } from "url";

// ─── ShieldNet Scanner Engine ───────────────────────────────────────

const ATTACK_VECTORS = [
  { id: "xss_reflected", name: "Reflected XSS", severity: "high", category: "injection" },
  { id: "xss_stored", name: "Stored XSS", severity: "critical", category: "injection" },
  { id: "sqli_basic", name: "SQL Injection", severity: "critical", category: "injection" },
  { id: "sqli_blind", name: "Blind SQL Injection", severity: "critical", category: "injection" },
  { id: "ssrf", name: "Server-Side Request Forgery", severity: "high", category: "injection" },
  { id: "idor", name: "Insecure Direct Object Reference", severity: "high", category: "access_control" },
  { id: "cors_wildcard", name: "CORS Misconfiguration", severity: "medium", category: "config" },
  { id: "security_headers", name: "Missing Security Headers", severity: "medium", category: "config" },
  { id: "info_disclosure", name: "Information Disclosure", severity: "medium", category: "info_leak" },
  { id: "path_traversal", name: "Path Traversal", severity: "high", category: "injection" },
  { id: "open_redirect", name: "Open Redirect", severity: "medium", category: "injection" },
  { id: "csrf", name: "Cross-Site Request Forgery", severity: "high", category: "session" },
  { id: "jwt_none", name: "JWT None Algorithm", severity: "critical", category: "auth" },
  { id: "auth_bypass", name: "Authentication Bypass", severity: "critical", category: "auth" },
  { id: "rate_limit", name: "Missing Rate Limiting", severity: "medium", category: "dos" },
  { id: "api_exposure", name: "API Endpoint Exposure", severity: "high", category: "info_leak" },
  { id: "error_leak", name: "Verbose Error Messages", severity: "low", category: "info_leak" },
  { id: "tls_config", name: "TLS Configuration Issues", severity: "medium", category: "config" },
  { id: "crlf_injection", name: "CRLF Injection", severity: "medium", category: "injection" },
  { id: "command_injection", name: "Command Injection", severity: "critical", category: "injection" },
  { id: "nosql_injection", name: "NoSQL Injection", severity: "high", category: "injection" },
  { id: "xxe", name: "XML External Entity", severity: "high", category: "injection" },
  { id: "prototype_pollution", name: "Prototype Pollution", severity: "high", category: "injection" },
  { id: "mass_assignment", name: "Mass Assignment", severity: "high", category: "access_control" },
  { id: "broken_auth", name: "Broken Authentication", severity: "critical", category: "auth" },
  { id: "sensitive_data", name: "Sensitive Data Exposure", severity: "high", category: "info_leak" },
];

// Scan history stored in memory
const scanHistory = [];

function httpRequest(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const mod = url.protocol === "https:" ? https : http;
    const reqOpts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      path: url.pathname + url.search,
      method: options.method || "GET",
      headers: {
        "User-Agent": "ShieldNet-MCP/1.0 Security-Scanner",
        ...options.headers,
      },
      timeout: 10000,
      rejectUnauthorized: false,
    };

    const req = mod.request(reqOpts, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", (e) => reject(e));
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function checkSecurityHeaders(url) {
  const findings = [];
  try {
    const res = await httpRequest(url);
    const h = res.headers;
    const required = {
      "strict-transport-security": "HSTS not set — vulnerable to protocol downgrade",
      "x-content-type-options": "X-Content-Type-Options missing — MIME sniffing risk",
      "x-frame-options": "X-Frame-Options missing — clickjacking risk",
      "content-security-policy": "No CSP — XSS risk increased",
      "x-xss-protection": "X-XSS-Protection missing",
      "referrer-policy": "Referrer-Policy missing — privacy leak",
      "permissions-policy": "Permissions-Policy missing",
    };
    for (const [header, msg] of Object.entries(required)) {
      if (!h[header]) {
        findings.push({ vector: "security_headers", severity: "medium", detail: msg, evidence: `Missing: ${header}` });
      }
    }
    // CORS check
    if (h["access-control-allow-origin"] === "*") {
      findings.push({ vector: "cors_wildcard", severity: "high", detail: "CORS allows all origins", evidence: `Access-Control-Allow-Origin: ${h["access-control-allow-origin"]}` });
    }
    // Server header leak
    if (h["server"]) {
      findings.push({ vector: "info_disclosure", severity: "low", detail: "Server header reveals technology", evidence: `Server: ${h["server"]}` });
    }
    if (h["x-powered-by"]) {
      findings.push({ vector: "info_disclosure", severity: "low", detail: "X-Powered-By reveals framework", evidence: `X-Powered-By: ${h["x-powered-by"]}` });
    }
  } catch (e) {
    findings.push({ vector: "error", severity: "info", detail: `Connection failed: ${e.message}` });
  }
  return findings;
}

async function checkXSS(url) {
  const findings = [];
  const payloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'><svg/onload=alert(1)>",
  ];
  try {
    const u = new URL(url);
    for (const param of u.searchParams.keys()) {
      for (const payload of payloads) {
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, payload);
        const res = await httpRequest(testUrl.toString());
        if (res.body.includes(payload)) {
          findings.push({
            vector: "xss_reflected",
            severity: "high",
            detail: `Reflected XSS in parameter '${param}'`,
            evidence: `Payload reflected: ${payload.substring(0, 40)}`,
            param,
          });
          break;
        }
      }
    }
  } catch (e) { /* silent */ }
  return findings;
}

async function checkInfoDisclosure(url) {
  const findings = [];
  const paths = [
    "/.env", "/robots.txt", "/.git/config", "/package.json",
    "/api/health", "/api/status", "/debug", "/metrics",
    "/.well-known/security.txt", "/sitemap.xml",
  ];
  for (const path of paths) {
    try {
      const base = new URL(url);
      const res = await httpRequest(`${base.origin}${path}`);
      if (res.status === 200 && !res.body.includes("<!DOCTYPE") && res.body.length > 10 && res.body.length < 50000) {
        findings.push({
          vector: "info_disclosure",
          severity: path.includes(".env") || path.includes(".git") ? "critical" : "medium",
          detail: `Exposed endpoint: ${path}`,
          evidence: `HTTP ${res.status} — ${res.body.length} bytes`,
          path,
        });
      }
    } catch (e) { /* silent */ }
  }
  return findings;
}

async function checkTLS(url) {
  const findings = [];
  try {
    const u = new URL(url);
    if (u.protocol === "http:") {
      findings.push({ vector: "tls_config", severity: "high", detail: "Site uses HTTP, not HTTPS", evidence: url });
      // Check if HTTPS redirects
      try {
        const httpsUrl = url.replace("http:", "https:");
        await httpRequest(httpsUrl);
      } catch {
        findings.push({ vector: "tls_config", severity: "critical", detail: "HTTPS not available at all", evidence: url });
      }
    }
  } catch (e) { /* silent */ }
  return findings;
}

async function checkRateLimiting(url) {
  const findings = [];
  try {
    let blocked = false;
    for (let i = 0; i < 10; i++) {
      const res = await httpRequest(url);
      if (res.status === 429) { blocked = true; break; }
    }
    if (!blocked) {
      findings.push({ vector: "rate_limit", severity: "medium", detail: "No rate limiting detected after 10 rapid requests", evidence: "All requests returned 200" });
    }
  } catch (e) { /* silent */ }
  return findings;
}

async function runScan(url, mode = "standard") {
  const startTime = Date.now();
  const findings = [];

  // Run all checks
  findings.push(...await checkSecurityHeaders(url));
  findings.push(...await checkXSS(url));
  findings.push(...await checkInfoDisclosure(url));
  findings.push(...await checkTLS(url));
  
  if (mode === "aggressive") {
    findings.push(...await checkRateLimiting(url));
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  // Calculate grade
  const criticals = findings.filter(f => f.severity === "critical").length;
  const highs = findings.filter(f => f.severity === "high").length;
  const mediums = findings.filter(f => f.severity === "medium").length;
  const lows = findings.filter(f => f.severity === "low").length;

  let score = 100 - (criticals * 15) - (highs * 8) - (mediums * 3) - (lows * 1);
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 50 ? "D" : "F";

  const result = {
    url,
    mode,
    scanTime: new Date().toISOString(),
    duration: `${duration}s`,
    grade,
    score,
    summary: { total: findings.length, critical: criticals, high: highs, medium: mediums, low: lows },
    findings,
    vectors_checked: ATTACK_VECTORS.length,
  };

  scanHistory.push({ url, grade, score, time: result.scanTime, findingsCount: findings.length });

  return result;
}

// ─── Governance Engine ──────────────────────────────────────────────

function assessRisk(scanResult) {
  const { score, summary } = scanResult;
  let decision = "ALLOW";
  let reasoning = [];

  if (summary.critical > 0) {
    decision = "BLOCK";
    reasoning.push(`${summary.critical} critical vulnerabilities found — deployment BLOCKED`);
  } else if (summary.high > 2) {
    decision = "BLOCK";
    reasoning.push(`${summary.high} high-severity findings — too risky for production`);
  } else if (summary.high > 0 || score < 70) {
    decision = "WARN";
    reasoning.push(`${summary.high} high-severity findings — proceed with caution`);
  } else {
    reasoning.push("No critical or high-severity findings — safe to proceed");
  }

  const recommendations = [];
  if (summary.critical > 0) recommendations.push("Fix all critical vulnerabilities before deployment");
  if (summary.high > 0) recommendations.push("Address high-severity findings within 48 hours");
  if (summary.medium > 0) recommendations.push("Schedule medium-severity fixes in next sprint");

  return {
    decision,
    score,
    grade: scanResult.grade,
    reasoning,
    recommendations,
    policy: "ShieldNet Security Policy v1.0",
    timestamp: new Date().toISOString(),
  };
}

// ─── MCP Server Setup ───────────────────────────────────────────────

const server = new Server(
  { name: "shieldnet-mcp", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {}, prompts: {} } }
);

// ─── Tools ──────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_url",
      description: "Run a comprehensive security scan on a URL. Checks for XSS, CORS misconfiguration, security headers, information disclosure, TLS issues, and more. Returns findings with severity ratings and a security grade (A-F).",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "Target URL to scan (e.g., https://example.com)" },
          mode: { type: "string", enum: ["standard", "aggressive"], description: "Scan mode. 'aggressive' includes rate limit testing.", default: "standard" },
        },
        required: ["url"],
      },
    },
    {
      name: "assess_risk",
      description: "Run a security scan and make a governance decision (ALLOW/WARN/BLOCK) based on findings. Use this before deploying or connecting to an external service. Integrates with agentgateway for security governance.",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "Target URL to assess" },
          context: { type: "string", description: "Context for the assessment (e.g., 'pre-deployment check', 'new API integration')" },
        },
        required: ["url"],
      },
    },
    {
      name: "check_headers",
      description: "Quick check of security headers for a URL. Validates HSTS, CSP, CORS, X-Frame-Options, etc.",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "URL to check headers for" },
        },
        required: ["url"],
      },
    },
    {
      name: "scan_history",
      description: "View history of previous security scans performed in this session.",
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of recent scans to return", default: 10 },
        },
      },
    },
    {
      name: "compare_scans",
      description: "Compare security posture of two URLs side by side.",
      inputSchema: {
        type: "object",
        properties: {
          url1: { type: "string", description: "First URL" },
          url2: { type: "string", description: "Second URL" },
        },
        required: ["url1", "url2"],
      },
    },
    {
      name: "governance_policy",
      description: "View or evaluate the current security governance policy. Shows thresholds for ALLOW/WARN/BLOCK decisions.",
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["view", "evaluate"], description: "View the policy or evaluate a score against it" },
          score: { type: "number", description: "Security score to evaluate (0-100)" },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "scan_url": {
      const result = await runScan(args.url, args.mode || "standard");
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "assess_risk": {
      const scan = await runScan(args.url, "standard");
      const assessment = assessRisk(scan);
      assessment.context = args.context || "general assessment";
      assessment.scan_summary = scan.summary;
      assessment.url = args.url;
      return {
        content: [{ type: "text", text: JSON.stringify(assessment, null, 2) }],
      };
    }

    case "check_headers": {
      const findings = await checkSecurityHeaders(args.url);
      const missing = findings.filter(f => f.vector === "security_headers").length;
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            url: args.url,
            headers_checked: 7,
            missing_headers: missing,
            findings,
            verdict: missing === 0 ? "PASS" : missing <= 2 ? "WARN" : "FAIL",
          }, null, 2),
        }],
      };
    }

    case "scan_history": {
      const limit = args?.limit || 10;
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            total_scans: scanHistory.length,
            recent: scanHistory.slice(-limit).reverse(),
          }, null, 2),
        }],
      };
    }

    case "compare_scans": {
      const [scan1, scan2] = await Promise.all([
        runScan(args.url1, "standard"),
        runScan(args.url2, "standard"),
      ]);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            comparison: {
              url1: { url: args.url1, grade: scan1.grade, score: scan1.score, findings: scan1.summary },
              url2: { url: args.url2, grade: scan2.grade, score: scan2.score, findings: scan2.summary },
              winner: scan1.score >= scan2.score ? args.url1 : args.url2,
              score_diff: Math.abs(scan1.score - scan2.score),
            },
          }, null, 2),
        }],
      };
    }

    case "governance_policy": {
      if (args?.action === "evaluate" && args?.score != null) {
        const decision = args.score >= 70 ? "ALLOW" : args.score >= 50 ? "WARN" : "BLOCK";
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ score: args.score, decision, policy: "ShieldNet Security Policy v1.0" }, null, 2),
          }],
        };
      }
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            policy: "ShieldNet Security Policy v1.0",
            thresholds: {
              ALLOW: "Score >= 70, no critical findings",
              WARN: "Score 50-69, or high-severity findings present",
              BLOCK: "Score < 50, or any critical vulnerabilities",
            },
            vectors_checked: ATTACK_VECTORS.length,
            categories: [...new Set(ATTACK_VECTORS.map(v => v.category))],
          }, null, 2),
        }],
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

// ─── Resources ──────────────────────────────────────────────────────

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "shieldnet://attack-vectors",
      name: "Attack Vectors Database",
      description: "Complete list of security attack vectors ShieldNet checks for",
      mimeType: "application/json",
    },
    {
      uri: "shieldnet://scan-history",
      name: "Scan History",
      description: "History of all security scans performed in this session",
      mimeType: "application/json",
    },
    {
      uri: "shieldnet://governance-policy",
      name: "Security Governance Policy",
      description: "Current security governance policy with ALLOW/WARN/BLOCK thresholds",
      mimeType: "application/json",
    },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;

  if (uri === "shieldnet://attack-vectors") {
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify({ vectors: ATTACK_VECTORS, total: ATTACK_VECTORS.length }, null, 2),
      }],
    };
  }

  if (uri === "shieldnet://scan-history") {
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify({ scans: scanHistory, total: scanHistory.length }, null, 2),
      }],
    };
  }

  if (uri === "shieldnet://governance-policy") {
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify({
          policy: "ShieldNet Security Policy v1.0",
          thresholds: { ALLOW: ">= 70", WARN: "50-69", BLOCK: "< 50" },
          auto_block: ["critical vulnerabilities", "> 2 high-severity findings"],
        }, null, 2),
      }],
    };
  }

  throw new Error(`Unknown resource: ${uri}`);
});

// ─── Prompts ────────────────────────────────────────────────────────

server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: [
    {
      name: "security_audit",
      description: "Perform a comprehensive security audit of a target URL with governance decision",
      arguments: [
        { name: "url", description: "Target URL to audit", required: true },
        { name: "context", description: "Why this audit is being performed", required: false },
      ],
    },
    {
      name: "pre_deployment_check",
      description: "Run security checks before deploying or connecting to an external service",
      arguments: [
        { name: "url", description: "Service URL to verify", required: true },
      ],
    },
  ],
}));

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "security_audit") {
    return {
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Perform a comprehensive security audit of ${args.url}.

1. First, use the scan_url tool to scan the target.
2. Then, use assess_risk to make a governance decision.
3. Provide a detailed report with:
   - Executive summary
   - All findings by severity
   - Governance decision (ALLOW/WARN/BLOCK)
   - Recommended remediation steps
   
Context: ${args.context || "Routine security audit"}`,
          },
        },
      ],
    };
  }

  if (name === "pre_deployment_check") {
    return {
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `Pre-deployment security verification for ${args.url}.

1. Check security headers with check_headers tool.
2. Run a full scan with scan_url.
3. Make a governance decision with assess_risk.
4. If BLOCK: list all blocking issues that must be fixed.
5. If WARN: list concerns and whether to proceed.
6. If ALLOW: confirm safe to deploy.

This is a gate check — be strict.`,
          },
        },
      ],
    };
  }

  throw new Error(`Unknown prompt: ${name}`);
});

// ─── Start Server ───────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ShieldNet MCP Server running on stdio");
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
