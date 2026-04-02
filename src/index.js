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

// ─── HTTP Client ────────────────────────────────────────────────────

function httpRequest(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(urlStr);
      const mod = url.protocol === "https:" ? https : http;
      const reqOpts = {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: options.method || "GET",
        headers: {
          "User-Agent": "ShieldNet-MCP/1.0 Security-Scanner",
          ...(options.headers || {}),
        },
        timeout: options.timeout || 8000,
        rejectUnauthorized: false,
      };

      const req = mod.request(reqOpts, (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > 200000) { res.destroy(); resolve({ status: res.statusCode, headers: res.headers, body: body.slice(0, 200000) }); }
        });
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on("error", (e) => reject(e));
      req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")); });
      if (options.body) req.write(options.body);
      req.end();
    } catch (e) { reject(e); }
  });
}

async function safeRequest(urlStr, options = {}) {
  try { return await httpRequest(urlStr, options); }
  catch (e) { return { status: 0, headers: {}, body: "", error: e.message }; }
}

// ─── Scanner Modules ────────────────────────────────────────────────

async function checkSecurityHeaders(baseUrl) {
  const findings = [];
  const res = await safeRequest(baseUrl);
  if (res.error) return [{ vector: "connection", severity: "info", detail: `Cannot connect: ${res.error}`, evidence: baseUrl }];

  const h = res.headers;
  const checks = [
    ["strict-transport-security", "medium", "HSTS not set — protocol downgrade attacks possible"],
    ["x-content-type-options", "medium", "X-Content-Type-Options missing — MIME sniffing risk"],
    ["x-frame-options", "medium", "X-Frame-Options missing — clickjacking possible"],
    ["content-security-policy", "medium", "No Content-Security-Policy — increased XSS risk"],
    ["referrer-policy", "low", "Referrer-Policy missing — referer header may leak URLs"],
    ["permissions-policy", "low", "Permissions-Policy missing — browser features unrestricted"],
  ];

  for (const [header, severity, detail] of checks) {
    if (!h[header]) {
      findings.push({ vector: "security_headers", severity, detail, evidence: `Missing: ${header}` });
    }
  }

  if (h["access-control-allow-origin"] === "*") {
    findings.push({ vector: "cors_wildcard", severity: "high", detail: "CORS allows all origins — any website can make authenticated requests", evidence: `Access-Control-Allow-Origin: *` });
  }
  if (h["server"]) {
    findings.push({ vector: "info_disclosure", severity: "low", detail: `Server header reveals technology: ${h["server"]}`, evidence: `Server: ${h["server"]}` });
  }
  if (h["x-powered-by"]) {
    findings.push({ vector: "info_disclosure", severity: "low", detail: `X-Powered-By reveals framework`, evidence: `X-Powered-By: ${h["x-powered-by"]}` });
  }

  // Cookie security
  const cookies = h["set-cookie"];
  if (cookies) {
    const cookieStr = Array.isArray(cookies) ? cookies.join("; ") : cookies;
    if (!cookieStr.toLowerCase().includes("httponly")) {
      findings.push({ vector: "session_security", severity: "high", detail: "Cookie missing HttpOnly flag — accessible via JavaScript/XSS", evidence: `Set-Cookie without HttpOnly` });
    }
    if (!cookieStr.toLowerCase().includes("secure") && baseUrl.startsWith("https")) {
      findings.push({ vector: "session_security", severity: "medium", detail: "Cookie missing Secure flag on HTTPS site", evidence: `Set-Cookie without Secure` });
    }
    if (!cookieStr.toLowerCase().includes("samesite")) {
      findings.push({ vector: "csrf", severity: "medium", detail: "Cookie missing SameSite — CSRF risk", evidence: `Set-Cookie without SameSite` });
    }
  }

  return findings;
}

async function checkInjection(baseUrl) {
  const findings = [];
  const url = new URL(baseUrl);
  
  // Collect params from URL + common params to probe
  const params = [...url.searchParams.keys()];
  const commonParams = ["q", "search", "query", "id", "page", "url", "redirect", "callback", "next", "file", "path", "name", "user", "email"];
  const testParams = params.length > 0 ? params : commonParams.slice(0, 5);

  // XSS payloads
  const xssPayloads = [
    { payload: '<script>alert(1)</script>', name: "basic script tag" },
    { payload: '"><img src=x onerror=alert(1)>', name: "img onerror" },
    { payload: "'-alert(1)-'", name: "JS context escape" },
    { payload: "{{7*7}}", name: "template injection" },
    { payload: "${7*7}", name: "expression injection" },
  ];

  // SQLi payloads
  const sqliPayloads = [
    { payload: "' OR '1'='1", signals: ["error", "sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "ORA-", "Warning"], name: "basic OR" },
    { payload: "1' AND 1=1--", signals: ["error", "sql", "syntax"], name: "boolean-based" },
    { payload: "1 UNION SELECT NULL--", signals: ["error", "union", "select", "column"], name: "UNION" },
    { payload: "'; WAITFOR DELAY '0:0:1'--", signals: ["error", "sql", "waitfor"], name: "time-based" },
  ];

  // Path traversal payloads
  const pathPayloads = [
    { payload: "../../../etc/passwd", signals: ["root:", "/bin/", "nobody"], name: "etc/passwd" },
    { payload: "....//....//....//etc/passwd", signals: ["root:", "/bin/"], name: "double-dot bypass" },
    { payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", signals: ["root:"], name: "URL-encoded traversal" },
  ];

  // Command injection signals
  const cmdSignals = ["uid=", "gid=", "root", "bin/", "Permission denied"];

  for (const param of testParams) {
    // XSS tests
    for (const { payload, name } of xssPayloads) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, payload);
      const res = await safeRequest(testUrl.toString());
      if (res.body && res.body.includes(payload)) {
        findings.push({
          vector: "xss_reflected", severity: "high",
          detail: `Reflected XSS via ${name} in parameter '${param}'`,
          evidence: `Payload reflected unescaped: ${payload.substring(0, 30)}`,
        });
        break; // One XSS per param is enough
      }
      // Template injection check — only if response is NOT HTML (SPA pages always contain "49" somewhere)
      if (!res.body?.includes("<!DOCTYPE") && !res.body?.includes("<html")) {
        if ((payload === "{{7*7}}" && res.body?.includes("49")) || (payload === "${7*7}" && res.body?.includes("49"))) {
          findings.push({
            vector: "template_injection", severity: "critical",
            detail: `Server-Side Template Injection in parameter '${param}'`,
            evidence: `${payload} evaluated to 49`,
          });
        }
      }
    }

    // SQLi tests — compare response with baseline to avoid false positives
    for (const { payload, signals, name } of sqliPayloads) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, payload);
      const res = await safeRequest(testUrl.toString());
      if (!res.body || res.body.includes("<!DOCTYPE") || res.body.includes("<html")) continue; // Skip HTML/SPA responses
      const bodyLower = (res.body || "").toLowerCase();
      const strongSignals = signals.filter(s => !["error"].includes(s.toLowerCase())); // "error" alone is too noisy
      for (const signal of strongSignals) {
        if (bodyLower.includes(signal.toLowerCase())) {
          findings.push({
            vector: "sqli", severity: "critical",
            detail: `Potential SQL Injection (${name}) in parameter '${param}'`,
            evidence: `Signal '${signal}' found after payload: ${payload.substring(0, 20)}`,
          });
          break;
        }
      }
    }

    // Path traversal tests (only on file/path-like params)
    if (["file", "path", "page", "url", "template", "include", "doc"].includes(param)) {
      for (const { payload, signals, name } of pathPayloads) {
        const testUrl = new URL(baseUrl);
        testUrl.searchParams.set(param, payload);
        const res = await safeRequest(testUrl.toString());
        for (const signal of signals) {
          if (res.body?.includes(signal)) {
            findings.push({
              vector: "path_traversal", severity: "critical",
              detail: `Path Traversal (${name}) via parameter '${param}'`,
              evidence: `Signal '${signal}' found in response`,
            });
            break;
          }
        }
      }
    }

    // Command injection tests — only on non-HTML responses
    const cmdPayloads = ["; id", "| id", "$(id)", "`id`"];
    for (const payload of cmdPayloads) {
      const testUrl = new URL(baseUrl);
      testUrl.searchParams.set(param, payload);
      const res = await safeRequest(testUrl.toString());
      if (!res.body || res.body.includes("<!DOCTYPE") || res.body.includes("<html")) continue;
      for (const signal of cmdSignals) {
        if (res.body?.includes(signal)) {
          findings.push({
            vector: "command_injection", severity: "critical",
            detail: `Potential Command Injection in parameter '${param}'`,
            evidence: `Signal '${signal}' after payload: ${payload}`,
          });
          break;
        }
      }
    }
  }

  // SSRF test via redirect/callback/url params
  const ssrfParams = testParams.filter(p => ["url", "redirect", "callback", "next", "link", "href", "target", "dest", "return"].includes(p));
  for (const param of ssrfParams) {
    const testUrl = new URL(baseUrl);
    testUrl.searchParams.set(param, "http://169.254.169.254/latest/meta-data/");
    const res = await safeRequest(testUrl.toString());
    if (res.body?.includes("ami-id") || res.body?.includes("instance-id") || res.body?.includes("iam")) {
      findings.push({
        vector: "ssrf", severity: "critical",
        detail: `SSRF to cloud metadata via parameter '${param}'`,
        evidence: `Cloud metadata accessible through redirect parameter`,
      });
    }
  }

  // Open redirect test
  for (const param of ssrfParams) {
    const testUrl = new URL(baseUrl);
    testUrl.searchParams.set(param, "https://evil.com");
    const res = await safeRequest(testUrl.toString());
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers["location"] || "";
      if (location.includes("evil.com")) {
        findings.push({
          vector: "open_redirect", severity: "medium",
          detail: `Open redirect via parameter '${param}'`,
          evidence: `Redirects to: ${location}`,
        });
      }
    }
  }

  return findings;
}

async function checkInfoDisclosure(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;

  const paths = [
    { path: "/.env", severity: "critical", desc: "Environment file — may contain API keys, DB credentials" },
    { path: "/.git/config", severity: "critical", desc: "Git config exposed — source code access possible" },
    { path: "/.git/HEAD", severity: "critical", desc: "Git HEAD exposed — source code access possible" },
    { path: "/package.json", severity: "medium", desc: "Package manifest — reveals dependencies and versions" },
    { path: "/composer.json", severity: "medium", desc: "Composer manifest exposed" },
    { path: "/api/health", severity: "low", desc: "Health endpoint — may reveal version info" },
    { path: "/api/status", severity: "low", desc: "Status endpoint" },
    { path: "/debug", severity: "high", desc: "Debug endpoint" },
    { path: "/metrics", severity: "medium", desc: "Metrics endpoint — operational data exposed" },
    { path: "/stats", severity: "medium", desc: "Stats endpoint" },
    { path: "/api/docs", severity: "low", desc: "API documentation" },
    { path: "/swagger.json", severity: "medium", desc: "Swagger/OpenAPI spec — full API surface exposed" },
    { path: "/openapi.json", severity: "medium", desc: "OpenAPI spec exposed" },
    { path: "/.well-known/security.txt", severity: "info", desc: "Security.txt" },
    { path: "/robots.txt", severity: "info", desc: "Robots.txt" },
    { path: "/wp-config.php.bak", severity: "critical", desc: "WordPress config backup" },
    { path: "/server-status", severity: "high", desc: "Apache server-status — active connections visible" },
    { path: "/phpinfo.php", severity: "high", desc: "PHP info — full server configuration exposed" },
    { path: "/.DS_Store", severity: "medium", desc: "macOS directory listing exposed" },
    { path: "/backup.sql", severity: "critical", desc: "SQL backup file" },
    { path: "/dump.sql", severity: "critical", desc: "SQL dump file" },
    { path: "/.htpasswd", severity: "critical", desc: "Apache password file" },
    { path: "/web.config", severity: "medium", desc: "IIS configuration file" },
    { path: "/elmah.axd", severity: "high", desc: "ASP.NET error log viewer" },
    { path: "/trace.axd", severity: "high", desc: "ASP.NET request trace" },
  ];

  const results = await Promise.allSettled(
    paths.map(async ({ path, severity, desc }) => {
      const res = await safeRequest(`${origin}${path}`, { timeout: 5000 });
      if (
        res.status === 200 &&
        res.body.length > 5 &&
        res.body.length < 100000 &&
        !res.body.includes("<!DOCTYPE") &&
        !res.body.includes("<html") &&
        !res.body.includes("404") &&
        !res.body.includes("Not Found")
      ) {
        return { vector: "info_disclosure", severity, detail: `${desc}: ${path}`, evidence: `HTTP 200 — ${res.body.length} bytes`, path };
      }
      return null;
    })
  );

  for (const r of results) {
    if (r.status === "fulfilled" && r.value) findings.push(r.value);
  }

  return findings;
}

async function checkTLS(baseUrl) {
  const findings = [];
  const url = new URL(baseUrl);

  if (url.protocol === "http:") {
    findings.push({ vector: "tls_config", severity: "high", detail: "Site uses HTTP — all traffic is unencrypted", evidence: baseUrl });
    const httpsUrl = baseUrl.replace("http:", "https:");
    const res = await safeRequest(httpsUrl);
    if (res.error) {
      findings.push({ vector: "tls_config", severity: "critical", detail: "HTTPS not available — no encryption possible", evidence: res.error });
    }
  } else {
    // Check HTTP → HTTPS redirect
    const httpUrl = baseUrl.replace("https:", "http:");
    const res = await safeRequest(httpUrl);
    if (res.status === 200) {
      findings.push({ vector: "tls_config", severity: "medium", detail: "HTTP does not redirect to HTTPS", evidence: `HTTP ${res.status} — no redirect` });
    }
  }

  return findings;
}

async function checkRateLimiting(baseUrl) {
  const findings = [];
  const start = Date.now();
  let success = 0;

  for (let i = 0; i < 20; i++) {
    const res = await safeRequest(baseUrl, { timeout: 3000 });
    if (res.status === 429) return findings; // Rate limited — good
    if (res.status > 0 && res.status < 500) success++;
  }

  const elapsed = Date.now() - start;
  if (success >= 18) {
    findings.push({
      vector: "rate_limit", severity: "medium",
      detail: `No rate limiting — ${success}/20 requests succeeded in ${(elapsed / 1000).toFixed(1)}s`,
      evidence: `${(success / (elapsed / 1000)).toFixed(0)} req/sec sustained`,
    });
  }

  return findings;
}

async function checkAuth(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;

  // Check for JWT in response
  const res = await safeRequest(baseUrl);
  const jwtPattern = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
  const jwts = res.body?.match(jwtPattern);
  if (jwts) {
    findings.push({
      vector: "sensitive_data", severity: "high",
      detail: "JWT token found in response body",
      evidence: `Token: ${jwts[0].substring(0, 30)}...`,
    });
    // Decode JWT header to check for none algorithm vulnerability
    try {
      const header = JSON.parse(Buffer.from(jwts[0].split(".")[0], "base64url").toString());
      if (header.alg === "none" || header.alg === "None") {
        findings.push({
          vector: "jwt_none", severity: "critical",
          detail: "JWT uses 'none' algorithm — signature verification bypassed",
          evidence: `Algorithm: ${header.alg}`,
        });
      }
    } catch (e) { /* not valid JWT */ }
  }

  // Check for API keys / secrets in response
  const secretPatterns = [
    { pattern: /['"](sk|pk|api|key|secret|token|password|apikey)[_-]?['"]\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]/gi, name: "API key/secret" },
    { pattern: /Bearer\s+[A-Za-z0-9._-]{20,}/g, name: "Bearer token" },
    { pattern: /password["']?\s*[:=]\s*["'][^"']{4,}/gi, name: "Password in source" },
  ];

  for (const { pattern, name } of secretPatterns) {
    const matches = res.body?.match(pattern);
    if (matches) {
      findings.push({
        vector: "sensitive_data", severity: "high",
        detail: `${name} found in page source`,
        evidence: `Match: ${matches[0].substring(0, 40)}...`,
      });
    }
  }

  // Email harvesting
  const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = [...new Set(res.body?.match(emailPattern) || [])];
  if (emails.length > 0) {
    findings.push({
      vector: "info_disclosure", severity: "low",
      detail: `${emails.length} email address(es) found in page`,
      evidence: emails.slice(0, 3).join(", "),
    });
  }

  return findings;
}

async function checkMisconfiguration(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;

  // CORS preflight with evil origin
  const corsRes = await safeRequest(baseUrl, {
    method: "OPTIONS",
    headers: { "Origin": "https://evil-attacker.com", "Access-Control-Request-Method": "POST" },
  });
  const allowOrigin = corsRes.headers?.["access-control-allow-origin"];
  if (allowOrigin && allowOrigin.includes("evil-attacker.com")) {
    findings.push({
      vector: "cors_wildcard", severity: "critical",
      detail: "CORS reflects arbitrary origin — full CSRF possible",
      evidence: `Origin: evil-attacker.com → Access-Control-Allow-Origin: ${allowOrigin}`,
    });
  }
  const allowCreds = corsRes.headers?.["access-control-allow-credentials"];
  if (allowCreds === "true" && allowOrigin === "*") {
    findings.push({
      vector: "cors_wildcard", severity: "critical",
      detail: "CORS wildcard with credentials — authentication bypass via cross-origin requests",
      evidence: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
    });
  }

  // HTTP methods
  const dangerousMethods = ["PUT", "DELETE", "PATCH", "TRACE"];
  for (const method of dangerousMethods) {
    const res = await safeRequest(baseUrl, { method });
    if (res.status !== 405 && res.status !== 404 && res.status !== 501 && res.status > 0) {
      if (method === "TRACE" && res.body?.includes("TRACE")) {
        findings.push({
          vector: "misconfiguration", severity: "medium",
          detail: "TRACE method enabled — Cross-Site Tracing possible",
          evidence: `TRACE returned HTTP ${res.status}`,
        });
      }
    }
  }

  // Version disclosure in common error pages
  const errorRes = await safeRequest(`${origin}/nonexistent-page-${Date.now()}`);
  const versionPatterns = [
    /Apache\/[\d.]+/i, /nginx\/[\d.]+/i, /PHP\/[\d.]+/i,
    /Express\/[\d.]+/i, /ASP\.NET/i, /Tomcat\/[\d.]+/i,
    /IIS\/[\d.]+/i, /Werkzeug\/[\d.]+/i, /Django\/[\d.]+/i,
  ];
  for (const pattern of versionPatterns) {
    const match = errorRes.body?.match(pattern);
    if (match) {
      findings.push({
        vector: "info_disclosure", severity: "medium",
        detail: `Version disclosed in error page: ${match[0]}`,
        evidence: `Found in 404 page response`,
      });
    }
  }

  return findings;
}

// ─── Main Scanner ───────────────────────────────────────────────────

const scanHistory = [];

async function runScan(url, mode = "standard") {
  const startTime = Date.now();
  const allFindings = [];

  // Run modules in parallel where safe
  const [headers, injection, infoDisc, tls, auth, misconfig] = await Promise.allSettled([
    checkSecurityHeaders(url),
    checkInjection(url),
    checkInfoDisclosure(url),
    checkTLS(url),
    checkAuth(url),
    checkMisconfiguration(url),
  ]);

  for (const result of [headers, injection, infoDisc, tls, auth, misconfig]) {
    if (result.status === "fulfilled") allFindings.push(...result.value);
  }

  if (mode === "aggressive") {
    const rateLimitResult = await checkRateLimiting(url);
    allFindings.push(...rateLimitResult);
  }

  // Deduplicate
  const seen = new Set();
  const findings = allFindings.filter(f => {
    const key = `${f.vector}:${f.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
    info: findings.filter(f => f.severity === "info").length,
  };

  let score = 100 - (summary.critical * 15) - (summary.high * 8) - (summary.medium * 3) - (summary.low * 1);
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 50 ? "D" : "F";

  const result = {
    url,
    mode,
    scanTime: new Date().toISOString(),
    duration: `${duration}s`,
    grade,
    score,
    summary,
    modules_run: ["security_headers", "injection", "info_disclosure", "tls", "auth", "misconfiguration", ...(mode === "aggressive" ? ["rate_limiting"] : [])],
    findings: findings.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    }),
  };

  scanHistory.push({ url, grade, score, time: result.scanTime, findingsCount: findings.length, duration: result.duration });
  return result;
}

// ─── Governance Engine ──────────────────────────────────────────────

function assessRisk(scanResult) {
  const { score, summary, url, findings } = scanResult;
  let decision, confidence;

  if (summary.critical > 0) {
    decision = "BLOCK";
    confidence = 0.95;
  } else if (summary.high > 2) {
    decision = "BLOCK";
    confidence = 0.85;
  } else if (summary.high > 0 || score < 70) {
    decision = "WARN";
    confidence = 0.75;
  } else {
    decision = "ALLOW";
    confidence = 0.9;
  }

  const blocking_issues = findings
    .filter(f => f.severity === "critical" || f.severity === "high")
    .map(f => ({ severity: f.severity, vector: f.vector, detail: f.detail }));

  return {
    decision,
    confidence,
    score,
    grade: scanResult.grade,
    url,
    reasoning: decision === "BLOCK"
      ? `${summary.critical} critical + ${summary.high} high-severity findings. Deployment BLOCKED.`
      : decision === "WARN"
        ? `${summary.high} high-severity findings detected. Proceed with caution.`
        : `No critical or high-severity findings. Safe to proceed.`,
    blocking_issues,
    recommendations: [
      ...(summary.critical > 0 ? ["URGENT: Fix all critical vulnerabilities before any deployment"] : []),
      ...(summary.high > 0 ? ["HIGH: Address high-severity findings within 48 hours"] : []),
      ...(summary.medium > 0 ? ["MEDIUM: Schedule medium-severity fixes in next sprint"] : []),
      ...(summary.low > 0 ? ["LOW: Address in regular maintenance cycle"] : []),
    ],
    policy: "ShieldNet Governance Policy v1.0",
    scan_summary: summary,
    timestamp: new Date().toISOString(),
  };
}

// ─── MCP Server ─────────────────────────────────────────────────────

const server = new Server(
  { name: "shieldnet-mcp", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {}, prompts: {} } }
);

// ─── Tools ──────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_url",
      description: "Run a comprehensive security scan on a URL. Checks 7 modules: security headers, injection (XSS/SQLi/SSTI/command injection/path traversal), CORS, info disclosure (25 sensitive paths), TLS, authentication issues, and misconfigurations. Returns findings with severity ratings and a security grade (A-F). Use 'aggressive' mode to also test rate limiting.",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "Target URL to scan" },
          mode: { type: "string", enum: ["standard", "aggressive"], description: "Scan mode", default: "standard" },
        },
        required: ["url"],
      },
    },
    {
      name: "assess_risk",
      description: "Security governance gate: scan a URL and return an ALLOW/WARN/BLOCK decision with confidence score. Use this as a guardrail before an AI agent connects to any external service. Designed for agentgateway integration.",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "Target URL to assess" },
          context: { type: "string", description: "Context (e.g., 'pre-deployment', 'new API integration')" },
        },
        required: ["url"],
      },
    },
    {
      name: "check_headers",
      description: "Quick security headers audit — checks HSTS, CSP, CORS, X-Frame-Options, cookie flags, and more.",
      inputSchema: {
        type: "object",
        properties: { url: { type: "string", description: "URL to check" } },
        required: ["url"],
      },
    },
    {
      name: "scan_history",
      description: "View history of security scans performed in this session with grades and scores.",
      inputSchema: {
        type: "object",
        properties: { limit: { type: "number", description: "Max results", default: 10 } },
      },
    },
    {
      name: "compare_scans",
      description: "Compare security posture of two URLs side by side — useful for evaluating which endpoint is safer.",
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
      description: "View the security governance policy or evaluate a score against ALLOW/WARN/BLOCK thresholds.",
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["view", "evaluate"], default: "view" },
          score: { type: "number", description: "Score to evaluate (0-100)" },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const json = (obj) => ({ content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] });

  switch (name) {
    case "scan_url":
      return json(await runScan(args.url, args.mode || "standard"));

    case "assess_risk": {
      const scan = await runScan(args.url, "standard");
      const assessment = assessRisk(scan);
      if (args.context) assessment.context = args.context;
      return json(assessment);
    }

    case "check_headers": {
      const findings = await checkSecurityHeaders(args.url);
      const missing = findings.filter(f => f.vector === "security_headers").length;
      return json({
        url: args.url, headers_checked: 6, missing_headers: missing, findings,
        verdict: missing === 0 ? "PASS" : missing <= 2 ? "WARN" : "FAIL",
      });
    }

    case "scan_history":
      return json({ total_scans: scanHistory.length, recent: scanHistory.slice(-(args?.limit || 10)).reverse() });

    case "compare_scans": {
      const [s1, s2] = await Promise.all([runScan(args.url1), runScan(args.url2)]);
      return json({
        url1: { url: args.url1, grade: s1.grade, score: s1.score, findings: s1.summary },
        url2: { url: args.url2, grade: s2.grade, score: s2.score, findings: s2.summary },
        safer: s1.score >= s2.score ? args.url1 : args.url2,
        score_difference: Math.abs(s1.score - s2.score),
      });
    }

    case "governance_policy":
      if (args?.action === "evaluate" && args?.score != null) {
        const d = args.score >= 70 ? "ALLOW" : args.score >= 50 ? "WARN" : "BLOCK";
        return json({ score: args.score, decision: d, policy: "ShieldNet Governance Policy v1.0" });
      }
      return json({
        policy: "ShieldNet Governance Policy v1.0",
        thresholds: { ALLOW: "≥ 70 + no criticals", WARN: "50-69 or high findings", BLOCK: "< 50 or criticals" },
        modules: ["security_headers", "injection", "info_disclosure", "tls", "auth", "misconfiguration", "rate_limiting"],
      });

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

// ─── Resources ──────────────────────────────────────────────────────

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    { uri: "shieldnet://attack-vectors", name: "Attack Vector Database", description: "Security checks performed by ShieldNet", mimeType: "application/json" },
    { uri: "shieldnet://scan-history", name: "Scan History", description: "All scans from this session", mimeType: "application/json" },
    { uri: "shieldnet://governance-policy", name: "Governance Policy", description: "ALLOW/WARN/BLOCK thresholds", mimeType: "application/json" },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const uri = request.params.uri;
  const wrap = (data) => ({ contents: [{ uri, mimeType: "application/json", text: JSON.stringify(data, null, 2) }] });

  if (uri === "shieldnet://attack-vectors") {
    return wrap({
      modules: {
        security_headers: ["HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Cookie flags"],
        injection: ["Reflected XSS", "SQL Injection (boolean/UNION/time-based)", "Server-Side Template Injection", "Command Injection", "Path Traversal", "SSRF", "Open Redirect"],
        info_disclosure: ["25 sensitive paths (.env, .git, package.json, swagger, backups, server-status, etc.)"],
        tls: ["HTTP vs HTTPS", "HTTPS redirect check"],
        auth: ["JWT exposure", "JWT 'none' algorithm", "API keys in source", "Passwords in source", "Email harvesting"],
        misconfiguration: ["CORS origin reflection", "CORS credentials+wildcard", "TRACE method", "Version disclosure in errors"],
        rate_limiting: ["20-request burst test"],
      },
      total_checks: "50+ individual checks across 7 modules",
    });
  }
  if (uri === "shieldnet://scan-history") return wrap({ scans: scanHistory });
  if (uri === "shieldnet://governance-policy") {
    return wrap({
      policy: "ShieldNet Governance Policy v1.0",
      thresholds: { ALLOW: "≥ 70, no criticals", WARN: "50-69 or high findings", BLOCK: "< 50 or criticals" },
      auto_block_on: ["Any critical vulnerability", "More than 2 high-severity findings"],
    });
  }
  throw new Error(`Unknown resource: ${uri}`);
});

// ─── Prompts ────────────────────────────────────────────────────────

server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: [
    { name: "security_audit", description: "Full security audit with governance decision", arguments: [{ name: "url", required: true }, { name: "context", required: false }] },
    { name: "pre_deployment_check", description: "Security gate check before deployment", arguments: [{ name: "url", required: true }] },
  ],
}));

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const msg = (text) => ({ messages: [{ role: "user", content: { type: "text", text } }] });

  if (name === "security_audit") {
    return msg(`Security audit for ${args.url}.\n\n1. scan_url to find vulnerabilities\n2. assess_risk for governance decision\n3. Report: executive summary, findings by severity, ALLOW/WARN/BLOCK, remediation\n\nContext: ${args.context || "Routine audit"}`);
  }
  if (name === "pre_deployment_check") {
    return msg(`Pre-deployment gate for ${args.url}.\n\n1. check_headers\n2. scan_url (aggressive)\n3. assess_risk\n\nBLOCK = list blocking issues. WARN = list concerns. ALLOW = confirm safe.\nBe strict — this is a production gate.`);
  }
  throw new Error(`Unknown prompt: ${name}`);
});

// ─── Start ──────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("ShieldNet MCP Server v1.0.0 — 7 modules, 50+ checks");
