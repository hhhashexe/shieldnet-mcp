#!/usr/bin/env node
/**
 * ShieldNet MCP Server — Integration Test Suite
 *
 * Tests all 6 MCP tools via the official MCP Client SDK over JSON-RPC
 * stdin/stdout. Spawns the server as a child process.
 *
 * Usage:  node test/test.js
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_PATH = path.resolve(__dirname, "../src/index.js");

// ─── Minimal assertion helpers ────────────────────────────────────────

let passed = 0;
let failed = 0;
const errors = [];

function assert(condition, label) {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${label}`);
    failed++;
    errors.push(label);
  }
}

function assertNoError(result, label) {
  let parsed;
  try {
    const text = result?.content?.[0]?.text ?? "{}";
    parsed = JSON.parse(text);
  } catch {
    assert(false, `${label} — response not valid JSON`);
    return null;
  }
  assert(!parsed.error, `${label} — no error field (got: ${parsed.error ?? "none"})`);
  return parsed;
}

// ─── Test runner ─────────────────────────────────────────────────────

const SAFE_TARGET = "https://example.com";

async function runTests(client) {
  // ── 1. scan_url ──────────────────────────────────────────────────
  console.log("\n📋 Tool: scan_url");

  {
    const res = await client.callTool({ name: "scan_url", arguments: { url: SAFE_TARGET } });
    const data = assertNoError(res, "scan_url — valid URL returns no error");
    if (data) {
      assert(typeof data.url === "string", "scan_url — result.url is string");
      assert(typeof data.score === "number", "scan_url — result.score is number");
      assert(data.score >= 0 && data.score <= 100, "scan_url — score in [0, 100]");
      assert(["A","B","C","D","F"].includes(data.grade), "scan_url — grade is letter");
      assert(Array.isArray(data.findings), "scan_url — findings is array");
      assert(typeof data.summary === "object", "scan_url — summary is object");
      assert(["standard","aggressive"].includes(data.mode), "scan_url — mode is valid");
      assert(Array.isArray(data.modules_run), "scan_url — modules_run is array");
      assert(data.modules_run.length >= 6, "scan_url — at least 6 modules ran");
    }
  }

  // No false positives on example.com
  {
    const res = await client.callTool({ name: "scan_url", arguments: { url: SAFE_TARGET } });
    const data = assertNoError(res, "scan_url — example.com no false positives");
    if (data) {
      const criticals = data.findings.filter(f => f.severity === "critical");
      assert(criticals.length === 0, `scan_url — no critical findings on example.com (found: ${JSON.stringify(criticals.map(f => f.vector))})`);
    }
  }

  // Invalid URL
  {
    const res = await client.callTool({ name: "scan_url", arguments: { url: "not-a-url" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "scan_url — invalid URL returns error");
  }

  // Empty url
  {
    const res = await client.callTool({ name: "scan_url", arguments: { url: "" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "scan_url — empty URL returns error");
  }

  // Missing url
  {
    const res = await client.callTool({ name: "scan_url", arguments: {} });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "scan_url — missing URL returns error");
  }

  // Non-http protocol
  {
    const res = await client.callTool({ name: "scan_url", arguments: { url: "ftp://example.com" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "scan_url — ftp:// returns error");
  }

  // ── 2. assess_risk ───────────────────────────────────────────────
  console.log("\n📋 Tool: assess_risk");

  {
    const res = await client.callTool({ name: "assess_risk", arguments: { url: SAFE_TARGET } });
    const data = assertNoError(res, "assess_risk — valid URL returns no error");
    if (data) {
      assert(["ALLOW","WARN","BLOCK"].includes(data.decision), "assess_risk — decision is valid");
      assert(typeof data.confidence === "number", "assess_risk — confidence is number");
      assert(data.confidence > 0 && data.confidence <= 1, "assess_risk — confidence in (0,1]");
      assert(typeof data.reasoning === "string", "assess_risk — reasoning is string");
      assert(Array.isArray(data.blocking_issues), "assess_risk — blocking_issues is array");
      assert(Array.isArray(data.recommendations), "assess_risk — recommendations is array");
      assert(data.policy === "ShieldNet Governance Policy v1.0", "assess_risk — policy string correct");
    }
  }

  // With context
  {
    const res = await client.callTool({ name: "assess_risk", arguments: { url: SAFE_TARGET, context: "pre-deployment gate" } });
    const data = assertNoError(res, "assess_risk — with context");
    if (data) {
      assert(data.context === "pre-deployment gate", "assess_risk — context echoed back");
    }
  }

  // Invalid URL
  {
    const res = await client.callTool({ name: "assess_risk", arguments: { url: "javascript:alert(1)" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "assess_risk — javascript: URL blocked");
  }

  // ── 3. check_headers ────────────────────────────────────────────
  console.log("\n📋 Tool: check_headers");

  {
    const res = await client.callTool({ name: "check_headers", arguments: { url: SAFE_TARGET } });
    const data = assertNoError(res, "check_headers — valid URL");
    if (data) {
      assert(typeof data.url === "string", "check_headers — url present");
      assert(typeof data.missing_headers === "number", "check_headers — missing_headers is number");
      assert(typeof data.headers_checked === "number", "check_headers — headers_checked is number");
      assert(["PASS","WARN","FAIL"].includes(data.verdict), "check_headers — verdict is valid");
      assert(Array.isArray(data.findings), "check_headers — findings is array");
    }
  }

  // Invalid URL
  {
    const res = await client.callTool({ name: "check_headers", arguments: { url: "://bad" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "check_headers — bad URL returns error");
  }

  // ── 4. scan_history ──────────────────────────────────────────────
  console.log("\n📋 Tool: scan_history");

  {
    const res = await client.callTool({ name: "scan_history", arguments: {} });
    const data = assertNoError(res, "scan_history — no args works");
    if (data) {
      assert(typeof data.total_scans === "number", "scan_history — total_scans is number");
      assert(Array.isArray(data.recent), "scan_history — recent is array");
      // We've done at least 3 scans above
      assert(data.total_scans >= 3, `scan_history — at least 3 scans recorded (got ${data.total_scans})`);
    }
  }

  // With limit
  {
    const res = await client.callTool({ name: "scan_history", arguments: { limit: 2 } });
    const data = assertNoError(res, "scan_history — limit=2");
    if (data) {
      assert(data.recent.length <= 2, "scan_history — limit honoured");
    }
  }

  // ── 5. compare_scans ─────────────────────────────────────────────
  console.log("\n📋 Tool: compare_scans");

  {
    const res = await client.callTool({
      name: "compare_scans",
      arguments: { url1: SAFE_TARGET, url2: "http://example.com" },
    });
    const data = assertNoError(res, "compare_scans — two valid URLs");
    if (data) {
      assert(typeof data.url1 === "object", "compare_scans — url1 result object");
      assert(typeof data.url2 === "object", "compare_scans — url2 result object");
      assert(typeof data.safer === "string", "compare_scans — safer is string");
      assert(typeof data.score_difference === "number", "compare_scans — score_difference is number");
    }
  }

  // Invalid url1
  {
    const res = await client.callTool({ name: "compare_scans", arguments: { url1: "bad", url2: SAFE_TARGET } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "compare_scans — bad url1 returns error");
  }

  // Invalid url2
  {
    const res = await client.callTool({ name: "compare_scans", arguments: { url1: SAFE_TARGET, url2: "bad" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "compare_scans — bad url2 returns error");
  }

  // ── 6. governance_policy ─────────────────────────────────────────
  console.log("\n📋 Tool: governance_policy");

  {
    const res = await client.callTool({ name: "governance_policy", arguments: {} });
    const data = assertNoError(res, "governance_policy — view (default)");
    if (data) {
      assert(typeof data.policy === "string", "governance_policy — policy string present");
      assert(typeof data.thresholds === "object", "governance_policy — thresholds present");
      assert(Array.isArray(data.modules), "governance_policy — modules is array");
    }
  }

  {
    const res = await client.callTool({ name: "governance_policy", arguments: { action: "view" } });
    const data = assertNoError(res, "governance_policy — action=view explicit");
    if (data) {
      assert(data.policy === "ShieldNet Governance Policy v1.0", "governance_policy — policy name correct");
    }
  }

  // evaluate — ALLOW
  {
    const res = await client.callTool({ name: "governance_policy", arguments: { action: "evaluate", score: 85 } });
    const data = assertNoError(res, "governance_policy — evaluate score=85");
    if (data) {
      assert(data.decision === "ALLOW", `governance_policy — score 85 → ALLOW (got ${data.decision})`);
    }
  }

  // evaluate — WARN
  {
    const res = await client.callTool({ name: "governance_policy", arguments: { action: "evaluate", score: 60 } });
    const data = assertNoError(res, "governance_policy — evaluate score=60");
    if (data) {
      assert(data.decision === "WARN", `governance_policy — score 60 → WARN (got ${data.decision})`);
    }
  }

  // evaluate — BLOCK
  {
    const res = await client.callTool({ name: "governance_policy", arguments: { action: "evaluate", score: 30 } });
    const data = assertNoError(res, "governance_policy — evaluate score=30");
    if (data) {
      assert(data.decision === "BLOCK", `governance_policy — score 30 → BLOCK (got ${data.decision})`);
    }
  }

  // evaluate — non-numeric score
  {
    const res = await client.callTool({ name: "governance_policy", arguments: { action: "evaluate", score: "bad" } });
    const data = JSON.parse(res?.content?.[0]?.text ?? "{}");
    assert(typeof data.error === "string", "governance_policy — non-numeric score returns error");
  }

  // score clamping — above 100
  {
    const res = await client.callTool({ name: "governance_policy", arguments: { action: "evaluate", score: 150 } });
    const data = assertNoError(res, "governance_policy — score=150 clamped");
    if (data) {
      assert(data.score <= 100, "governance_policy — score clamped to ≤ 100");
      assert(data.decision === "ALLOW", "governance_policy — clamped 150→100 → ALLOW");
    }
  }
}

// ─── Main ─────────────────────────────────────────────────────────────

async function main() {
  console.log("🛡  ShieldNet MCP — Integration Test Suite");
  console.log("============================================");
  console.log(`Target: ${SAFE_TARGET}`);
  console.log("Starting server…\n");

  const transport = new StdioClientTransport({
    command: "node",
    args: [SERVER_PATH],
  });

  const client = new Client({ name: "shieldnet-test-client", version: "1.0.0" }, { capabilities: {} });

  try {
    await client.connect(transport);
    console.log("✅ Server connected\n");

    // Verify tools are listed correctly
    const tools = await client.listTools();
    const toolNames = tools.tools.map(t => t.name);
    console.log(`📦 Registered tools: ${toolNames.join(", ")}\n`);
    assert(toolNames.includes("scan_url"),          "ListTools — scan_url registered");
    assert(toolNames.includes("assess_risk"),        "ListTools — assess_risk registered");
    assert(toolNames.includes("check_headers"),      "ListTools — check_headers registered");
    assert(toolNames.includes("scan_history"),       "ListTools — scan_history registered");
    assert(toolNames.includes("compare_scans"),      "ListTools — compare_scans registered");
    assert(toolNames.includes("governance_policy"),  "ListTools — governance_policy registered");
    assert(tools.tools.length === 6,                 `ListTools — exactly 6 tools (got ${tools.tools.length})`);

    // Verify resources
    const resources = await client.listResources();
    const uris = resources.resources.map(r => r.uri);
    assert(uris.includes("shieldnet://attack-vectors"),    "ListResources — attack-vectors");
    assert(uris.includes("shieldnet://scan-history"),      "ListResources — scan-history");
    assert(uris.includes("shieldnet://governance-policy"), "ListResources — governance-policy");

    // Verify prompts
    const prompts = await client.listPrompts();
    const promptNames = prompts.prompts.map(p => p.name);
    assert(promptNames.includes("security_audit"),       "ListPrompts — security_audit");
    assert(promptNames.includes("pre_deployment_check"), "ListPrompts — pre_deployment_check");

    await runTests(client);

  } catch (err) {
    console.error("\n💥 Fatal error:", err.message);
    process.exitCode = 1;
  } finally {
    await client.close();

    console.log("\n============================================");
    console.log(`Results: ${passed} passed, ${failed} failed`);
    if (errors.length > 0) {
      console.error("\nFailed assertions:");
      for (const e of errors) console.error(`  • ${e}`);
    }
    console.log(failed === 0 ? "\n🎉 All tests passed!" : "\n❌ Some tests FAILED");
    process.exitCode = failed > 0 ? 1 : 0;
  }
}

main();
