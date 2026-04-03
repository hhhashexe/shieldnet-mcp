#!/usr/bin/env bash
# ============================================================
#  ShieldNet MCP — Interactive Demo
#  Demonstrates the scanner via MCP JSON-RPC over stdio:
#    1. tools/list  — discover available tools
#    2. scan_url    — run a live security scan
#  Pretty-prints the results with color formatting.
#
#  Usage:  bash demo.sh [URL]
#          bash demo.sh https://example.com
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TARGET="${1:-https://example.com}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$SCRIPT_DIR/src/index.js"
FORMATTER="$SCRIPT_DIR/demo_format.py"

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║       🛡️  ShieldNet MCP — Security Scanner Demo           ║${NC}"
echo -e "${BOLD}${BLUE}║          MCP_HACK//26 · Track: Secure & Govern MCP       ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Target: ${BOLD}${TARGET}${NC}"
echo -e "  ${DIM}Mode:   standard scan (7 modules, 50+ checks)${NC}"
echo ""

# ─── Dependency checks ───────────────────────────────────────
deps_ok=true
for dep in node python3; do
  if ! command -v "$dep" &>/dev/null; then
    echo -e "  ${RED}✗ missing:${NC} '$dep' is required but not found." >&2
    deps_ok=false
  else
    echo -e "  ${GREEN}✓${NC} ${dep} found: $(command -v "$dep")"
  fi
done
if [[ ! -d "$SCRIPT_DIR/node_modules" ]]; then
  echo -e "  ${RED}✗ missing:${NC} node_modules — run 'npm install' first." >&2
  deps_ok=false
else
  echo -e "  ${GREEN}✓${NC} dependencies installed"
fi
if [[ "$deps_ok" = false ]]; then
  exit 1
fi
if [[ ! -f "$SERVER" ]]; then
  echo -e "${RED}Error: $SERVER not found. Run from the project root.${NC}" >&2; exit 1
fi

echo ""
echo -e "${DIM}  Launching ShieldNet MCP server…${NC}"

# ─── Build MCP JSON-RPC request sequence ──────────────────────
# MCP uses newline-delimited JSON-RPC 2.0 over stdio.
# Step 1: handshake (initialize + initialized notification)
# Step 2: tools/list  — discover what the server offers
# Step 3: tools/call  — run scan_url against the target
# Step 4: tools/call  — run assess_risk for governance decision
REQUESTS="$(printf '%s\n' \
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"shieldnet-demo\",\"version\":\"1.0.0\"}}}" \
  "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"scan_url\",\"arguments\":{\"url\":\"${TARGET}\",\"mode\":\"standard\"}}}" \
  "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"assess_risk\",\"arguments\":{\"url\":\"${TARGET}\",\"context\":\"demo run\"}}}")"

# ─── Execute: pipe requests into server, capture all responses ──
RAW_OUTPUT="$(echo "$REQUESTS" | timeout 60 node "$SERVER" 2>/dev/null || true)"

if [[ -z "$RAW_OUTPUT" ]]; then
  echo -e "${RED}Error: No output from server.${NC}" >&2
  echo -e "${RED}Make sure dependencies are installed: npm install${NC}" >&2
  exit 1
fi

# ─── Parse & display tools/list ───────────────────────────────
TOOLS_BLOCK="$(echo "$RAW_OUTPUT" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('{'): continue
    try:
        obj = json.loads(line)
        if obj.get('id') == 2 and 'result' in obj:
            tools = obj['result'].get('tools', [])
            for t in tools:
                name = t.get('name','?')
                desc = (t.get('description','') or '')[:80]
                print(f'  {chr(0x25b6) if True else \" \"}  {name}: {desc}')
    except: pass
" 2>/dev/null || true)"

if [[ -n "$TOOLS_BLOCK" ]]; then
  echo -e "\n${BOLD}${GREEN}📥 Available MCP Tools:${NC}"
  echo "$TOOLS_BLOCK"
fi

# ─── Format and print scan results ───────────────────────────
echo ""
echo "$RAW_OUTPUT" | python3 "$FORMATTER" "$TARGET"
