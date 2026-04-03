#!/usr/bin/env python3
"""
ShieldNet MCP Demo — Output formatter
Reads JSON-RPC responses from stdin, extracts scan results, prints formatted output.
Usage: echo "$RAW_OUTPUT" | python3 demo_format.py <target_url>
"""
import sys
import json

target = sys.argv[1] if len(sys.argv) > 1 else "unknown"
raw = sys.stdin.read()
lines = [l.strip() for l in raw.splitlines() if l.strip().startswith('{')]

scan_result = None
risk_result = None

for line in lines:
    try:
        obj = json.loads(line)
        if obj.get("id") == 3:
            text = obj.get("result", {}).get("content", [{}])[0].get("text", "{}")
            scan_result = json.loads(text)
        elif obj.get("id") == 4:
            text = obj.get("result", {}).get("content", [{}])[0].get("text", "{}")
            risk_result = json.loads(text)
    except Exception:
        pass

# ANSI color codes
R  = '\033[0;31m';  O  = '\033[0;33m';  Y  = '\033[1;33m'
G  = '\033[0;32m';  C  = '\033[0;36m';  B  = '\033[0;34m'
BL = '\033[1m';     DM = '\033[2m';     NC = '\033[0m'

SEV_COLOR   = {'critical': R, 'high': O, 'medium': Y, 'low': C, 'info': DM}
GRADE_COLOR = {'A': G, 'B': G, 'C': Y, 'D': O, 'F': R}

if not scan_result or scan_result.get("error"):
    err = (scan_result or {}).get("error", "no response from server")
    print(f"{R}Scan failed: {err}{NC}")
    sys.exit(1)

grade    = scan_result.get("grade", "?")
score    = scan_result.get("score", 0)
duration = scan_result.get("duration", "?")
summary  = scan_result.get("summary", {})
findings = scan_result.get("findings", [])
modules  = ', '.join(scan_result.get("modules_run", []))
gc = GRADE_COLOR.get(grade, NC)

print(f"{BL}┌─────────────── SCAN RESULTS ──────────────────────────┐{NC}")
print(f"{BL}│{NC}  URL      : {C}{target}{NC}")
print(f"{BL}│{NC}  Grade    : {gc}{BL}{grade}{NC}   Score: {gc}{score}/100{NC}")
print(f"{BL}│{NC}  Duration : {DM}{duration}{NC}")
print(f"{BL}│{NC}  Modules  : {DM}{modules}{NC}")
print(f"{BL}└───────────────────────────────────────────────────────┘{NC}")
print()

print(f"{BL}FINDING SUMMARY{NC}")
for sev, label in [('critical','Critical'),('high','High'),('medium','Medium'),('low','Low'),('info','Info')]:
    count = summary.get(sev, 0)
    sc = SEV_COLOR.get(sev, NC)
    bar = '█' * min(count, 20)
    print(f"  {sc}{label:<8} : {count:>3}  {bar}{NC}")
print(f"  {'─'*24}")
print(f"  {'Total':<8} : {summary.get('total',0):>3}")
print()

if findings:
    print(f"{BL}FINDINGS{NC}")
    for f in findings:
        sev  = f.get("severity", "info")
        sc   = SEV_COLOR.get(sev, NC)
        vec  = f.get("vector", "")
        det  = f.get("detail", "")
        evi  = f.get("evidence", "")
        print(f"  {sc}[{sev.upper():<8}]{NC} {BL}{vec}{NC}")
        print(f"             {det}")
        if evi:
            print(f"             {DM}↳ {evi}{NC}")
        print()
else:
    print(f"  {G}✓ No findings — this target looks clean!{NC}")
    print()

if risk_result and not risk_result.get("error"):
    decision   = risk_result.get("decision", "?")
    confidence = risk_result.get("confidence", 0)
    reasoning  = risk_result.get("reasoning", "")
    recs       = risk_result.get("recommendations", [])

    dc = {
        "ALLOW": f"{G}{BL}✅  ALLOW{NC}",
        "WARN":  f"{Y}{BL}⚠️   WARN{NC}",
        "BLOCK": f"{R}{BL}🚫  BLOCK{NC}"
    }.get(decision, decision)

    print(f"{BL}┌─────────────── GOVERNANCE DECISION ───────────────────┐{NC}")
    print(f"{BL}│{NC}  Decision   : {dc}")
    print(f"{BL}│{NC}  Confidence : {int(confidence * 100)}%")
    print(f"{BL}│{NC}  Reasoning  : {reasoning}")
    print(f"{BL}└───────────────────────────────────────────────────────┘{NC}")
    if recs:
        print()
        print(f"{BL}RECOMMENDATIONS{NC}")
        for r in recs:
            print(f"  • {r}")

print()
print(f"{DM}  Powered by ShieldNet MCP v1.0.0 — github.com/hhhashexe/shieldnet-mcp{NC}")
print()
