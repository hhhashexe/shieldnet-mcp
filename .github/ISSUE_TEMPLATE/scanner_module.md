---
name: Scanner Module
about: Propose or track a new scanner module for ShieldNet MCP
title: "[SCANNER] "
labels: scanner
assignees: ""
---

## Module Name
<!-- e.g., ReentrancyGuard, FlashLoanDetector, AccessControlAudit -->

## What It Checks
<!-- Describe the vulnerability class or pattern this scanner detects. -->

## Attack Vectors
<!-- List known attack vectors or exploit paths this module should catch. -->

## False Positive Mitigation
<!-- How will this module avoid flagging safe patterns as vulnerable? -->

## Example Output
<!-- Show an example of the expected scan output / report format. -->
```json
{
  "file": "contracts/Vault.sol",
  "line": 42,
  "severity": "high",
  "pattern": "reentrancy",
  "message": "External call before state update — potential reentrancy"
}
```
