# ShieldNet MCP — Integration Analysis for MCP_HACK//26

> **Context:** "Secure & Govern MCP" track — MCP & AI Agents Hackathon 2026
> **Deadline:** April 3, 2026 11:59 PM ET (TODAY!)
> **Prize:** $1,000 cash + Credly badge + 1:1 with expert + swag
> **Judges:** Chris Aniszczyk (CNCF CTO), Lin Sun (Solo.io VP OSS), Christian Posta (Solo.io FCTO), Michael Levan (Solo.io AI Architect), Alan Blount (Google ADK), Dmytro Rashko, Nathan Taber (NVIDIA), Carlos Santana (AWS), Keith Mattix (Microsoft), Sebastian Maniak (Snyk/HashiCorp MVP)

---

## 🔬 Project Analyses

---

### 1. AgentGateway (solo-io/agentgateway)

#### What It Does

AgentGateway is an **open-source, AI-native data-plane proxy** built for agentic AI communication. It routes and secures traffic between AI agents, MCP (Model Context Protocol) servers, A2A (Agent-to-Agent) backends, and LLM providers. Written in **Rust**, it supports Kubernetes Gateway API natively, uses standard CRDs (`AgentgatewayBackend`, `HTTPRoute`), and provides enterprise features like JWT auth, CEL-based RBAC, rate limiting, prompt guardrails, OTel observability, and OpenAPI-to-MCP translation. Think of it as Envoy, but purpose-built for the MCP/A2A era.

#### ShieldNet MCP Integration: The "Security Scanner Sidecar" Pattern

This is the **biggest opportunity** for a winning hackathon submission. AgentGateway already has:
- **MCP federation** — it aggregates multiple MCP servers into a virtualized endpoint
- **Static & Dynamic MCP routing** via `AgentgatewayBackend` CRD
- **ExtProc (External Processing)** — hooks for custom processing on requests/responses
- **Guardrail webhooks** for prompt/response moderation

**ShieldNet MCP integrates as a security-scanning MCP server** that AgentGateway federates alongside your production MCP servers. Every tool call gets scanned before execution.

#### Integration Option A: Static MCP Security Scanner (Easiest — Demo-Ready)

Deploy ShieldNet MCP as a standard MCP server that AgentGateway proxies:

```yaml
# Step 1: Deploy ShieldNet MCP as a Kubernetes Service
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shieldnet-mcp-scanner
spec:
  selector:
    matchLabels:
      app: shieldnet-mcp-scanner
  template:
    metadata:
      labels:
        app: shieldnet-mcp-scanner
    spec:
      containers:
        - name: shieldnet
          image: shieldnet/mcp-scanner:latest
          ports:
            - containerPort: 8000
          env:
            - name: SHIELDNET_POLICY
              value: "strict"
            - name: SHIELDNET_SCAN_LEVELS
              value: "secrets,dependency_vulns,prompt_injection,tool_safety"
---
apiVersion: v1
kind: Service
metadata:
  name: shieldnet-mcp-scanner
  annotations:
    agentgateway.dev/mcp-path: "/mcp"
spec:
  selector:
    app: shieldnet-mcp-scanner
  ports:
    - port: 80
      targetPort: 8000
      appProtocol: agentgateway.dev/mcp  # ← critical annotation

# Step 2: Register as an AgentgatewayBackend
---
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: shieldnet-security-backend
spec:
  mcp:
    targets:
      - name: shieldnet-scanner
        static:
          host: shieldnet-mcp-scanner.default.svc.cluster.local
          port: 80
          protocol: StreamableHTTP  # or SSE

# Step 3: Route to the security scanner
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: shieldnet-mcp-route
spec:
  parentRefs:
    - name: agentgateway-proxy
      namespace: agentgateway-system
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /shieldnet
      backendRefs:
        - name: shieldnet-security-backend
          group: agentgateway.dev
          kind: AgentgatewayBackend
```

**ShieldNet MCP tools exposed through this integration:**
- `shieldnet_scan_prompt(input)` — Scans prompts for injection attacks
- `shieldnet_scan_dependencies(project_path)` — Checks for vulnerable deps
- `shieldnet_scan_secrets(file_content)` — Detects hardcoded secrets/keys
- `shieldnet_assess_tool_risk(tool_spec)` — Evaluates MCP tool specs for dangerous capabilities
- `shieldnet_audit_session(session_id)` — Reviews agent tool-call history for anomalies

#### Integration Option B: Pre-Flight Safety Guardrail via ExtProc

Use AgentGateway's **ExtProc** (external processing) to call ShieldNet before any MCP tool invocation reaches the backend:

```yaml
# ExtProc Filter that validates MCP tool calls via ShieldNet
apiVersion: agentgateway.dev/v1alpha1
kind: EnvoyExtensionPolicy
metadata:
  name: shieldnet-extproc
spec:
  extProc:
    - backendRefs:
        - group: ""
          kind: Service
          name: shieldnet-extproc-validator
          port: 9000
      processingMode:
        request:
          body: Buffered
        response:
          body: Buffered
```

This creates a **transparent security layer** — every request/response passing through AgentGateway gets validated without changing the agent code.

#### Integration Option C: Guardrail Webhook

AgentGateway supports **LLM guardrail webhooks**. ShieldNet can serve as the moderation endpoint:

```yaml
# AgentGateway guardrail config pointing to ShieldNet
apiVersion: agentgateway.dev/v1alpha1
kind: LLMGuardrail
metadata:
  name: shieldnet-guardrail
spec:
  webhook:
    url: "http://shieldnet-mcp-scanner.shieldnet.svc:8000/v1/guardrail"
    timeout: 3s
  policy:
    promptInspection: enabled
    responseInspection: enabled
    severityThreshold: high
```

#### Why Judges Will Love This

- **Direct relevance**: AgentGateway is *the* hackathon sponsor project
- **Native integration**: Uses standard Kubernetes CRDs (no hacky sidecars)
- **Security-first**: Exactly the "Secure & Govern" track theme
- **Production pattern**: The Static MCP + ExtProc combo is enterprise-grade

---

### 2. Kagent (kagent-dev/kagent)

#### What It Does

Kagent is a **Kubernetes-native framework for building, deploying, and managing AI agents**. It introduces CRDs (`Agent`, `ToolServer`, `RemoteMCPServer`, `ModelConfig`) that let you declare agents as YAML. Agents run on Google ADK (Python) or a native Go runtime, with built-in tools for Kubernetes, Istio, Helm, Argo, Prometheus, Grafana, and Cilium. The controller manages deployments, a CLI provides management, and a web dashboard enables interactive chat. Core philosophy: **declarative, observable, testable AI agents on Kubernetes**.

#### ShieldNet MCP Integration: "Security ToolServer" for Kagent Agents

Kagent agents consume tools via `RemoteMCPServer` or `MCPServer` CRDs. ShieldNet integrates as a **dedicated security ToolServer** that kagent agents query before executing tools.

#### Integration: ShieldNet as a Kagent RemoteMCPServer

```yaml
# Step 1: Deploy ShieldNet MCP server as a Kubernetes Service
apiVersion: v1
kind: Service
metadata:
  name: shieldnet-security-scanner
  labels:
    app: shieldnet-security
    kagent.dev/mcp-server: "true"
spec:
  selector:
    app: shieldnet-mcp
  ports:
    - name: mcp
      port: 8000
      targetPort: 8000
---
# Step 2: Register as a RemoteMCPServer in kagent
apiVersion: kagent.dev/v1alpha2
kind: RemoteMCPServer
metadata:
  name: shieldnet-server
  namespace: kagent
spec:
  endpoint: "http://shieldnet-security-scanner.kagent.svc.cluster.local:8000/mcp"
  description: "Security scanning tools for ShieldNet MCP"

# Step 3: Attach ShieldNet tools to a security-audit Agent
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: security-audit-agent
  namespace: kagent
spec:
  description: "Audits cluster security and flags vulnerabilities"
  type: Declarative
  declarative:
    modelConfig: default-model-config
    systemMessage: |
      You are a security-focused agent that audits Kubernetes clusters.
      Before accessing any cloud-native tool (Helm, Istio, ArgoCD), 
      ALWAYS run shieldnet_scan_environment() first.
      If threats are detected, report them and do NOT proceed with changes.
    tools:
      # ShieldNet security tools (always available)
      - mcpServer:
          apiGroup: kagent.dev
          kind: RemoteMCPServer
          name: shieldnet-server
        toolNames:
          - shieldnet_scan_environment
          - shieldnet_scan_deployments
          - shieldnet_check_network_policies
          - shieldnet_detect_secrets
      # Operational tools (guarded by ShieldNet pre-flight)
      - mcpServer:
          apiGroup: kagent.dev
          kind: RemoteMCPServer
          name: kagent-tool-server
        toolNames:
          - k8s_get_resources
          - helm_list_releases
          - istio_analyze
```

#### Integration: "Security Pipeline" Agent Chain

Create a two-agent pipeline where ShieldNet acts as a gatekeeper:

```yaml
# Agent 1: Security pre-flight (uses ShieldNet)
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: security-gate
spec:
  type: Declarative
  declarative:
    modelConfig: default-model-config
    systemMessage: |
      You are a security gate. Scan the requested operation.
      Return "APPROVE" or "BLOCK" with reasoning.
    tools:
      - mcpServer:
          kind: RemoteMCPServer
          name: shieldnet-server
        toolNames:
          - shieldnet_assess_operation

# Agent 2: Operational agent (only runs if gate approves)
apiVersion: kagent.dev/v1alpha2
kind: Agent
metadata:
  name: cluster-operator
spec:
  type: Declarative
  declarative:
    modelConfig: default-model-config
    systemMessage: |
      You manage cluster resources. Before ANY write operation,
      check with the "security-gate" agent first.
    tools:
      - mcpServer:
          kind: RemoteMCPServer
          name: kagent-tool-server
        toolNames:
          - helm_upgrade
          - k8s_apply_manifest
```

#### Integration: ShieldNet + Kagent Tracing = Security Observability

Kagent supports **OpenTelemetry tracing**. ShieldNet can inject security metadata into traces:

```python
# ShieldNet MCP tool implementation
from opentelemetry import trace
from mcp.server import Server

tracer = trace.get_tracer("shieldnet")

@server.tool()
async def shieldnet_scan_deployment(name: str, namespace: str) -> dict:
    with tracer.start_as_current_span("shieldnet.scan") as span:
        result = await run_scan(name, namespace)
        span.set_attribute("shieldnet.severity", result.severity)
        span.set_attribute("shieldnet.findings", len(result.findings))
        span.set_attribute("shieldnet.status", "PASS" if result.safe else "FAIL")
        return result.to_dict()
```

This means ShieldNet scan results appear in **Grafana/Jaeger alongside kagent's existing traces** — a unified security + operations dashboard.

#### Why Judges Will Love This

- **"Building Cool Agents" track crossover**: Uses kagent's actual CRDs
- **Real-world pattern**: Pre-flight scanning is what enterprises need
- **CNCF alignment**: Kagent is a CNCF sandbox project
- **Multi-layered security**: Combines MCP tools + agent chains + traces

---

### 3. AgentRegistry (agentregistry org)

#### What It Does

AgentRegistry is the **up-and-coming project** for discovering, sharing, and versioning AI agents, skills, and MCP servers in the ecosystem. It's designed to solve the "tool sprawl" problem — instead of every team building custom tool integrations, there's a centralized registry where you publish and discover vetted MCP servers and agent configurations. From the hackathon site: *"Dive deep into agentregistry with MCP, agents, or skills. Extend the registry, build integrations, or create tools that enhance discoverability."*

> ⚠️ **Note:** The GitHub org currently has no public repositories (private/internal development). Analysis below is based on the hackathon track description and industry standards for registry patterns.

#### ShieldNet MCP Integration: "Security Badge" for Published Skills

The registry is the perfect chokepoint for security. ShieldNet can:

1. **Pre-publish scanning** — When a contributor uploads a new MCP server or skill, ShieldNet automatically scans it
2. **Security badges/signatures** — Registry entries get a "ShieldNet Verified" badge after passing security checks
3. **Policy gating** — Only ShieldNet-approved servers can be listed in the registry

#### Integration Concept: Registry Validation Pipeline

```yaml
# ShieldNet as a pre-publish validation step
apiVersion: batch/v1
kind: CronJob
metadata:
  name: registry-security-scan
spec:
  schedule: "*/30 * * * *"  # Scan new entries every 30 min
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: shieldnet-scanner
              image: shieldnet/registry-scanner:latest
              command: ["shieldnet-scan-registry"]
              args:
                - "--registry-url=https://agentregistry.dev/api/v1"
                - "--auto-badge=true"
                - "--reject-critical=true"
              env:
                - name: SHIELDNET_MODE
                  value: "registry-validation"
```

#### Integration Concept: MCP Server Security Metadata

Every published MCP server in the registry includes ShieldNet metadata:

```json
{
  "name": "kubernetes-manager",
  "description": "Manage K8s clusters via MCP tools",
  "version": "1.2.0",
  "shieldnet_security": {
    "badge": "✅ verified",
    "scan_date": "2026-04-02T18:00:00Z",
    "secrets_found": 0,
    "vulnerabilities": [],
    "risk_level": "low",
    "tool_capabilities": {
      "reads_cluster_state": true,
      "writes_resources": true,
      "deletes_resources": false,
      "network_access": ["kubernetes-api"]
    },
    "prompt_injection_risk": "low",
    "data_exfiltration_risk": "medium"
  }
}
```

#### Integration Concept: ShieldNet MCP Server Published TO the Registry

The hackathon submission itself can publish ShieldNet as a registry entry:

```yaml
# shieldnet-mcp Skill/Server entry for AgentRegistry
apiVersion: agentregistry.dev/v1alpha1
kind: MCPServerEntry
metadata:
  name: shieldnet-security-scanner
spec:
  title: "ShieldNet MCP — Security Scanner"
  category: "security"
  description: "Automated security scanning for MCP agents and tools"
  endpoints:
    - transport: "streamable-http"
      url: "https://shieldnet.example.com/mcp"
  tools:
    - name: "shieldnet_scan_prompt"
      description: "Detect prompt injection in MCP tool inputs"
    - name: "shieldnet_scan_dependencies"
      description: "Scan project dependencies for known CVEs"
    - name: "shieldnet_scan_secrets"
      description: "Detect hardcoded secrets and API keys"
  metadata:
    self_scanned: true
    security_level: "enterprise"
```

#### Why Judges Will Love This

- **Untapped territory**: No public repos = huge opportunity to be first
- **"Explore Agent Registry" track**: Direct fit
- **Security as a first-class concern**: Makes the registry trustworthy
- **Network effect**: Every published skill gets free security scanning

---

## 🏆 What Makes a Winning "Secure & Govern MCP" Submission

Based on the hackathon details, judges include **CNCF, Solo.io, Google, AWS, Microsoft, and NVIDIA** leadership. Here's what will separate winners from runners-up:

### 1. **Works with AgentGateway + Kagent Together** (Highest Impact)
Don't just target one project. A submission that shows ShieldNet MCP working as:
- An `AgentgatewayBackend` MCP server in AgentGateway AND
- A `RemoteMCPServer` in Kagent agents

That demonstrates **cross-ecosystem thinking** — exactly what enterprise buyers need.

### 2. **Live Demo > Slides** (Non-Negotiable)
- Deployable via `helm install` or `kubectl apply -f`
- Shows a real attack being blocked (e.g., prompt injection, secret exfiltration)
- Dashboard with real scan results

### 3. **Ties to the Exact Track Theme**
The track says: *"Focus on security and governance of MCP/AI agents with agentgateway. Build tools that help secure, monitor, and manage AI agent deployments."*

Key words: **secure**, **monitor**, **manage**, **agentgateway**.

### 4. **Judge-Specific Bait** 🎣
| Judge | Cares About | Show Them |
|-------|-------------|-----------|
| **Chris Aniszczyk (CNCF)** | Cloud-native standards, open source | K8s CRDs, CNCF ecosystem fit |
| **Lin Sun (Solo.io VP OSS)** | Istio, AgentGateway adoption | Native agentgateway integration |
| **Christian Posta (Solo.io FCTO)** | Practical enterprise patterns | Production-ready YAML configs |
| **Michael Levan (Solo.io AI Architect)** | Developer experience | Easy installation, clear docs |
| **Alan Blount (Google ADK)** | ADK compatibility | Works with kagent's ADK engine |
| **Sebastian Maniak (Snyk/HashiCorp)** | Security depth | Real vulnerability detection |

### 5. **Submission Checklist**
- [ ] GitHub repo with clear README (architecture diagram, quickstart)
- [ ] Working demo (deploy script, test scenario showing attack + defense)
- [ ] Integration with at least one of: AgentGateway, Kagent, AgentRegistry
- [ ] Video demo or live walkthrough (3-5 minutes)
- [ ] Blog post explaining the "why" and "how"
- [ ] Registration confirmed (deadline April 3 11:59 PM ET)

### 6. **Differentiation Strategy**

Most submissions will build a basic MCP security wrapper. Stand out by:

| Layer | What Others Will Do | What ShieldNet Should Do |
|-------|-------------------|------------------------|
| **Scanner** | Check prompt text | Scan deps, secrets, network, runtime, and tool specs |
| **Integration** | One protocol | AgentGateway MCP + Kagent ToolServer + direct MCP |
| **UX** | Console output | Grafana dashboard + Grafana alerting rules |
| **Demo** | "It scans text" | Live attack/defense with real MCP tool interception |
| **Story** | Technical feature list | "Every MCP tool call gets a security guard — zero agent changes needed" |

### 7. **Winning Narrative**

> *"AgentGateway solves MCP connectivity. Kagent makes agents native to Kubernetes. But neither validates that the tools being called are safe. ShieldNet MCP is the security layer that sits between agents and tools — scanning every tool invocation, detecting prompt injections, flagging vulnerable dependencies, and preventing data exfiltration — all through the standard MCP protocol. Zero changes to agent code."*

---

## 📁 File Structure Recommendation

```
shieldnet-mcp/
├── README.md                    # Project overview, quickstart
├── INTEGRATIONS.md              # ← This file
├── src/
│   ├── mcp_server.py            # Main MCP server implementation
│   ├── scanners/
│   │   ├── prompt_injection.py  # Prompt injection detection
│   │   ├── secret_detection.py  # Hardcoded secrets scanner
│   │   ├── dependency_check.py  # CVE/dependency scanner
│   │   └── tool_assessment.py   # MCP tool capability risk analysis
│   └── integrations/
│       ├── agentgateway.yaml    # AgentGateway CRD configs
│       └── kagent.yaml          # Kagent CRD configs
├── deploy/
│   ├── helm/                    # Helm chart
│   └── k8s/                     # Raw k8s manifests
├── demo/
│   ├── attack_scenarios/        # Test inputs that trigger scans
│   └── grafana_dashboard.json   # Security dashboard
├── docs/
│   └── architecture.md          # Architecture diagram + explanation
└── tests/
    └── test_scanners.py         # Unit tests
```

---

*Generated: 2026-04-03 00:48 UTC*
*For: MCP_HACK//26 — "Secure & Govern MCP" Track*
