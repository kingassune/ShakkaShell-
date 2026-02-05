# ShakkaShell 2.0 - Product Requirements Document

**Document Version:** 1.0  
**Date:** February 2026  
**Author:** Assune  
**Status:** Draft  

---

## Executive Summary

ShakkaShell 2.0 transforms a 6-year-old natural language to security one-liner tool into a state-of-the-art autonomous offensive security platform. By incorporating 2025's cutting-edge research in AI-driven penetration testing, multi-agent orchestration, and the Model Context Protocol (MCP), ShakkaShell will become a serious tool for security professionals while remaining accessible enough to vibe code.

**Vision:** Any security task describable in plain text becomes executable—in any language, at any skill level.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Goals & Success Metrics](#2-goals--success-metrics)
3. [User Personas](#3-user-personas)
4. [Feature Specifications](#4-feature-specifications)
5. [Technical Architecture](#5-technical-architecture)
6. [Implementation Phases](#6-implementation-phases)
7. [Dependencies & Stack](#7-dependencies--stack)
8. [Risks & Mitigations](#8-risks--mitigations)
9. [Appendix: Research References](#9-appendix-research-references)

---

## 1. Problem Statement

### Current State
- Original ShakkaShell converts natural language to security one-liners via OpenAI
- Single-model, single-shot architecture
- No memory, no context, no tool awareness
- No integration with modern AI tooling ecosystem

### Market Context (2025-2026)
- Autonomous AI pentesting agents are production-ready (PentAGI, AutoPentester, HackSynth)
- MCP has become the standard for AI-tool integration (adopted by OpenAI, Anthropic, Google)
- Multi-agent architectures outperform single-LLM approaches by 228%+ (PentestAgent research)
- Research shows LLMs can autonomously replicate real breaches (CMU Equifax study)

### Opportunity
ShakkaShell can leapfrog competitors by combining:
- The simplicity of natural language interface (original vision)
- The power of multi-agent orchestration (2025 research)
- Universal tool access via MCP (2025 standard)
- Persistent learning via vector memory (proven architecture)

---

## 2. Goals & Success Metrics

### Primary Goals

| Goal | Metric | Target |
|------|--------|--------|
| Autonomous task completion | % of tasks requiring no human intervention | >60% |
| Multi-model support | Number of LLM providers supported | 5+ |
| Tool ecosystem integration | MCP-compatible hosts that can use ShakkaShell | 3+ |
| Developer adoption | GitHub stars within 6 months | 500+ |
| pip installability | `pip install shakkashell` works | Yes |

### Secondary Goals

| Goal | Metric | Target |
|------|--------|--------|
| Memory effectiveness | Successful recalls from vector store | >80% |
| CVE-to-exploit success | Working PoC generation rate | >30% |
| Command safety | Dangerous commands caught before execution | 100% |

---

## 3. User Personas

### Persona 1: The Weekend Pentester
**Name:** Alex  
**Experience:** 2 years in IT security, learning offensive techniques  
**Pain Points:**
- Forgets command syntax constantly
- Doesn't know which tool to use for what
- Wants to learn by doing, not reading man pages

**ShakkaShell Use Case:**
```
> shakka "find all open ports on 192.168.1.0/24 and check for default creds"
```

### Persona 2: The Red Team Lead
**Name:** Jordan  
**Experience:** 8 years, manages team of 5  
**Pain Points:**
- Junior team members ask repetitive questions
- Needs consistent methodology across engagements
- Report generation is tedious

**ShakkaShell Use Case:**
```
> shakka --agent "Full recon and initial access assessment on target.com, generate report"
```

### Persona 3: The AI-Native Developer
**Name:** Sam  
**Experience:** Building AI-powered tools, security-curious  
**Pain Points:**
- Wants to add security scanning to their AI workflow
- MCP integration is the expected standard
- Doesn't want to learn pentesting tools

**ShakkaShell Use Case:**
```python
# In their Claude Desktop / VS Code / AI IDE
"Use shakka to scan my local network for vulnerabilities"
```

---

## 4. Feature Specifications

### 4.1 Core Features (P0 - Must Have)

#### 4.1.1 Multi-Model Support
**Description:** Support for multiple LLM providers with easy switching.

**Supported Providers:**
- OpenAI (GPT-4, GPT-4o, o1, o3)
- Anthropic (Claude 3.5, Claude 4)
- Google (Gemini 2.5)
- Ollama (local models)
- OpenRouter (aggregator)
- DeepSeek
- Custom OpenAI-compatible endpoints

**Interface:**
```bash
shakka --model claude-4 "scan target"
shakka --model ollama/llama3.3 "scan target"
shakka --model openrouter/deepseek-r1 "scan target"
```

**Configuration:**
```yaml
# ~/.shakkashell/config.yaml
default_model: claude-sonnet-4
models:
  openai:
    api_key: ${OPENAI_API_KEY}
    models: [gpt-4o, o1, o3-mini]
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    models: [claude-sonnet-4, claude-opus-4]
  ollama:
    base_url: http://localhost:11434
    models: [llama3.3:70b, qwen3:32b]
```

**Acceptance Criteria:**
- [ ] Provider switching works without restart
- [ ] API keys from environment or config file
- [ ] Graceful fallback if provider unavailable
- [ ] Cost tracking per provider (optional)

---

#### 4.1.2 MCP Server Mode
**Description:** Expose ShakkaShell as an MCP server for integration with any MCP-compatible AI client.

**Protocol:** JSON-RPC 2.0 over stdio or HTTP

**Exposed Tools:**
```json
{
  "tools": [
    {
      "name": "shakka_execute",
      "description": "Convert natural language to security command and execute",
      "inputSchema": {
        "type": "object",
        "properties": {
          "prompt": { "type": "string", "description": "Natural language security task" },
          "execute": { "type": "boolean", "default": false },
          "explain": { "type": "boolean", "default": false }
        },
        "required": ["prompt"]
      }
    },
    {
      "name": "shakka_scan",
      "description": "Quick network/host scan",
      "inputSchema": {
        "type": "object",
        "properties": {
          "target": { "type": "string" },
          "scan_type": { "type": "string", "enum": ["quick", "full", "vuln"] }
        },
        "required": ["target"]
      }
    },
    {
      "name": "shakka_exploit",
      "description": "Lookup or generate exploit for CVE",
      "inputSchema": {
        "type": "object",
        "properties": {
          "cve": { "type": "string", "pattern": "^CVE-\\d{4}-\\d+$" }
        },
        "required": ["cve"]
      }
    }
  ]
}
```

**Interface:**
```bash
shakka --mcp                    # Start MCP server on stdio
shakka --mcp --port 3000        # Start MCP server on HTTP
shakka --mcp --transport sse    # Server-sent events transport
```

**Acceptance Criteria:**
- [ ] Works with Claude Desktop
- [ ] Works with VS Code + Continue/Copilot
- [ ] Works with Cursor IDE
- [ ] Proper error handling per MCP spec
- [ ] Authentication support (optional)

---

#### 4.1.3 Command Safety Layer
**Description:** Validate and confirm dangerous commands before execution.

**Dangerous Command Patterns:**
- Destructive: `rm -rf`, `mkfs`, `dd if=`
- Privilege escalation: `sudo`, `chmod 777`, `chown root`
- Network exfil: `curl | bash`, `wget -O- | sh`
- Credential exposure: Commands outputting passwords/keys

**Interface:**
```
> shakka "delete all logs on the system"

⚠️  DANGEROUS COMMAND DETECTED

Generated command:
  sudo rm -rf /var/log/*

Risks identified:
  • Irreversible file deletion
  • Requires root privileges
  • Affects system logging

[E]xecute  [M]odify  [C]ancel  [?] Help
```

**Configuration:**
```yaml
safety:
  confirm_dangerous: true      # Always confirm dangerous commands
  block_destructive: false     # Block vs confirm destructive commands
  allowed_targets: []          # Whitelist of IPs/domains
  blocked_commands: [rm -rf /] # Absolute blocklist
```

**Acceptance Criteria:**
- [ ] All destructive commands require confirmation
- [ ] Clear explanation of risks
- [ ] Modification option to adjust command
- [ ] Audit log of all executed commands
- [ ] `--yolo` flag to skip confirmation (with warning)

---

#### 4.1.4 Persistent Vector Memory
**Description:** Store and retrieve attack knowledge using vector embeddings.

**Memory Types:**
1. **Session Memory:** Current engagement context
2. **Target Memory:** Per-target findings and successful approaches
3. **Technique Memory:** General attack patterns that worked
4. **Failure Memory:** Approaches to avoid

**Interface:**
```bash
# Explicit memory operations
shakka remember "SQLi on port 8080 worked with --dbs flag"
shakka recall "What worked on this target?"
shakka forget --target 192.168.1.1

# Automatic memory (enabled by default)
shakka "scan 192.168.1.1"  # Automatically recalls previous findings
```

**Storage:**
```
~/.shakkashell/
├── memory/
│   ├── chroma.db           # Vector store
│   ├── targets/            # Per-target JSON
│   └── techniques.json     # Global technique library
```

**Implementation:**
- ChromaDB for local vector storage (zero external deps)
- OpenAI/Ollama embeddings (configurable)
- Semantic search with similarity threshold
- Automatic cleanup of old memories

**Acceptance Criteria:**
- [ ] Memories persist across sessions
- [ ] Recall accuracy >80% for relevant queries
- [ ] Memory size limit with LRU eviction
- [ ] Export/import memory for team sharing
- [ ] Privacy mode (no persistent storage)

---

### 4.2 Agent Features (P1 - High Priority)

#### 4.2.1 Multi-Agent Orchestration
**Description:** Hierarchical agent system for complex, multi-step tasks.

**Agent Roles:**

| Agent | Responsibility | Model Recommendation |
|-------|---------------|---------------------|
| Orchestrator | Task planning, agent coordination | Claude Opus / GPT-4 |
| Recon Agent | Enumeration, OSINT, service detection | Claude Sonnet / GPT-4o |
| Exploit Agent | Vulnerability analysis, exploit selection | Claude Sonnet / o1 |
| Persistence Agent | Post-exploitation, maintaining access | Claude Haiku / GPT-4o-mini |
| Reporter Agent | Findings documentation, report generation | Claude Sonnet / GPT-4o |

**Interface:**
```bash
# Single complex task triggers multi-agent workflow
shakka --agent "Compromise the AD controller starting from external web server"

# Agent mode with visibility
shakka --agent --verbose "Full assessment of target.com"

[Orchestrator] Planning attack chain...
[Recon Agent] Scanning target.com:80,443...
[Recon Agent] Found: Apache 2.4.41, PHP 7.4, WordPress 5.8
[Exploit Agent] Analyzing WordPress plugins...
[Exploit Agent] CVE-2021-34527 applicable, generating payload...
```

**Architecture:**
```
                    ┌─────────────────┐
                    │   Orchestrator  │
                    │   (Planning)    │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
    │  Recon  │        │ Exploit │        │ Report  │
    │  Agent  │        │  Agent  │        │  Agent  │
    └────┬────┘        └────┬────┘        └────┬────┘
         │                   │                   │
    ┌────▼────────────────────────────────────────┐
    │              Shared Memory Store             │
    └──────────────────────────────────────────────┘
```

**Acceptance Criteria:**
- [ ] Agents can execute independently
- [ ] Orchestrator handles failures gracefully
- [ ] Shared memory between agents
- [ ] Configurable agent models
- [ ] Interrupt and resume capability

---

#### 4.2.2 CVE-to-Exploit Pipeline
**Description:** Automated lookup and synthesis of exploits from CVE identifiers.

**Data Sources:**
1. NIST NVD (vulnerability details)
2. Exploit-DB (existing exploits)
3. GitHub (PoC repositories)
4. Nuclei Templates (scanning templates)
5. LLM Synthesis (when no existing exploit found)

**Interface:**
```bash
shakka exploit CVE-2024-1234

╔══════════════════════════════════════════════════╗
║  CVE-2024-1234 - Apache Path Traversal           ║
╠══════════════════════════════════════════════════╣
║  CVSS: 9.8 (Critical)                            ║
║  Affected: Apache HTTP Server 2.4.49-2.4.50      ║
║  Type: Path Traversal → RCE                      ║
╠══════════════════════════════════════════════════╣
║  Existing Exploits Found: 3                      ║
║  [1] exploit-db/50383 (verified)                 ║
║  [2] github/blasty/CVE-2024-1234                 ║
║  [3] nuclei/http/cves/2024/CVE-2024-1234.yaml    ║
╠══════════════════════════════════════════════════╣
║  Actions:                                        ║
║  [D]ownload  [T]est  [G]enerate custom  [S]can   ║
╚══════════════════════════════════════════════════╝
```

**Synthesis Mode:**
When no existing exploit found, use LLM to:
1. Parse CVE description and references
2. Analyze vulnerable code (if available)
3. Generate exploit skeleton
4. Suggest testing approach

**Acceptance Criteria:**
- [ ] NVD lookup works for any CVE
- [ ] Exploit-DB integration functional
- [ ] GitHub PoC search functional
- [ ] LLM synthesis produces testable code
- [ ] Safety checks before exploit execution

---

#### 4.2.3 Chain-of-Thought Attack Planning
**Description:** Expose the AI's reasoning process for complex attack planning.

**Interface:**
```bash
shakka plan "Get domain admin from external foothold"

┌─────────────────────────────────────────────────────────────┐
│ ATTACK PLAN: External to Domain Admin                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ THINKING:                                                   │
│ ─────────                                                   │
│ Starting from external foothold, I need to:                 │
│                                                             │
│ 1. INITIAL ACCESS                                           │
│    • Current position: External web server (10.0.0.5)       │
│    • Need: Internal network access                          │
│    → Check for SSRF, command injection, or file upload      │
│    → If web shell possible, pivot to internal scanning      │
│                                                             │
│ 2. INTERNAL RECONNAISSANCE                                  │
│    • Goal: Find AD infrastructure                           │
│    → Scan for 88/tcp (Kerberos), 389/tcp (LDAP)            │
│    → Identify domain controllers                            │
│    → Enumerate users via RPC or LDAP                        │
│                                                             │
│ 3. CREDENTIAL HARVESTING                                    │
│    • Options ranked by stealth:                             │
│    → Kerberoasting (low noise, no admin needed)            │
│    → AS-REP roasting (if accounts vulnerable)              │
│    → NTLM relay (requires positioning)                     │
│                                                             │
│ 4. PRIVILEGE ESCALATION                                     │
│    • With service account or user creds:                    │
│    → Check for delegation issues                           │
│    → Look for GPP passwords                                │
│    → Attempt DCSync if replication rights found            │
│                                                             │
│ RECOMMENDED FIRST STEP:                                     │
│ shakka "SSRF scan on web application at 10.0.0.5"          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Acceptance Criteria:**
- [ ] Works with reasoning models (o1, DeepSeek-R1, Claude thinking)
- [ ] Clear step-by-step breakdown
- [ ] Actionable next steps
- [ ] Alternative paths suggested
- [ ] Risk assessment per step

---

### 4.3 Advanced Features (P2 - Nice to Have)

#### 4.3.1 Tool-Aware Command Generation
**Description:** Detect installed tools and generate commands using available software.

**Implementation:**
```bash
# On startup, scan for available tools
shakka --detect-tools

Detected Tools:
  ✓ nmap (7.94)
  ✓ gobuster (3.6)
  ✓ sqlmap (1.8)
  ✓ ffuf (2.1)
  ✗ nuclei (not found)
  ✗ metasploit (not found)

# Commands will only use detected tools
shakka "scan for vulnerabilities"
# → Uses nmap scripts instead of nuclei
```

**Acceptance Criteria:**
- [ ] Automatic tool detection on startup
- [ ] Fallback alternatives when tool missing
- [ ] Suggest tool installation when beneficial
- [ ] Custom tool registration

---

#### 4.3.2 Anti-Honeypot Detection
**Description:** Heuristics to detect and avoid security traps.

**Detection Patterns:**
1. **Suspiciously Easy Credentials:** Password in obvious location with high-value name
2. **Unicode Manipulation:** U+0008 (backspace) hiding content from LLM
3. **Planted Evidence:** "All CVEs patched" messages in logs
4. **Canary Files:** Files with names like `passwords.txt` in unexpected locations
5. **Timing Anomalies:** Services responding too fast or with unusual patterns

**Interface:**
```bash
shakka --paranoid "enumerate 10.0.0.0/24"

⚠️  POTENTIAL HONEYPOT INDICATORS DETECTED

[!] 10.0.0.15 - SSH banner contains unusual delay pattern
[!] 10.0.0.22 - credentials.txt found in web root (likely canary)
[!] 10.0.0.30 - "Admin password: hunter2" in robots.txt (too easy)

Recommended: Skip flagged hosts or proceed with caution
```

**Acceptance Criteria:**
- [ ] Detects common honeypot patterns
- [ ] Configurable sensitivity
- [ ] Doesn't block, just warns
- [ ] Logs suspected honeypots

---

#### 4.3.3 Report Generation
**Description:** Automated generation of professional penetration testing reports.

**Output Formats:**
- Markdown (default)
- HTML (styled)
- DOCX (Word)
- PDF

**Interface:**
```bash
shakka report --format docx --output report.docx

# Generates report from session memory including:
# - Executive summary
# - Methodology
# - Findings (critical → info)
# - Evidence (screenshots, command outputs)
# - Remediation recommendations
```

**Acceptance Criteria:**
- [ ] Professional formatting
- [ ] CVSS scoring for findings
- [ ] Evidence auto-attachment
- [ ] Customizable template
- [ ] Executive summary generation

---

## 5. Technical Architecture

### 5.1 System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ShakkaShell 2.0                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐       │
│  │   CLI/TUI     │    │  MCP Server   │    │   Python API  │       │
│  │  Interface    │    │  (JSON-RPC)   │    │   (Library)   │       │
│  └───────┬───────┘    └───────┬───────┘    └───────┬───────┘       │
│          │                    │                    │               │
│          └────────────────────┼────────────────────┘               │
│                               │                                     │
│                    ┌──────────▼──────────┐                         │
│                    │   Core Controller   │                         │
│                    │   (Orchestration)   │                         │
│                    └──────────┬──────────┘                         │
│                               │                                     │
│      ┌────────────────────────┼────────────────────────┐           │
│      │                        │                        │           │
│  ┌───▼───┐              ┌────▼────┐              ┌────▼────┐      │
│  │ Safety │              │  Agent  │              │ Memory  │      │
│  │ Layer  │              │ System  │              │ Store   │      │
│  └───┬───┘              └────┬────┘              └────┬────┘      │
│      │                        │                        │           │
│      │    ┌───────────────────┼───────────────────┐   │           │
│      │    │                   │                   │   │           │
│      │ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐   │           │
│      │ │Recon│ │Exploi│ │Persi│ │Repor│ │Custo│   │           │
│      │ │Agent│ │Agent │ │Agent│ │Agent│ │Agent│   │           │
│      │ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘   │           │
│      │    └───────┴───────┴───────┴───────┘       │           │
│      │                    │                        │           │
│  ┌───▼────────────────────▼────────────────────────▼───┐       │
│  │                   LLM Router                         │       │
│  │  (OpenAI / Anthropic / Ollama / OpenRouter / etc)   │       │
│  └───┬─────────────────────────────────────────────────┘       │
│      │                                                          │
│  ┌───▼────────────────────────────────────────────────┐        │
│  │              Tool Execution Layer                   │        │
│  │  (Subprocess / Docker / SSH / Local)               │        │
│  └─────────────────────────────────────────────────────┘        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2 Data Flow

```
User Input
    │
    ▼
┌──────────────┐
│ Parse Intent │ ──→ Is it a question? ──→ Answer from memory/LLM
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Recall Memory│ ──→ Similar past actions found? ──→ Suggest reuse
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Route to     │
│ Agent(s)     │ ──→ Simple task? ──→ Direct LLM generation
└──────┬───────┘     Complex task? ──→ Multi-agent orchestration
       │
       ▼
┌──────────────┐
│ Generate     │
│ Command(s)   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Safety Check │ ──→ Dangerous? ──→ Confirm with user
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Execute      │ ──→ Capture output
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Store Memory │ ──→ Save findings to vector store
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Present      │ ──→ Display results to user
│ Results      │
└──────────────┘
```

### 5.3 Directory Structure

```
shakkashell/
├── pyproject.toml              # Package configuration
├── README.md
├── LICENSE
│
├── src/
│   └── shakkashell/
│       ├── __init__.py
│       ├── __main__.py         # Entry point
│       ├── cli.py              # CLI interface (Click/Typer)
│       ├── config.py           # Configuration management
│       │
│       ├── core/
│       │   ├── controller.py   # Main orchestration
│       │   ├── router.py       # LLM routing logic
│       │   └── safety.py       # Command safety checks
│       │
│       ├── agents/
│       │   ├── base.py         # Base agent class
│       │   ├── orchestrator.py # Planning agent
│       │   ├── recon.py        # Reconnaissance agent
│       │   ├── exploit.py      # Exploitation agent
│       │   ├── persist.py      # Persistence agent
│       │   └── reporter.py     # Reporting agent
│       │
│       ├── memory/
│       │   ├── store.py        # Vector store interface
│       │   ├── embeddings.py   # Embedding generation
│       │   └── retrieval.py    # Semantic search
│       │
│       ├── tools/
│       │   ├── detector.py     # Tool detection
│       │   ├── executor.py     # Command execution
│       │   └── parsers/        # Output parsers (nmap, etc)
│       │
│       ├── integrations/
│       │   ├── cve.py          # CVE/NVD integration
│       │   ├── exploitdb.py    # Exploit-DB integration
│       │   └── nuclei.py       # Nuclei template integration
│       │
│       ├── mcp/
│       │   ├── server.py       # MCP server implementation
│       │   ├── tools.py        # MCP tool definitions
│       │   └── transport.py    # stdio/HTTP/SSE transports
│       │
│       └── llm/
│           ├── providers/
│           │   ├── openai.py
│           │   ├── anthropic.py
│           │   ├── ollama.py
│           │   └── openrouter.py
│           └── prompts/
│               ├── system.py
│               ├── recon.py
│               └── exploit.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
└── examples/
    ├── basic_usage.py
    ├── mcp_client.py
    └── custom_agent.py
```

---

## 6. Implementation Phases

### Phase 1: Foundation (Week 1-2)
**Goal:** Core infrastructure and basic functionality

| Task | Priority | Effort | Dependencies |
|------|----------|--------|--------------|
| Project scaffolding (pyproject.toml, structure) | P0 | 2h | None |
| Configuration system (YAML + env vars) | P0 | 4h | None |
| LLM router with OpenAI support | P0 | 4h | Config |
| Basic CLI with Click/Typer | P0 | 4h | Router |
| Single-shot command generation | P0 | 4h | CLI, Router |
| Safety check layer | P0 | 6h | Command gen |
| Add Anthropic provider | P0 | 2h | Router |
| Add Ollama provider | P0 | 2h | Router |
| Unit tests for core | P1 | 4h | All above |

**Deliverable:** `pip install` works, basic `shakka "scan target"` functional

### Phase 2: Memory & MCP (Week 3-4)
**Goal:** Persistent memory and ecosystem integration

| Task | Priority | Effort | Dependencies |
|------|----------|--------|--------------|
| ChromaDB integration | P0 | 4h | None |
| Embedding generation (OpenAI/Ollama) | P0 | 4h | ChromaDB |
| Memory store/recall interface | P0 | 6h | Embeddings |
| Automatic memory on command execution | P1 | 4h | Memory store |
| MCP server (stdio transport) | P0 | 8h | Core |
| MCP tools definition | P0 | 4h | MCP server |
| MCP HTTP transport | P1 | 4h | MCP server |
| Test with Claude Desktop | P0 | 2h | MCP server |

**Deliverable:** Memory persists, works as MCP server

### Phase 3: Agents (Week 5-6)
**Goal:** Multi-agent orchestration

| Task | Priority | Effort | Dependencies |
|------|----------|--------|--------------|
| Base agent class | P0 | 4h | Core |
| Orchestrator agent | P0 | 8h | Base agent |
| Recon agent | P0 | 6h | Base agent |
| Exploit agent | P1 | 6h | Base agent |
| Reporter agent | P1 | 6h | Base agent |
| Agent coordination system | P0 | 8h | All agents |
| Shared memory between agents | P0 | 4h | Memory, Agents |
| `--agent` CLI flag | P0 | 2h | Coordination |

**Deliverable:** `shakka --agent "complex task"` works

### Phase 4: CVE & Polish (Week 7-8)
**Goal:** CVE pipeline and production readiness

| Task | Priority | Effort | Dependencies |
|------|----------|--------|--------------|
| NVD API integration | P0 | 4h | None |
| Exploit-DB scraper | P1 | 4h | None |
| GitHub PoC search | P1 | 4h | None |
| LLM exploit synthesis | P2 | 8h | CVE lookup |
| `shakka exploit CVE-XXXX` command | P0 | 4h | Integrations |
| Tool detection system | P1 | 4h | None |
| Anti-honeypot heuristics | P2 | 6h | None |
| Report generation | P2 | 8h | Memory |
| Documentation | P0 | 8h | All |
| PyPI publishing | P0 | 2h | All |

**Deliverable:** Full v2.0 release

---

## 7. Dependencies & Stack

### Core Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| `click` or `typer` | CLI framework | Latest |
| `rich` | Terminal formatting | Latest |
| `pydantic` | Configuration/validation | 2.x |
| `httpx` | HTTP client | Latest |
| `chromadb` | Vector storage | Latest |
| `openai` | OpenAI API | Latest |
| `anthropic` | Anthropic API | Latest |

### Optional Dependencies

| Package | Purpose | When Needed |
|---------|---------|-------------|
| `ollama` | Local LLM | Ollama provider |
| `mcp` | MCP protocol | MCP server mode |
| `python-docx` | Report generation | DOCX reports |
| `weasyprint` | PDF generation | PDF reports |

### Development Dependencies

| Package | Purpose |
|---------|---------|
| `pytest` | Testing |
| `pytest-asyncio` | Async tests |
| `ruff` | Linting |
| `mypy` | Type checking |
| `pre-commit` | Git hooks |

---

## 8. Risks & Mitigations

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| LLM generates dangerous commands | High | High | Safety layer with confirmation, blocklist |
| Multi-agent loops infinitely | Medium | Medium | Iteration limits, timeout, human interrupt |
| Memory grows unbounded | Medium | Low | Size limits, LRU eviction, cleanup command |
| MCP spec changes | Low | Medium | Abstract transport layer, follow spec updates |
| Embedding dimension mismatch | Low | High | Lock embedding model per memory store |

### Business/Adoption Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Competitors ship similar tool | High | Medium | Focus on UX and community |
| API costs too high for users | Medium | Medium | Ollama support, cost tracking |
| Security researchers distrust AI | Medium | High | Transparency, explain mode, local-first option |

### Legal/Ethical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Used for malicious purposes | High | High | Clear terms of use, target whitelisting option |
| Generates working malware | Medium | High | Output filtering, no persistence by default |
| Liability for generated exploits | Low | High | Disclaimer, research-only framing |

---

## 9. Appendix: Research References

### Key Papers

1. **PentestAgent** (ACM ASIA CCS '25)
   - Multi-agent framework for automated pentesting
   - 228.6% improvement in task completion
   - Source: https://dl.acm.org/doi/10.1145/3708821.3733882

2. **CMU Autonomous Attack Research** (2025)
   - LLMs autonomously replicated Equifax breach
   - Hierarchical agent system with abstractions
   - Source: Carnegie Mellon Engineering

3. **USENIX Security: Defending Against AI Attackers** (2025)
   - Honeypot techniques that exploit LLM weaknesses
   - Unicode tricks, planted evidence, hallucination traps
   - Source: USENIX Security '25

4. **Forewarned is Forearmed** (arXiv 2505.12786)
   - Survey of LLM-based autonomous cyberattack agents
   - Capability uplift, throughput uplift, autonomous risk
   - Source: https://arxiv.org/abs/2505.12786

5. **MCP Specification** (November 2025)
   - Model Context Protocol standard
   - Adopted by OpenAI, Anthropic, Google
   - Source: https://modelcontextprotocol.io

### Tools Analyzed

- **PentAGI** (https://github.com/vxcontrol/pentagi) - Full autonomous pentesting system
- **AutoPentester** - LLM agent framework for pentesting
- **HackSynth** - LLM agent evaluation framework
- **Hexstrike-AI** - Multi-agent exploit orchestration

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | Feb 2026 | Assune | Initial PRD |

---

*End of Document*
