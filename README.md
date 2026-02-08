# ShakkaShell v2.0

> **State-of-the-art autonomous offensive security platform**

ShakkaShell 2.0 transforms natural language into executable security commands using AI. Featuring multi-agent orchestration, real CVE-to-exploit pipelines, MCP server integration, and persistent vector memory.

[![Tests](https://img.shields.io/badge/tests-960%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Features

### Core Capabilities
- 🤖 **Multiple LLM Providers**: OpenAI, Anthropic Claude, **OpenRouter** (200+ models), Ollama (local)
- 🔄 **Dynamic Provider Switching**: Switch providers via CLI without restart
- 🎯 **Smart Command Generation**: Natural language to security commands with tool-awareness
- 🛡️ **Safety Layer**: Risk classification, dangerous command detection, YOLO mode
- 📝 **History Tracking**: SQLite database with search and filtering
- 💰 **Cost Tracking**: Per-provider token and cost tracking

### v2.0 Advanced Features
- 🤝 **Multi-Agent Orchestration**: LLM-powered Recon, Exploit, Persistence, and Reporter agents
- 🔍 **Real CVE-to-Exploit Pipeline**: Live NVD API, Exploit-DB, GitHub PoC search
- 🧠 **Persistent Vector Memory**: ChromaDB-backed knowledge base with semantic search
- 🌐 **MCP Server**: JSON-RPC 2.0 over stdio/HTTP for AI tool integration
- 📊 **Report Generation**: Markdown, HTML, DOCX, PDF with CVSS scoring
- 🎯 **LLM Attack Planning**: Dynamic plan generation with MITRE ATT&CK mapping
- 🔧 **Tool Detection**: Auto-detect installed tools with fallback alternatives
- 🍯 **Anti-Honeypot**: Detect security traps with configurable sensitivity

---

## Quick Start

### Installation

\`\`\`bash
# Prerequisites: Python 3.11+

# Clone and install
git clone https://github.com/kingassune/ShakkaShell-.git
cd ShakkaShell-
pip install -e .

# Or with Poetry
poetry install
\`\`\`

### Configuration

\`\`\`bash
# Set API keys (choose your provider)
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENROUTER_API_KEY="sk-or-v1-..."  # Access 200+ models

# Set default provider
export SHAKKA_DEFAULT_PROVIDER="openrouter"  # openai, anthropic, ollama, openrouter
\`\`\`

---

## Usage Examples

### Basic Command Generation

\`\`\`bash
# Generate security commands
shakka generate "scan ports on 10.0.0.1"
shakka generate "enumerate directories on https://target.com"

# Use different providers
shakka generate "find SQL injection" --provider anthropic
shakka generate "reverse shell" --provider openrouter
shakka generate "local privesc" --provider ollama
\`\`\`

### Agent Mode (LLM-Powered Multi-Agent)

\`\`\`bash
# Run autonomous multi-agent assessment
shakka agent "Full recon and initial access assessment on target.com"

# Verbose mode shows agent reasoning
shakka agent --verbose "Compromise the AD controller from external foothold"

# Agents use LLM for intelligent analysis
shakka agent "Analyze web app vulnerabilities on 192.168.1.100"
\`\`\`

### CVE Exploit Lookup (Real APIs)

\`\`\`bash
# Search for exploits by CVE - queries live NVD, Exploit-DB, GitHub
shakka exploit CVE-2021-44228   # Returns real CVSS 10.0, 103+ references
shakka exploit CVE-2024-1234 --source exploit_db
shakka exploit CVE-2023-44487 --source github
shakka exploit CVE-2020-1472 --code --limit 5
shakka exploit CVE-2024-1234 --no-llm  # Disable LLM synthesis
\`\`\`

### MCP Server Mode

\`\`\`bash
# Start as MCP server for AI tool integration
shakka --mcp                    # stdio transport (Claude Desktop)
shakka --mcp --port 3000        # HTTP transport
\`\`\`

### History & Configuration

\`\`\`bash
shakka history                  # View command history
shakka history --limit 20       # Last 20 commands
shakka config --show            # Show configuration
shakka validate                 # Validate providers
\`\`\`

---

## Real API Integrations

### NVD (National Vulnerability Database)
Live integration with NVD API 2.0 for CVE details:
\`\`\`python
from shakka.exploit import CVELookup

lookup = CVELookup()
cve = await lookup.get("CVE-2021-44228")
print(f"{cve.cve_id}: CVSS {cve.cvss.score} ({cve.cvss.severity.value})")
# Output: CVE-2021-44228: CVSS 10.0 (critical)
\`\`\`

### GitHub PoC Search
Real GitHub API search for proof-of-concept repositories:
\`\`\`python
from shakka.exploit import GitHubSearch

search = GitHubSearch()
repos = await search.search_by_cve("CVE-2021-44228", min_stars=100)
# Returns: fullhunt/log4j-scan (3438★), kozmer/log4j-shell-poc (1849★), ...
\`\`\`

### Exploit-DB Search
Dual approach: searchsploit CLI (if available) + web API fallback:
\`\`\`python
from shakka.exploit import ExploitDBSearch

search = ExploitDBSearch()
exploits = await search.search_by_keyword("log4j")
code = await search.get_exploit_code("50590")  # Download exploit code
\`\`\`

---

## LLM-Powered Components

### Attack Planning
The planner uses LLM to generate dynamic attack strategies:
\`\`\`python
from shakka.planning import AttackPlanner, PlannerConfig

planner = AttackPlanner(config=PlannerConfig(use_llm=True))
plan = await planner.plan("Enumerate web app vulnerabilities", context={"target": "192.168.1.100"})
# Returns structured plan with phases, actions, and MITRE mappings
\`\`\`

### Intelligent Agents
All agents use LLM for context-aware analysis:
\`\`\`python
from shakka.agents.roles import ReconAgent
from shakka.config import ShakkaConfig

config = ShakkaConfig(default_provider="openrouter")
agent = ReconAgent(shakka_config=config)
result = await agent.execute("Analyze web application at 192.168.1.100")
# Returns structured findings: ports, services, vulnerabilities
\`\`\`

---

## Provider Configuration

### OpenRouter (Recommended for Cost Efficiency)
Access 200+ models through a single API:
\`\`\`bash
export OPENROUTER_API_KEY="sk-or-v1-..."
export SHAKKA_DEFAULT_PROVIDER="openrouter"
export SHAKKA_OPENROUTER_MODEL="deepseek/deepseek-chat"  # Fast & cheap
# Or: "openai/gpt-4o", "anthropic/claude-3.5-sonnet", "meta-llama/llama-3.3-70b"
\`\`\`

### Local with Ollama
Run completely offline:
\`\`\`bash
# Start Ollama server
ollama serve
ollama pull llama3.3

# Configure ShakkaShell
export SHAKKA_DEFAULT_PROVIDER="ollama"
export SHAKKA_OLLAMA_MODEL="llama3.3"
\`\`\`

### Provider Fallback
Automatic fallback when primary provider fails:
\`\`\`yaml
# ~/.config/shakka/config.yaml
default_provider: openrouter
fallback_providers:
  - anthropic
  - openai
  - ollama
enable_fallback: true
\`\`\`

---

## Documentation

See [docs/](docs/README.md) for detailed documentation:

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Setup and installation |
| [Configuration](docs/configuration.md) | API keys, providers, settings |
| [CLI Reference](docs/cli.md) | Command line interface |
| [Multi-Agent System](docs/agents.md) | LLM-powered agent orchestration |
| [MCP Server](docs/mcp.md) | AI tool integration protocol |
| [CVE Pipeline](docs/exploit.md) | Real NVD, Exploit-DB, GitHub APIs |
| [Safety Layer](docs/safety.md) | Command validation and risks |
| [Vector Memory](docs/memory.md) | Persistent knowledge base |
| [Report Generation](docs/reports.md) | Markdown, HTML, PDF reports |
| [Tool Detection](docs/tools.md) | Installed tool awareness |
| [Anti-Honeypot](docs/honeypot.md) | Trap detection |

---

## Architecture

\`\`\`
shakka/
├── __init__.py           # Package info
├── __main__.py           # Entry point
├── cli.py                # Typer CLI interface
├── config.py             # Configuration management
├── core/                 # Core command generation
│   ├── generator.py      # Command generation orchestration
│   ├── validator.py      # Command validation & safety
│   ├── executor.py       # Optional command execution
│   ├── safety.py         # Safety checks & risk classification
│   └── cost_tracker.py   # Token & cost tracking
├── providers/            # LLM providers
│   ├── base.py           # Abstract LLM provider
│   ├── openai.py         # OpenAI/GPT implementation
│   ├── anthropic.py      # Claude implementation
│   ├── ollama.py         # Local Ollama implementation
│   └── openrouter.py     # OpenRouter (200+ models)
├── agents/               # Multi-agent system (LLM-powered)
│   ├── base.py           # Base agent class with LLM integration
│   ├── orchestrator.py   # Task planning & coordination
│   ├── roles.py          # Specialized agents (Recon, Exploit, etc.)
│   └── message.py        # Agent communication
├── mcp/                  # MCP server
│   ├── server.py         # JSON-RPC 2.0 server
│   ├── tools.py          # MCP tool definitions
│   └── transport.py      # stdio/HTTP transports
├── exploit/              # CVE pipeline (Real APIs)
│   ├── cve.py            # NVD API 2.0 integration
│   ├── exploitdb.py      # Exploit-DB (searchsploit + web)
│   ├── github.py         # GitHub PoC search API
│   └── pipeline.py       # Pipeline orchestrator
├── planning/             # Attack planning (LLM-powered)
│   ├── planner.py        # Dynamic LLM plan generation
│   └── models.py         # Plan data structures
├── storage/              # Data persistence
│   ├── models.py         # SQLAlchemy models
│   ├── database.py       # Database connection
│   ├── history.py        # History CRUD operations
│   └── memory.py         # Vector memory store
├── reports/              # Report generation
├── honeypot/             # Anti-honeypot detection
├── tools/                # Tool detection & fallback
└── utils/                # Utilities
    └── display.py        # Rich console helpers
\`\`\`

---

## Development

\`\`\`bash
# Run all tests (960 tests)
pytest

# Run with coverage
pytest --cov=shakka --cov-report=term-missing

# Run specific test file
pytest tests/test_cli.py -v

# Validate installation
shakka validate
\`\`\`

### Test Results
\`\`\`
======================= 960 passed, 1 warning in 25.15s ========================
\`\`\`

---

## Security Considerations

⚠️ **Important**: ShakkaShell generates offensive security commands. Always:

- ✅ Obtain proper authorization before testing
- ✅ Use only in controlled environments
- ✅ Understand commands before executing
- ✅ Follow responsible disclosure practices
- ✅ Comply with applicable laws and regulations

---

## License

MIT License - see [LICENSE](LICENSE) for details

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before running any generated commands. The authors are not responsible for misuse or damage caused by this tool.

---

**Made with ❤️ by the ShakkaShell Team**
