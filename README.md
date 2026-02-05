# ShakkaShell v2.0

> State-of-the-art autonomous offensive security platform

ShakkaShell 2.0 transforms natural language to security commands using AI, featuring multi-agent orchestration, CVE-to-exploit pipelines, MCP server integration, and persistent vector memory.

## Features

### Core Capabilities
- 🤖 **Multiple LLM Providers**: OpenAI, Anthropic Claude, Ollama (local), with automatic fallback
- 🎯 **Smart Command Generation**: Natural language to security commands with tool-awareness
- 🛡️ **Safety Layer**: Risk classification, dangerous command detection, YOLO mode
- 📝 **History Tracking**: SQLite database with search and filtering
- 💰 **Cost Tracking**: Per-provider token and cost tracking

### v2.0 Advanced Features
- 🤝 **Multi-Agent Orchestration**: Recon, Exploit, Persistence, and Reporter agents
- 🔍 **CVE-to-Exploit Pipeline**: NVD, Exploit-DB, GitHub PoC, LLM synthesis
- 🧠 **Persistent Vector Memory**: ChromaDB-backed knowledge base with semantic search
- 🌐 **MCP Server**: JSON-RPC 2.0 over stdio/HTTP for AI tool integration
- 📊 **Report Generation**: Markdown, HTML, DOCX, PDF with CVSS scoring
- 🎯 **Attack Planning**: Chain-of-thought reasoning with MITRE ATT&CK mapping
- 🔧 **Tool Detection**: Auto-detect installed tools with fallback alternatives
- 🍯 **Anti-Honeypot**: Detect security traps with configurable sensitivity

## Quick Start

### Installation

```bash
# Prerequisites: Python 3.11+

# Clone and install
git clone https://github.com/kingassune/ShakkaShell-.git
cd ShakkaShell-
pip install -e .

# Or with Poetry
poetry install
```

### Configuration

```bash
# Set API keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

# Or use config file (~/.config/shakka/config.yaml)
```

## Usage Examples

### Basic Command Generation

```bash
# Generate security commands
shakka generate "scan ports on 10.0.0.1"
shakka generate "enumerate directories on https://target.com"
shakka generate "find SQL injection in login form" --provider anthropic
```

### Agent Mode (Multi-Agent Orchestration)

```bash
# Run autonomous multi-agent assessment
shakka agent "Full recon and initial access assessment on target.com"
shakka --agent "Compromise the AD controller from external foothold"
```

### CVE Exploit Lookup

```bash
# Search for exploits by CVE
shakka exploit CVE-2024-1234
shakka exploit CVE-2021-44228 --source exploit_db
shakka exploit CVE-2023-44487 --code --limit 5
shakka exploit CVE-2020-1472 --no-llm
```

### MCP Server Mode

```bash
# Start as MCP server for AI tool integration
shakka --mcp                    # stdio transport
shakka --mcp --port 3000        # HTTP transport
```

### History & Config

```bash
shakka history                  # View command history
shakka history --limit 20       # Last 20 commands
shakka config --show            # Show configuration
shakka validate                 # Validate providers
```

## Documentation

See [docs/](docs/README.md) for detailed documentation:

- [Installation Guide](docs/installation.md)
- [Configuration](docs/configuration.md)
- [CLI Reference](docs/cli.md)
- [Multi-Agent System](docs/agents.md)
- [MCP Server](docs/mcp.md)
- [CVE Pipeline](docs/exploit.md)
- [Safety Layer](docs/safety.md)
- [Vector Memory](docs/memory.md)
- [Report Generation](docs/reports.md)
- [Tool Detection](docs/tools.md)
- [Anti-Honeypot](docs/honeypot.md)
## Architecture

```
shakka/
├── __init__.py           # Package info
├── __main__.py           # Entry point
├── cli.py                # Typer CLI interface
├── config.py             # Configuration management
├── core/                 # Core command generation
│   ├── generator.py      # Command generation orchestration
│   ├── validator.py      # Command validation
│   └── executor.py       # Optional command execution
├── providers/            # LLM providers
│   ├── base.py           # Abstract LLM provider
│   ├── openai.py         # OpenAI/GPT implementation
│   ├── anthropic.py      # Claude implementation
│   └── ollama.py         # Local Ollama implementation
├── agents/               # Multi-agent system
│   ├── base.py           # Base agent class
│   ├── orchestrator.py   # Task planning & coordination
│   └── roles.py          # Specialized agents (Recon, Exploit, etc.)
├── mcp/                  # MCP server
│   ├── server.py         # JSON-RPC 2.0 server
│   ├── tools.py          # MCP tool definitions
│   └── transport.py      # stdio/HTTP transports
├── exploit/              # CVE pipeline
│   ├── cve.py            # NVD API integration
│   ├── exploitdb.py      # Exploit-DB search
│   ├── github.py         # GitHub PoC search
│   └── pipeline.py       # Pipeline orchestrator
├── storage/              # Data persistence
│   ├── models.py         # SQLAlchemy models
│   ├── database.py       # Database connection
│   └── history.py        # History CRUD operations
├── memory/               # Vector memory
├── reports/              # Report generation
├── honeypot/             # Anti-honeypot detection
├── planning/             # Attack planning
├── tools/                # Tool detection
└── utils/
    └── display.py        # Rich console helpers
```

## Development

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=shakka --cov-report=term-missing

# Run specific test file
pytest tests/test_cli.py -v
```

## Security Considerations

⚠️ **Important**: ShakkaShell generates offensive security commands. Always:

- Obtain proper authorization before testing
- Use only in controlled environments
- Understand commands before executing
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

## License

MIT License - see [LICENSE](LICENSE) for details

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before running any generated commands. The authors are not responsible for misuse or damage caused by this tool.

---

**Made with ❤️ by the ShakkaShell Team**
