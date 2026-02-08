# ShakkaShell v2.0 Documentation

Welcome to ShakkaShell v2.0, a state-of-the-art autonomous offensive security platform featuring:

- **Multiple LLM Providers**: OpenAI, Anthropic, OpenRouter (200+ models), Ollama
- **Real API Integrations**: Live NVD, Exploit-DB, and GitHub APIs for CVE lookups
- **LLM-Powered Agents**: Multi-agent orchestration with intelligent analysis
- **960 tests passing** with comprehensive coverage

## Getting Started

- [Installation Guide](installation.md) - Prerequisites and setup
- [Configuration](configuration.md) - Environment variables and config files

## Core Features

- [CLI Reference](cli.md) - Command-line interface commands
- [Safety Layer](safety.md) - Dangerous command detection and confirmation

## Advanced Features

- [Multi-Agent System](agents.md) - Autonomous agent orchestration
- [MCP Server](mcp.md) - Model Context Protocol integration
- [CVE Pipeline](exploit.md) - CVE-to-exploit lookup and synthesis
- [Vector Memory](memory.md) - Persistent knowledge base
- [Report Generation](reports.md) - Multi-format report output
- [Tool Detection](tools.md) - Automatic tool discovery
- [Anti-Honeypot](honeypot.md) - Security trap detection

## Developer Resources

- [Python API](api.md) - Programmatic usage

## Quick Example

```bash
# Configure provider (OpenRouter recommended)
export OPENROUTER_API_KEY="sk-or-v1-..."
export SHAKKA_DEFAULT_PROVIDER="openrouter"

# Basic command generation
shakka generate "scan ports on 10.0.0.1"

# Multi-agent mode (LLM-powered)
shakka agent "Full recon on target.com"

# CVE exploit lookup (real NVD/GitHub/Exploit-DB APIs)
shakka exploit CVE-2021-44228  # Returns CVSS 10.0, PoC repos, etc.

# MCP server mode
shakka --mcp --port 3000
```

## Support

- [GitHub Issues](https://github.com/kingassune/ShakkaShell-/issues)
- [GitHub Discussions](https://github.com/kingassune/ShakkaShell-/discussions)
