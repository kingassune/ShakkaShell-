# ShakkaShell v2.0 Documentation

Welcome to ShakkaShell v2.0, a state-of-the-art autonomous offensive security platform.

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
# Basic command generation
shakka generate "scan ports on 10.0.0.1"

# Multi-agent mode
shakka agent "Full recon on target.com"

# CVE exploit lookup
shakka exploit CVE-2024-1234

# MCP server mode
shakka --mcp --port 3000
```

## Support

- [GitHub Issues](https://github.com/kingassune/ShakkaShell-/issues)
- [GitHub Discussions](https://github.com/kingassune/ShakkaShell-/discussions)
