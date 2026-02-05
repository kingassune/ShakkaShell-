# ShakkaShell v2.0

> Natural language to offensive security commands

ShakkaShell is a CLI tool that converts plain language requests into executable security commands using AI language models (OpenAI, Anthropic Claude, or local Ollama models).

## Features

- 🤖 **Multiple LLM Providers**: OpenAI GPT, Anthropic Claude, or local Ollama models
- 🎯 **Smart Command Generation**: Converts natural language to security commands
- 🛡️ **Risk Assessment**: Automatic risk level classification (Low/Medium/High/Critical)
- ✅ **Command Validation**: Syntax and safety checks
- 📝 **History Tracking**: SQLite database for command history
- 🎨 **Rich CLI**: Beautiful terminal interface with colors and formatting
- ⚙️ **Configurable**: Environment variables and YAML config support

## Installation

### Prerequisites

- Python 3.11+
- Poetry (recommended) or pip

### Install with Poetry

```bash
git clone https://github.com/kingassune/ShakkaShell-.git
cd ShakkaShell-
poetry install
```

### Install with pip

```bash
pip install -e .
```

## Configuration

### Environment Variables

Set your API keys:

```bash
# For OpenAI (GPT-3.5/GPT-4)
export OPENAI_API_KEY="sk-..."

# For Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional: Set default provider
export SHAKKA_DEFAULT_PROVIDER="openai"  # or "anthropic" or "ollama"
```

### Config File

ShakkaShell uses a config file at:
- Linux/macOS: `~/.config/shakka/config.yaml`
- Windows: `%APPDATA%/shakka/config.yaml`

Example `config.yaml`:

```yaml
default_provider: openai
debug: false
max_history: 100
auto_copy: true
confirm_execution: true
```

## Usage

### Generate Commands

```bash
# Single command generation
python -m shakka generate "scan ports on 10.0.0.1"

# With specific provider
python -m shakka generate "find subdomains for example.com" --provider anthropic

# Interactive mode
python -m shakka generate --interactive
```

### Example Outputs

```bash
$ python -m shakka generate "scan ports on 10.0.0.1"
```

Output:
```
╭─ ShakkaShell ──────────────────────────────────╮
│ Command:                                       │
│ nmap -sV -sC 10.0.0.1                         │
├────────────────────────────────────────────────┤
│ Risk: Medium                                   │
│ Requires: nmap                                 │
│                                                │
│ Performs service version detection and runs   │
│ default NSE scripts on target host.           │
╰────────────────────────────────────────────────╯
```

### View History

```bash
# Show recent commands
python -m shakka history

# Show last 20 commands
python -m shakka history --limit 20

# Clear history
python -m shakka history --clear
```

### Manage Configuration

```bash
# Show current configuration
python -m shakka config --show

# Set default provider
python -m shakka config --set-provider anthropic
```

### Validate Providers

```bash
# Validate all configured providers
python -m shakka validate

# Validate specific provider
python -m shakka validate --provider openai
```

## Supported Commands

ShakkaShell can generate commands for various offensive security tasks:

- **Port Scanning**: nmap, masscan
- **Web Enumeration**: gobuster, ffuf, dirb, nikto
- **Vulnerability Assessment**: sqlmap, nikto
- **Password Cracking**: hydra, john, hashcat
- **Network Analysis**: tcpdump, wireshark
- **And many more...**

## Example Prompts

```bash
# Network scanning
"scan ports on 192.168.1.0/24"
"find live hosts in 10.0.0.0/8"

# Web application testing
"enumerate directories on https://example.com"
"test SQL injection on login form at http://target.com/login"
"find subdomains for example.com"

# Password attacks
"brute force SSH on 10.0.0.5 with rockyou wordlist"
"crack MD5 hash with john the ripper"

# Reconnaissance
"perform DNS enumeration on example.com"
"scan for SMB vulnerabilities on 192.168.1.10"
```

## Risk Levels

ShakkaShell classifies commands by risk level:

- **Low**: Passive reconnaissance, safe information gathering
- **Medium**: Active scanning, may trigger detection systems
- **High**: Exploitation attempts, potentially harmful
- **Critical**: Destructive operations, system modifications

## Safety Features

- ✅ Risk level warnings for all commands
- ✅ Prerequisite tool checks
- ✅ Command syntax validation
- ✅ Alternative command suggestions
- ✅ Confirmation prompts (configurable)
- ✅ Dry-run mode for testing

## Development

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=shakka --cov-report=term-missing

# Run specific test file
pytest tests/test_cli.py -v
```

### Code Style

```bash
# Format with ruff
ruff check shakka/

# Type checking (if using mypy)
mypy shakka/
```

## Architecture

```
shakka/
├── __init__.py           # Package info
├── __main__.py           # Entry point
├── cli.py                # Typer CLI interface
├── config.py             # Configuration management
├── core/
│   ├── generator.py      # Command generation orchestration
│   ├── validator.py      # Command validation
│   └── executor.py       # Optional command execution
├── providers/
│   ├── base.py          # Abstract LLM provider
│   ├── openai.py        # OpenAI/GPT implementation
│   ├── anthropic.py     # Claude implementation
│   └── ollama.py        # Local Ollama implementation
├── storage/
│   ├── models.py        # SQLAlchemy models
│   ├── database.py      # Database connection
│   └── history.py       # History CRUD operations
└── utils/
    └── display.py       # Rich console helpers
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Security Considerations

⚠️ **Important**: ShakkaShell generates offensive security commands. Always:

- Obtain proper authorization before testing
- Use only in controlled environments
- Understand commands before executing
- Follow responsible disclosure practices
- Comply with applicable laws and regulations

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before running any generated commands. The authors are not responsible for misuse or damage caused by this tool.

## Support

- 📖 Documentation: [Project Wiki](#)
- 🐛 Bug Reports: [GitHub Issues](https://github.com/kingassune/ShakkaShell-/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/kingassune/ShakkaShell-/discussions)

## Credits

Built with:
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [Rich](https://rich.readthedocs.io/) - Terminal formatting
- [LiteLLM](https://docs.litellm.ai/) - Unified LLM interface
- [Pydantic](https://pydantic-docs.helpmanual.io/) - Data validation
- [SQLAlchemy](https://www.sqlalchemy.org/) - Database ORM

---

**Made with ❤️ by the ShakkaShell Team**
