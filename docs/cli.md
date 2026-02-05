# CLI Reference

## Global Options

```bash
shakka [OPTIONS] COMMAND [ARGS]...

Options:
  --version          Show version
  --help             Show help message
  --mcp              Start as MCP server
  --mcp --port PORT  Start MCP HTTP server on port
  --agent            Enable multi-agent mode
```

## Commands

### generate

Generate security commands from natural language.

```bash
shakka generate [OPTIONS] PROMPT

Arguments:
  PROMPT         Natural language description of the task

Options:
  --provider, -p    LLM provider (openai, anthropic, ollama)
  --model, -m       Specific model to use
  --execute, -e     Execute the generated command
  --explain, -x     Include detailed explanation
  --dry-run         Show command without executing
  --yolo            Skip safety confirmations
  --interactive     Interactive mode for multiple prompts
```

**Examples:**

```bash
# Basic generation
shakka generate "scan ports on 10.0.0.1"

# With specific provider
shakka generate "find subdomains for example.com" --provider anthropic

# Execute immediately
shakka generate "ping localhost" --execute

# Interactive mode
shakka generate --interactive
```

### agent

Run multi-agent orchestration for complex tasks.

```bash
shakka agent [OPTIONS] TASK

Arguments:
  TASK           Complex task description

Options:
  --verbose, -v     Show agent communication details
  --max-steps       Maximum steps (default: 10)
  --timeout         Timeout in seconds (default: 300)
```

**Examples:**

```bash
# Full assessment
shakka agent "Full recon and initial access assessment on target.com"

# Verbose mode
shakka agent --verbose "Compromise the AD controller from external foothold"

# Limited steps
shakka agent --max-steps 5 "Quick scan of 192.168.1.0/24"
```

### exploit

Search for exploits by CVE identifier.

```bash
shakka exploit [OPTIONS] CVE_ID

Arguments:
  CVE_ID         CVE identifier (e.g., CVE-2024-1234)

Options:
  --source, -s      Filter by source (nvd, exploit_db, github, llm)
  --code, -c        Show exploit code with syntax highlighting
  --limit, -n       Maximum results (default: 5)
  --no-llm          Disable LLM-based synthesis
```

**Examples:**

```bash
# Basic CVE lookup
shakka exploit CVE-2024-1234

# Filter by source
shakka exploit CVE-2021-44228 --source exploit_db

# Show exploit code
shakka exploit CVE-2023-44487 --code --limit 3

# Disable AI synthesis
shakka exploit CVE-2020-1472 --no-llm
```

### history

View and manage command history.

```bash
shakka history [OPTIONS]

Options:
  --limit, -n       Number of entries to show (default: 10)
  --search, -s      Search in history
  --clear           Clear all history
  --export          Export to file
```

**Examples:**

```bash
# View recent history
shakka history

# Last 20 commands
shakka history --limit 20

# Search history
shakka history --search "nmap"

# Clear history
shakka history --clear
```

### config

Manage configuration.

```bash
shakka config [OPTIONS]

Options:
  --show            Display current configuration
  --set KEY VALUE   Set configuration value
  --reset           Reset to defaults
```

**Examples:**

```bash
# Show config
shakka config --show

# Set default provider
shakka config --set default_provider anthropic
```

### validate

Validate LLM provider configurations.

```bash
shakka validate [OPTIONS]

Options:
  --provider, -p    Validate specific provider
```

**Examples:**

```bash
# Validate all providers
shakka validate

# Validate specific provider
shakka validate --provider openai
```

## MCP Server Mode

Start ShakkaShell as an MCP (Model Context Protocol) server:

```bash
# stdio transport (for Claude Desktop, etc.)
shakka --mcp

# HTTP transport
shakka --mcp --port 3000
```

See [MCP Server](mcp.md) for details.

## Next Steps

- [Multi-Agent System](agents.md)
- [CVE Pipeline](exploit.md)
- [Safety Layer](safety.md)
