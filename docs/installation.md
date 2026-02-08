# Installation Guide

## Prerequisites

- **Python 3.11+** (3.12 recommended)
- **pip** or **Poetry** for package management

## Install from Source

### Using Poetry (Recommended)

```bash
# Clone repository
git clone https://github.com/kingassune/ShakkaShell-.git
cd ShakkaShell-

# Install with Poetry
poetry install

# Activate virtual environment
poetry shell

# Verify installation
shakka --version
```

### Using pip

```bash
# Clone repository
git clone https://github.com/kingassune/ShakkaShell-.git
cd ShakkaShell-

# Install in development mode
pip install -e .

# Verify installation
shakka --version
```

## Optional Dependencies

Install optional features as needed:

```bash
# Vector memory (ChromaDB)
pip install chromadb

# Report generation
pip install python-docx weasyprint

# MCP server
pip install mcp
```

## Verify Installation

```bash
# Check version
shakka --version

# Validate providers
shakka validate

# Test command generation (requires API key)
shakka generate "test"
```

## Environment Setup

Configure at least one LLM provider:

```bash
# Option 1: OpenRouter (Recommended - 200+ models, single API)
export OPENROUTER_API_KEY="sk-or-v1-..."
export SHAKKA_DEFAULT_PROVIDER="openrouter"
export SHAKKA_OPENROUTER_MODEL="deepseek/deepseek-chat"  # Fast & cheap

# Option 2: OpenAI
export OPENAI_API_KEY="sk-..."
export SHAKKA_DEFAULT_PROVIDER="openai"

# Option 3: Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
export SHAKKA_DEFAULT_PROVIDER="anthropic"

# Option 4: Ollama (Local, no API key needed)
export SHAKKA_DEFAULT_PROVIDER="ollama"
export SHAKKA_OLLAMA_MODEL="llama3.3"
```

### Optional API Keys (for CVE Pipeline)

```bash
# Higher rate limits for NVD
export NVD_API_KEY="your-nvd-key"

# GitHub API for PoC search
export GITHUB_TOKEN="ghp_..."
```

## Quick Test

```bash
# Test command generation
shakka generate "list open ports"

# Test CVE lookup (real NVD API)
shakka exploit CVE-2021-44228

# Run agent mode
shakka agent "Scan localhost for vulnerabilities"
```

## Next Steps

- [Configure API keys](configuration.md)
- [CLI Reference](cli.md)
