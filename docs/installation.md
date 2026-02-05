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

## Next Steps

- [Configure API keys](configuration.md)
- [CLI Reference](cli.md)
