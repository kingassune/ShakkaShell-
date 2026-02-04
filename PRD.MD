# AGENTS.md — ShakkaShell v2.0

> Instructions for AI coding agents working on this project.

## Project Overview

ShakkaShell is a CLI tool that converts natural language into offensive security commands. This is a v2.0 rebuild of an existing proof-of-concept.

**Core Functionality:** User types “scan ports on 10.0.0.1” → Tool returns `nmap -sV -sC 10.0.0.1` with explanation and risk rating.

## Tech Stack (MUST USE)

|Component    |Package                |Version|
|-------------|-----------------------|-------|
|Python       |-                      |3.11+  |
|CLI Framework|typer                  |^0.9.0 |
|Rich Output  |rich                   |^13.0  |
|LLM Interface|litellm                |^1.0   |
|Config       |pydantic-settings      |^2.0   |
|Database     |sqlalchemy             |^2.0   |
|HTTP         |httpx                  |^0.25  |
|Testing      |pytest + pytest-asyncio|latest |
|Packaging    |poetry                 |-      |
|Linting      |ruff                   |latest |

## Project Structure

```
shakkashell/
├── shakka/
│   ├── __init__.py          # Version and package info
│   ├── __main__.py          # Entry: `python -m shakka`
│   ├── cli.py               # Typer app with all commands
│   ├── config.py            # Pydantic Settings for config
│   ├── core/
│   │   ├── generator.py     # LLM command generation
│   │   ├── validator.py     # Syntax + safety validation
│   │   └── executor.py      # Optional command execution
│   ├── providers/
│   │   ├── base.py          # Abstract LLMProvider class
│   │   ├── openai.py        # OpenAI implementation
│   │   ├── anthropic.py     # Claude implementation
│   │   └── ollama.py        # Local models
│   ├── storage/
│   │   ├── database.py      # SQLite connection
│   │   ├── models.py        # SQLAlchemy models
│   │   └── history.py       # History CRUD operations
│   └── utils/
│       ├── display.py       # Rich console helpers
│       └── clipboard.py     # Cross-platform clipboard
├── tests/
├── pyproject.toml
└── README.md
```

## Code Style Rules

1. **Type hints everywhere** — All functions must have full type annotations
1. **Async by default** — LLM calls and I/O should be async
1. **Pydantic models** — Use Pydantic for all data structures
1. **No print()** — Use `rich.console.Console` for all output
1. **Docstrings** — Google-style docstrings on all public functions
1. **Error handling** — Custom exceptions in `shakka/exceptions.py`

## Key Implementation Details

### 1. LLM Provider Interface

```python
# shakka/providers/base.py
from abc import ABC, abstractmethod
from pydantic import BaseModel

class CommandResult(BaseModel):
    command: str
    explanation: str
    risk_level: str  # Low | Medium | High | Critical
    prerequisites: list[str]
    alternatives: list[str]
    warnings: list[str]

class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, context: dict | None = None) -> CommandResult:
        pass
```

All providers (OpenAI, Anthropic, Ollama) must implement this interface.

### 2. CLI Structure

```python
# shakka/cli.py
import typer
from rich.console import Console

app = typer.Typer(
    name="shakka",
    help="Natural language to security commands",
    add_completion=False,
)
console = Console()

@app.command()
def main(
    query: str = typer.Argument(None, help="Your request in plain language"),
    interactive: bool = typer.Option(False, "-i", "--interactive"),
    provider: str = typer.Option(None, "--provider", "-p"),
    execute: bool = typer.Option(False, "--execute", "-x"),
):
    """Generate security commands from natural language."""
    pass

@app.command()
def history():
    """View command history."""
    pass

@app.command() 
def config():
    """Manage configuration."""
    pass
```

### 3. System Prompt (CRITICAL)

Store in `shakka/prompts/system.txt`:

```
You are ShakkaShell, an expert offensive security command generator.

TASK: Convert the user's natural language request into an executable security command.

RULES:
1. Output valid JSON only, no markdown
2. Use common tools: nmap, gobuster, ffuf, sqlmap, hydra, nikto, crackmapexec
3. Prefer safe defaults, add aggressive flags only when requested
4. Risk levels: Low (passive/safe), Medium (active scanning), High (exploitation), Critical (destructive)

OUTPUT FORMAT:
{
  "command": "the full executable command",
  "explanation": "1-2 sentence explanation",
  "risk_level": "Low|Medium|High|Critical",
  "prerequisites": ["tool1", "tool2"],
  "alternatives": ["alt command 1"],
  "warnings": ["any safety warnings"]
}
```

### 4. Config File Location

- Linux/macOS: `~/.config/shakka/config.yaml`
- Windows: `%APPDATA%/shakka/config.yaml`

Use `platformdirs` package for cross-platform paths.

### 5. Database Schema

```python
# shakka/storage/models.py
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from datetime import datetime

class Base(DeclarativeBase):
    pass

class CommandHistory(Base):
    __tablename__ = "history"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_input: Mapped[str]
    generated_command: Mapped[str]
    explanation: Mapped[str]
    risk_level: Mapped[str]
    provider: Mapped[str]
    executed: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
```

## Implementation Order

Follow this sequence:

### Phase 1: Foundation

1. `pyproject.toml` — Poetry config with all dependencies
1. `shakka/__init__.py` — Version info
1. `shakka/config.py` — Pydantic Settings class
1. `shakka/providers/base.py` — Abstract interface
1. `shakka/providers/openai.py` — First provider

### Phase 2: Core

1. `shakka/core/generator.py` — Orchestration logic
1. `shakka/cli.py` — Basic Typer app
1. `shakka/__main__.py` — Entry point
1. `shakka/utils/display.py` — Rich formatting

### Phase 3: Storage

1. `shakka/storage/models.py` — SQLAlchemy models
1. `shakka/storage/database.py` — Connection handling
1. `shakka/storage/history.py` — CRUD operations

### Phase 4: Additional Providers

1. `shakka/providers/anthropic.py`
1. `shakka/providers/ollama.py`

### Phase 5: Polish

1. `shakka/core/validator.py` — Command validation
1. `shakka/core/executor.py` — Optional execution
1. Tests for all modules
1. README with examples

## Testing Requirements

- Minimum 80% coverage
- Mock all LLM API calls in tests
- Test each provider independently
- Integration tests for CLI commands

```python
# Example test structure
# tests/test_generator.py
import pytest
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_generate_nmap_command():
    provider = MockProvider()
    result = await generator.generate("scan ports on 10.0.0.1", provider)
    assert "nmap" in result.command
    assert result.risk_level in ["Low", "Medium", "High", "Critical"]
```

## Environment Variables

```bash
# Required (one of these)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Optional
SHAKKA_DEFAULT_PROVIDER=anthropic
SHAKKA_CONFIG_PATH=/custom/path/config.yaml
SHAKKA_DEBUG=true
```

## Do NOT

- ❌ Use `print()` — use Rich console
- ❌ Use `requests` — use `httpx`
- ❌ Hardcode API keys anywhere
- ❌ Skip type hints
- ❌ Use synchronous I/O for network calls
- ❌ Generate commands without safety warnings for High/Critical risk

## Do

- ✅ Use `async/await` for all LLM calls
- ✅ Validate JSON responses from LLMs
- ✅ Handle API rate limits gracefully
- ✅ Show spinners during LLM calls with Rich
- ✅ Support `--json` flag for machine-readable output
- ✅ Include `--dry-run` flag for execution

## Example Interactions

**Input:** `shakka "find subdomains for example.com"`
**Expected Output:**

```
╭─ ShakkaShell ──────────────────────────────────────────╮
│ Command:                                               │
│ subfinder -d example.com -silent | httpx -silent      │
├────────────────────────────────────────────────────────┤
│ Risk: Low                                              │
│ Requires: subfinder, httpx                            │
│                                                        │
│ Discovers subdomains using passive sources, then      │
│ probes for live HTTP services.                        │
╰────────────────────────────────────────────────────────╯
[E]xecute  [C]opy  [M]odify  [Q]uit
```

## Questions for Human

If unclear on any requirement, ask before implementing. Key decision points:

- Windows support? (Recommend: Linux/macOS only for v1)
- Include tool installation commands? (Recommend: No, just warn if missing)
- Telemetry? (Recommend: No for v1)

-----

*Reference the full PRD.md for complete feature specifications.*