# Python API

ShakkaShell can be used as a Python library for programmatic access.

## Installation

```bash
pip install shakkashell
# or
poetry add shakkashell
```

## Quick Start

```python
from shakka import ShakkaShell

# Initialize
shakka = ShakkaShell()

# Generate command
result = await shakka.generate("scan ports on 10.0.0.1")
print(result.command)  # nmap -sV -sC 10.0.0.1
print(result.risk_level)  # medium
print(result.explanation)  # Performs service detection...

# Execute command
output = await shakka.execute(result)
print(output.stdout)
```

## Core Modules

### Command Generation

```python
from shakka.core.generator import CommandGenerator
from shakka.config import Config

config = Config()
generator = CommandGenerator(config)

result = await generator.generate("enumerate directories on https://target.com")
print(result.command)
print(result.tool_required)
print(result.risk_level)
```

### Provider Management

```python
from shakka.providers import OpenAIProvider, AnthropicProvider, OllamaProvider

# Use specific provider
openai = OpenAIProvider(api_key="sk-...")
response = await openai.generate("scan ports on target")

# With fallback
from shakka.core.generator import CommandGenerator

generator = CommandGenerator(
    providers=[OpenAIProvider(), AnthropicProvider()],
    enable_fallback=True
)
```

### Safety Checking

```python
from shakka.core.safety import SafetyChecker

checker = SafetyChecker()

# Check command safety
result = checker.check("rm -rf /var/log/*")
print(result.risk_level)
print(result.categories)
print(result.is_blocked)
```

### History

```python
from shakka.storage.history import HistoryManager

history = HistoryManager()

# Get recent commands
entries = history.get_recent(limit=10)
for entry in entries:
    print(f"{entry.timestamp}: {entry.command}")

# Search history
results = history.search("nmap")
```

## Advanced Modules

### Multi-Agent Orchestration

```python
from shakka.agents import Orchestrator, ReconAgent, ExploitAgent

orchestrator = Orchestrator()
orchestrator.add_agent(ReconAgent())
orchestrator.add_agent(ExploitAgent())

result = await orchestrator.execute("Full recon on target.com")

for step in result.steps:
    print(f"[{step.agent}] {step.action}")
    print(f"  Output: {step.output}")
```

### CVE Pipeline

```python
from shakka.exploit import ExploitPipeline, ExploitSource

pipeline = ExploitPipeline()

results = await pipeline.search("CVE-2024-1234")
for result in results:
    print(f"[{result.source.value}] {result.title}")
    print(f"  URL: {result.url}")
    print(f"  Confidence: {result.confidence}")
```

### MCP Server

```python
from shakka.mcp import MCPServer
from shakka.mcp.transport import create_http_transport

server = MCPServer()
transport = create_http_transport(port=3000)

# Start server
await transport.start(server)
```

### Vector Memory

```python
from shakka.memory import MemoryStore, MemoryType

store = MemoryStore(backend="chromadb")

# Store memory
await store.remember(
    "SQLi on port 8080 worked with --dbs",
    MemoryType.TECHNIQUE,
    target="192.168.1.1"
)

# Recall
memories = await store.recall("SQL injection techniques")
```

### Report Generation

```python
from shakka.reports import ReportGenerator, Finding, Severity

findings = [
    Finding(
        title="SQL Injection",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        description="...",
        remediation="Use parameterized queries"
    )
]

generator = ReportGenerator()
report = generator.generate(
    title="Pentest Report",
    findings=findings,
    format="html"
)
report.save("report.html")
```

### Tool Detection

```python
from shakka.tools import ToolDetector, ToolRegistry

detector = ToolDetector()
available = await detector.detect_all()

for tool in available:
    print(f"{tool.name}: {tool.version}")
```

### Honeypot Detection

```python
from shakka.honeypot import HoneypotDetector, Sensitivity

detector = HoneypotDetector(sensitivity=Sensitivity.HIGH)

result = await detector.analyze_target("10.0.0.1")
if result.has_indicators:
    for indicator in result.indicators:
        print(f"⚠️ {indicator.description}")
```

## Configuration

```python
from shakka.config import Config

# Load config
config = Config()

# Access settings
print(config.default_provider)
print(config.safety.confirm_dangerous)
print(config.memory.enable)

# Modify settings
config.default_provider = "anthropic"
config.save()
```

## Async vs Sync

Most operations are async:

```python
import asyncio
from shakka import ShakkaShell

async def main():
    shakka = ShakkaShell()
    result = await shakka.generate("scan target")
    print(result.command)

asyncio.run(main())
```

Sync wrappers available:

```python
from shakka import ShakkaShell

shakka = ShakkaShell()
result = shakka.generate_sync("scan target")  # Blocking call
```

## Error Handling

```python
from shakka import ShakkaShell
from shakka.exceptions import (
    ProviderError,
    SafetyError,
    ValidationError,
    MemoryError
)

shakka = ShakkaShell()

try:
    result = await shakka.generate("dangerous command")
except SafetyError as e:
    print(f"Safety check failed: {e}")
except ProviderError as e:
    print(f"LLM provider error: {e}")
except ValidationError as e:
    print(f"Validation error: {e}")
```

## See Also

- [CLI Reference](cli.md)
- [Configuration](configuration.md)
