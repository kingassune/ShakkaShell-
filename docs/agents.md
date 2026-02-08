# Multi-Agent System

ShakkaShell v2 features a multi-agent orchestration system for complex, multi-step security tasks.

## Overview

The agent system uses **LLM-powered analysis** for intelligent, context-aware security assessments. Each agent has a specialized prompt and uses the configured LLM provider for reasoning.

| Agent | Role | LLM Usage |
|-------|------|-----------|
| **Orchestrator** | Task planning, coordination | Generates attack plans dynamically |
| **Recon Agent** | Reconnaissance | Analyzes scan results, identifies targets |
| **Exploit Agent** | Exploitation | Suggests exploits, generates payloads |
| **Persistence Agent** | Post-exploitation | Recommends persistence mechanisms |
| **Reporter Agent** | Documentation | Summarizes findings, generates reports |

## Architecture

```
                    ┌─────────────────┐
                    │   Orchestrator  │
                    │   (Planning)    │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
    │  Recon  │        │ Exploit │        │ Report  │
    │  Agent  │        │  Agent  │        │  Agent  │
    └────┬────┘        └────┬────┘        └────┬────┘
         │                   │                   │
    ┌────▼────────────────────────────────────────┐
    │              Shared Memory Store             │
    └──────────────────────────────────────────────┘
```

## Usage

### CLI

```bash
# Run agent mode
shakka agent "Full recon and initial access assessment on target.com"

# Verbose mode (shows agent communication)
shakka agent --verbose "Compromise the AD controller from external foothold"

# With step limit
shakka agent --max-steps 5 "Quick scan of 192.168.1.0/24"
```

### Python API

```python
from shakka.agents import Orchestrator, ReconAgent, ExploitAgent
from shakka.config import ShakkaConfig

# Configure LLM provider (uses environment variables by default)
config = ShakkaConfig(default_provider="openrouter")

# Create orchestrator with LLM integration
orchestrator = Orchestrator(shakka_config=config)

# Add specialized agents (each uses LLM for analysis)
orchestrator.add_agent(ReconAgent(shakka_config=config))
orchestrator.add_agent(ExploitAgent(shakka_config=config))

# Execute task - agents use LLM for intelligent analysis
result = await orchestrator.execute(
    "Full assessment of target.com"
)

# Access results
for step in result.steps:
    print(f"{step.agent}: {step.output}")
```

### Direct Agent Usage

```python
from shakka.agents.roles import ReconAgent, ExploitAgent
from shakka.config import ShakkaConfig

# Initialize with config
config = ShakkaConfig(default_provider="anthropic")
agent = ReconAgent(shakka_config=config)

# Execute with LLM analysis
result = await agent.execute("Analyze web application at 192.168.1.100")
print(result.findings)  # LLM-generated analysis
```

## Agent Communication

Agents communicate via a message queue:

```python
from shakka.agents.message import AgentMessage, MessageQueue

# Send message between agents
message = AgentMessage(
    sender="recon",
    recipient="exploit",
    content={"target": "10.0.0.1", "ports": [80, 443]}
)
queue.send(message)
```

## Task Planning

The Orchestrator creates a structured plan:

```python
from shakka.agents.orchestrator import TaskPlan, TaskStep

plan = TaskPlan(
    goal="Compromise target",
    steps=[
        TaskStep(agent="recon", action="Port scan"),
        TaskStep(agent="recon", action="Service enumeration"),
        TaskStep(agent="exploit", action="Vulnerability analysis"),
        TaskStep(agent="exploit", action="Exploit execution"),
    ]
)
```

## Configuration

Each agent uses the configured LLM provider for intelligent analysis. You can customize models per agent:

```yaml
# config.yaml
agents:
  max_iterations: 10
  timeout: 300  # seconds
  model_overrides:
    orchestrator: claude-sonnet-4  # Best for planning
    recon: gpt-4o                  # Fast enumeration
    exploit: o1                    # Deep reasoning for exploits

# LLM Provider (used by all agents)
default_provider: openrouter
openrouter_model: deepseek/deepseek-chat  # Cost-effective default
```

### Provider Selection

```python
from shakka.config import ShakkaConfig
from shakka.agents.roles import ExploitAgent

# Use specific provider for agent
config = ShakkaConfig(
    default_provider="openrouter",
    openrouter_model="anthropic/claude-3.5-sonnet"  # Premium for exploit analysis
)
agent = ExploitAgent(shakka_config=config)
```

## Example Output

```
$ shakka agent "Recon and initial access on target.com"

╭─ Orchestrator ─────────────────────────────────────────╮
│ Planning attack chain...                               │
│                                                        │
│ Step 1: Port scan target.com                          │
│ Step 2: Service enumeration                           │
│ Step 3: Vulnerability analysis                        │
│ Step 4: Exploit selection                             │
╰────────────────────────────────────────────────────────╯

╭─ Recon Agent ──────────────────────────────────────────╮
│ Scanning target.com:80,443...                         │
│ Found: Apache 2.4.41, PHP 7.4, WordPress 5.8          │
╰────────────────────────────────────────────────────────╯

╭─ Exploit Agent ────────────────────────────────────────╮
│ Analyzing WordPress plugins...                        │
│ CVE-2021-34527 applicable                             │
│ Generating payload...                                 │
╰────────────────────────────────────────────────────────╯
```

## See Also

- [Attack Planning](planning.md)
- [CVE Pipeline](exploit.md)
- [Vector Memory](memory.md)
