# Multi-Agent System

ShakkaShell v2 features a multi-agent orchestration system for complex, multi-step security tasks.

## Overview

The agent system consists of specialized agents coordinated by an Orchestrator:

| Agent | Role | Specialty |
|-------|------|-----------|
| **Orchestrator** | Task planning, coordination | Breaking down complex goals |
| **Recon Agent** | Reconnaissance | Enumeration, OSINT, service detection |
| **Exploit Agent** | Exploitation | Vulnerability analysis, payload selection |
| **Persistence Agent** | Post-exploitation | Maintaining access, privilege escalation |
| **Reporter Agent** | Documentation | Findings, evidence, report generation |

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

# Create orchestrator
orchestrator = Orchestrator()

# Add specialized agents
orchestrator.add_agent(ReconAgent())
orchestrator.add_agent(ExploitAgent())

# Execute task
result = await orchestrator.execute(
    "Full assessment of target.com"
)

# Access results
for step in result.steps:
    print(f"{step.agent}: {step.output}")
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

```yaml
# config.yaml
agents:
  max_iterations: 10
  timeout: 300  # seconds
  model_overrides:
    orchestrator: claude-sonnet-4
    recon: gpt-4o
    exploit: o1
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
