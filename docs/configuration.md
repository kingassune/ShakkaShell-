# Configuration

ShakkaShell supports configuration via environment variables and YAML config files.

## Environment Variables

### API Keys

```bash
# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic  
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenRouter (access 200+ models via single API)
export OPENROUTER_API_KEY="sk-or-v1-..."

# Optional: Ollama base URL (default: http://localhost:11434)
export OLLAMA_BASE_URL="http://localhost:11434"
```

### Provider Settings

```bash
# Default provider (openai, anthropic, ollama, openrouter)
export SHAKKA_DEFAULT_PROVIDER="openrouter"

# Default model per provider
export SHAKKA_DEFAULT_MODEL="gpt-4o"
export SHAKKA_OPENROUTER_MODEL="deepseek/deepseek-chat"
export SHAKKA_OLLAMA_MODEL="llama3.3"

# Enable debug mode
export SHAKKA_DEBUG="true"
```

### Safety Settings

```bash
# Enable YOLO mode (skip confirmations)
export SHAKKA_YOLO_MODE="false"

# Block destructive commands
export SHAKKA_BLOCK_DESTRUCTIVE="false"

# Enable cost tracking
export SHAKKA_ENABLE_COST_TRACKING="true"
```

## Config File

Location:
- **Linux/macOS**: `~/.config/shakka/config.yaml`
- **Windows**: `%APPDATA%/shakka/config.yaml`

### Full Example

```yaml
# ~/.config/shakka/config.yaml

# LLM Provider Settings
default_provider: openrouter  # openai, anthropic, ollama, openrouter
default_model: gpt-4o
fallback_providers:
  - anthropic
  - openai
  - ollama
enable_fallback: true

# API Keys (can also use environment variables)
openai_api_key: ${OPENAI_API_KEY}
anthropic_api_key: ${ANTHROPIC_API_KEY}
openrouter_api_key: ${OPENROUTER_API_KEY}
ollama_base_url: http://localhost:11434

# Safety Settings
safety:
  confirm_dangerous: true
  block_destructive: false
  yolo_mode: false
  allowed_targets: []
  blocked_commands:
    - "rm -rf /"
    - "mkfs"

# Cost Tracking
enable_cost_tracking: true
cost_alert_threshold: 10.0  # Alert when costs exceed $10

# Memory Settings
memory:
  enable: true
  backend: json  # json or chromadb
  max_entries: 1000
  privacy_mode: false

# Agent Settings
agents:
  max_iterations: 10
  timeout: 300  # seconds
  model_overrides:
    orchestrator: claude-sonnet-4
    recon: gpt-4o
    exploit: o1

# History
max_history: 100
auto_save_history: true

# Display
debug: false
verbose: false
```

## Provider-Specific Config

### OpenAI

```yaml
openai:
  api_key: ${OPENAI_API_KEY}
  organization: org-xxx  # Optional
  models:
    - gpt-4o
    - gpt-4-turbo
    - o1
    - o3-mini
```

### Anthropic

```yaml
anthropic:
  api_key: ${ANTHROPIC_API_KEY}
  models:
    - claude-sonnet-4
    - claude-opus-4
    - claude-3-5-sonnet
```

### Ollama

```yaml
ollama:
  base_url: http://localhost:11434
  models:
    - llama3.3:70b
    - qwen3:32b
    - codellama:34b
```

### OpenRouter

OpenRouter provides access to 200+ models through a single API endpoint, making it ideal for cost optimization and model experimentation.

```yaml
openrouter:
  api_key: ${OPENROUTER_API_KEY}
  default_model: deepseek/deepseek-chat
  models:
    # Fast & cost-effective
    - deepseek/deepseek-chat
    - meta-llama/llama-3.3-70b-instruct
    # Premium models
    - openai/gpt-4o
    - anthropic/claude-3.5-sonnet
    - anthropic/claude-sonnet-4
    # Reasoning models
    - openai/o1
    - deepseek/deepseek-r1
```

**Popular OpenRouter models for security tasks:**
| Model | Best For | Cost |
|-------|----------|------|
| `deepseek/deepseek-chat` | General commands, fast | Very low |
| `meta-llama/llama-3.3-70b-instruct` | Complex analysis | Low |
| `openai/gpt-4o` | Accuracy, tool use | Medium |
| `anthropic/claude-3.5-sonnet` | Detailed reasoning | Medium |

## View Current Config

```bash
shakka config --show
```

## Next Steps

- [CLI Reference](cli.md)
- [Safety Layer](safety.md)
