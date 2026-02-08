# MCP Server

ShakkaShell can run as an MCP (Model Context Protocol) server, enabling integration with any MCP-compatible AI client.

## Overview

MCP is a standardized protocol for AI tool integration, adopted by OpenAI, Anthropic, and Google. ShakkaShell exposes its capabilities as MCP tools, including:

- **Real-time command generation** via configured LLM provider (OpenAI, Anthropic, OpenRouter, Ollama)
- **Live CVE lookups** via NVD, Exploit-DB, and GitHub APIs
- **Multi-agent orchestration** for complex security tasks

## Exposed Tools

| Tool | Description |
|------|-------------|
| `shakka_execute` | Convert natural language to security command and execute |
| `shakka_scan` | Quick network/host scan |
| `shakka_exploit` | Lookup or generate exploit for CVE |

### Tool Schemas

```json
{
  "tools": [
    {
      "name": "shakka_execute",
      "description": "Convert natural language to security command and execute",
      "inputSchema": {
        "type": "object",
        "properties": {
          "prompt": { "type": "string", "description": "Natural language security task" },
          "execute": { "type": "boolean", "default": false },
          "explain": { "type": "boolean", "default": false }
        },
        "required": ["prompt"]
      }
    },
    {
      "name": "shakka_scan",
      "description": "Quick network/host scan",
      "inputSchema": {
        "type": "object",
        "properties": {
          "target": { "type": "string" },
          "scan_type": { "type": "string", "enum": ["quick", "full", "vuln"] }
        },
        "required": ["target"]
      }
    },
    {
      "name": "shakka_exploit",
      "description": "Lookup or generate exploit for CVE",
      "inputSchema": {
        "type": "object",
        "properties": {
          "cve": { "type": "string", "pattern": "^CVE-\\d{4}-\\d+$" }
        },
        "required": ["cve"]
      }
    }
  ]
}
```

## Usage

### stdio Transport (Claude Desktop, etc.)

```bash
# Start MCP server on stdio
shakka --mcp
```

#### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shakka": {
      "command": "shakka",
      "args": ["--mcp"]
    }
  }
}
```

### HTTP Transport

```bash
# Start HTTP server
shakka --mcp --port 3000
```

Endpoints:
- `POST /` - JSON-RPC 2.0 endpoint
- `GET /health` - Health check
- `GET /info` - Server information
- `GET /sse` - Server-sent events (streaming)

### Python Client

```python
import httpx

# Call ShakkaShell via MCP HTTP
response = httpx.post(
    "http://localhost:3000",
    json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "shakka_execute",
            "arguments": {
                "prompt": "scan ports on 10.0.0.1"
            }
        },
        "id": 1
    }
)

result = response.json()
print(result["result"]["content"])
```

## Configuration

```yaml
# config.yaml
mcp:
  transport: stdio  # stdio or http
  port: 3000        # for HTTP transport
  cors:
    enabled: true
    origins: ["*"]
  auth:
    enabled: false
    token: ${MCP_AUTH_TOKEN}
```

## HTTP Transport Options

```python
from shakka.mcp.transport import HTTPTransportConfig, create_http_transport

config = HTTPTransportConfig(
    host="0.0.0.0",
    port=3000,
    cors_enabled=True,
    cors_origins=["*"],
    auth_token="secret-token"
)

transport = create_http_transport(config)
transport.start()
```

## Authentication

For HTTP transport, use Bearer token authentication:

```bash
curl -X POST http://localhost:3000 \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Integration Examples

### VS Code + Continue

```json
{
  "models": [
    {
      "title": "Claude with ShakkaShell",
      "provider": "anthropic",
      "model": "claude-sonnet-4",
      "mcpServers": ["shakka"]
    }
  ],
  "mcpServers": {
    "shakka": {
      "command": "shakka",
      "args": ["--mcp"]
    }
  }
}
```

### Cursor IDE

```json
{
  "mcpServers": {
    "shakka": {
      "command": "shakka",
      "args": ["--mcp"]
    }
  }
}
```

## See Also

- [CLI Reference](cli.md)
- [Python API](api.md)
