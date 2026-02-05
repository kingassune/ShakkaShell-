"""MCP (Model Context Protocol) server implementation for ShakkaShell.

This module exposes ShakkaShell as an MCP server for integration with
AI-native tools like Claude Desktop, VS Code with Continue/Copilot, and Cursor IDE.
"""

from shakka.mcp.server import MCPServer
from shakka.mcp.tools import MCPTool, MCPToolRegistry
from shakka.mcp.transport import (
    HTTPTransportConfig,
    MCPHTTPTransport,
    AsyncMCPHTTPTransport,
    create_http_transport,
    create_async_http_transport,
)

__all__ = [
    "MCPServer",
    "MCPTool",
    "MCPToolRegistry",
    "HTTPTransportConfig",
    "MCPHTTPTransport",
    "AsyncMCPHTTPTransport",
    "create_http_transport",
    "create_async_http_transport",
]
