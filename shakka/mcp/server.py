"""MCP Server implementation with JSON-RPC 2.0 protocol.

Implements the Model Context Protocol server for ShakkaShell,
supporting stdio transport for integration with MCP clients.
"""

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Optional, TextIO

from shakka.mcp.tools import MCPToolRegistry, create_default_tools


# MCP Protocol version
MCP_PROTOCOL_VERSION = "2024-11-05"

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


@dataclass
class MCPServerInfo:
    """Server information for MCP handshake."""
    
    name: str = "shakkashell"
    version: str = "2.0.0"


@dataclass 
class MCPCapabilities:
    """Server capabilities advertised to clients."""
    
    tools: bool = True
    prompts: bool = False
    resources: bool = False


@dataclass
class MCPServerConfig:
    """Configuration for the MCP server."""
    
    server_info: MCPServerInfo = field(default_factory=MCPServerInfo)
    capabilities: MCPCapabilities = field(default_factory=MCPCapabilities)


class MCPServer:
    """MCP Server implementation.
    
    Handles JSON-RPC 2.0 messages over stdio transport and exposes
    ShakkaShell functionality as MCP tools.
    
    Example:
        server = MCPServer()
        await server.run_stdio()
    """
    
    def __init__(
        self,
        config: Optional[MCPServerConfig] = None,
        tool_registry: Optional[MCPToolRegistry] = None,
    ):
        """Initialize the MCP server.
        
        Args:
            config: Server configuration. Uses defaults if not provided.
            tool_registry: Tool registry. Creates default tools if not provided.
        """
        self.config = config or MCPServerConfig()
        self.tool_registry = tool_registry or create_default_tools()
        self._running = False
        self._initialized = False
    
    async def run_stdio(
        self,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
    ) -> None:
        """Run the MCP server using stdio transport.
        
        Args:
            stdin: Input stream (defaults to sys.stdin)
            stdout: Output stream (defaults to sys.stdout)
        """
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        
        self._running = True
        
        while self._running:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, stdin.readline
                )
                
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                response = await self._handle_message(line)
                
                if response is not None:
                    self._write_response(stdout, response)
                    
            except Exception as e:
                error_response = self._create_error_response(
                    None, INTERNAL_ERROR, str(e)
                )
                self._write_response(stdout, error_response)
    
    def _write_response(self, stdout: TextIO, response: dict) -> None:
        """Write a JSON-RPC response to stdout.
        
        Args:
            stdout: Output stream
            response: Response dictionary to write
        """
        stdout.write(json.dumps(response) + "\n")
        stdout.flush()
    
    async def _handle_message(self, message: str) -> Optional[dict]:
        """Handle an incoming JSON-RPC message.
        
        Args:
            message: Raw JSON string from client
            
        Returns:
            Response dictionary or None for notifications
        """
        try:
            request = json.loads(message)
        except json.JSONDecodeError as e:
            return self._create_error_response(None, PARSE_ERROR, f"Parse error: {e}")
        
        # Validate JSON-RPC structure
        if not isinstance(request, dict):
            return self._create_error_response(None, INVALID_REQUEST, "Request must be an object")
        
        if request.get("jsonrpc") != "2.0":
            return self._create_error_response(
                request.get("id"), INVALID_REQUEST, "Invalid JSON-RPC version"
            )
        
        method = request.get("method")
        if not method or not isinstance(method, str):
            return self._create_error_response(
                request.get("id"), INVALID_REQUEST, "Method is required"
            )
        
        params = request.get("params", {})
        request_id = request.get("id")
        
        # Handle the method
        try:
            result = await self._dispatch_method(method, params)
            
            # Notifications don't get responses
            if request_id is None:
                return None
            
            return self._create_success_response(request_id, result)
            
        except MethodNotFoundError as e:
            return self._create_error_response(request_id, METHOD_NOT_FOUND, str(e))
        except InvalidParamsError as e:
            return self._create_error_response(request_id, INVALID_PARAMS, str(e))
        except Exception as e:
            return self._create_error_response(request_id, INTERNAL_ERROR, str(e))
    
    async def _dispatch_method(self, method: str, params: dict) -> Any:
        """Dispatch a method call to the appropriate handler.
        
        Args:
            method: MCP method name
            params: Method parameters
            
        Returns:
            Method result
            
        Raises:
            MethodNotFoundError: If method is not supported
        """
        handlers = {
            "initialize": self._handle_initialize,
            "initialized": self._handle_initialized,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "shutdown": self._handle_shutdown,
        }
        
        handler = handlers.get(method)
        if handler is None:
            raise MethodNotFoundError(f"Method not found: {method}")
        
        return await handler(params)
    
    async def _handle_initialize(self, params: dict) -> dict:
        """Handle the initialize request.
        
        Args:
            params: Client initialization parameters
            
        Returns:
            Server capabilities and info
        """
        self._initialized = True
        
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {} if self.config.capabilities.tools else None,
            },
            "serverInfo": {
                "name": self.config.server_info.name,
                "version": self.config.server_info.version,
            },
        }
    
    async def _handle_initialized(self, params: dict) -> None:
        """Handle the initialized notification.
        
        This is a notification from the client confirming initialization.
        
        Args:
            params: Notification parameters (ignored)
        """
        # This is a notification, no response needed
        return None
    
    async def _handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list request.
        
        Args:
            params: Request parameters (may include cursor for pagination)
            
        Returns:
            List of available tools
        """
        tools = self.tool_registry.list_tool_schemas()
        return {"tools": tools}
    
    async def _handle_tools_call(self, params: dict) -> dict:
        """Handle tools/call request.
        
        Args:
            params: Tool call parameters including name and arguments
            
        Returns:
            Tool execution result
            
        Raises:
            InvalidParamsError: If tool name or arguments are invalid
        """
        tool_name = params.get("name")
        if not tool_name:
            raise InvalidParamsError("Tool name is required")
        
        tool = self.tool_registry.get(tool_name)
        if tool is None:
            raise InvalidParamsError(f"Unknown tool: {tool_name}")
        
        arguments = params.get("arguments", {})
        
        # Validate required parameters
        for param in tool.parameters:
            if param.required and param.name not in arguments:
                raise InvalidParamsError(f"Missing required parameter: {param.name}")
        
        # Execute the tool handler if available
        if tool.handler:
            result = await tool.handler(**arguments)
        else:
            # Default stub response for tools without handlers
            result = {
                "status": "not_implemented",
                "message": f"Tool '{tool_name}' handler not yet implemented",
                "arguments_received": arguments,
            }
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2),
                }
            ],
        }
    
    async def _handle_shutdown(self, params: dict) -> None:
        """Handle shutdown request.
        
        Args:
            params: Shutdown parameters (ignored)
        """
        self._running = False
        return None
    
    def _create_success_response(self, request_id: Any, result: Any) -> dict:
        """Create a JSON-RPC success response.
        
        Args:
            request_id: Request ID to echo back
            result: Result data
            
        Returns:
            JSON-RPC response dictionary
        """
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        }
    
    def _create_error_response(
        self, request_id: Optional[Any], code: int, message: str
    ) -> dict:
        """Create a JSON-RPC error response.
        
        Args:
            request_id: Request ID to echo back (None for parse errors)
            code: JSON-RPC error code
            message: Error message
            
        Returns:
            JSON-RPC error response dictionary
        """
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
    
    def stop(self) -> None:
        """Stop the running server."""
        self._running = False


class MethodNotFoundError(Exception):
    """Raised when an unknown method is called."""
    pass


class InvalidParamsError(Exception):
    """Raised when method parameters are invalid."""
    pass
