"""HTTP Transport for MCP Server.

Provides HTTP transport layer for the MCP server, enabling integration
with HTTP-based MCP clients. Supports both request/response and SSE
(Server-Sent Events) for streaming notifications.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
import threading
from urllib.parse import parse_qs, urlparse


logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class HTTPTransportConfig:
    """Configuration for HTTP transport."""
    
    host: str = "127.0.0.1"
    port: int = 3000
    cors_enabled: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    auth_enabled: bool = False
    auth_token: Optional[str] = None
    request_timeout: float = 30.0
    max_request_size: int = 1024 * 1024  # 1MB
    enable_sse: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "cors_enabled": self.cors_enabled,
            "cors_origins": self.cors_origins,
            "auth_enabled": self.auth_enabled,
            "request_timeout": self.request_timeout,
            "max_request_size": self.max_request_size,
            "enable_sse": self.enable_sse,
        }


# =============================================================================
# HTTP Request Handler
# =============================================================================

class MCPHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP protocol.
    
    Handles JSON-RPC over HTTP POST and optional SSE for notifications.
    """
    
    # Reference to the MCP message handler
    message_handler: Optional[Callable] = None
    config: Optional[HTTPTransportConfig] = None
    sse_clients: Set = set()
    
    def log_message(self, format: str, *args) -> None:
        """Override to use logging module."""
        logger.debug(f"HTTP: {format % args}")
    
    def _set_cors_headers(self) -> None:
        """Set CORS headers if enabled."""
        if self.config and self.config.cors_enabled:
            origin = self.headers.get("Origin", "*")
            if self.config.cors_origins == ["*"] or origin in self.config.cors_origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Access-Control-Max-Age", "86400")
    
    def _check_auth(self) -> bool:
        """Check authentication if enabled."""
        if not self.config or not self.config.auth_enabled:
            return True
        
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            return token == self.config.auth_token
        
        return False
    
    def _send_json_response(self, data: Any, status_code: int = 200) -> None:
        """Send a JSON response."""
        response_bytes = json.dumps(data).encode("utf-8")
        
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self._set_cors_headers()
        self.end_headers()
        
        self.wfile.write(response_bytes)
    
    def _send_error_response(self, code: int, message: str, status_code: int = 400) -> None:
        """Send a JSON-RPC error response."""
        error_response = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": code,
                "message": message,
            },
        }
        self._send_json_response(error_response, status_code)
    
    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()
    
    def do_GET(self) -> None:
        """Handle GET requests.
        
        Supports:
        - /health - Health check endpoint
        - /info - Server info endpoint
        - /sse - Server-Sent Events stream (if enabled)
        """
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == "/health":
            self._handle_health()
        elif path == "/info":
            self._handle_info()
        elif path == "/sse" and self.config and self.config.enable_sse:
            self._handle_sse()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self) -> None:
        """Handle POST requests (JSON-RPC messages)."""
        # Check authentication
        if not self._check_auth():
            self._send_error_response(-32000, "Unauthorized", 401)
            return
        
        # Check content length
        content_length = int(self.headers.get("Content-Length", 0))
        if self.config and content_length > self.config.max_request_size:
            self._send_error_response(-32000, "Request too large", 413)
            return
        
        # Read request body
        try:
            body = self.rfile.read(content_length)
            message = body.decode("utf-8")
        except Exception as e:
            self._send_error_response(-32700, f"Failed to read request: {e}")
            return
        
        # Handle the message
        if self.message_handler:
            try:
                # Run the async handler in an event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    response = loop.run_until_complete(self.message_handler(message))
                finally:
                    loop.close()
                
                if response:
                    self._send_json_response(response)
                else:
                    # For notifications, return 204 No Content
                    self.send_response(204)
                    self._set_cors_headers()
                    self.end_headers()
                    
            except Exception as e:
                logger.error(f"Error handling message: {e}")
                self._send_error_response(-32603, f"Internal error: {e}", 500)
        else:
            self._send_error_response(-32603, "Handler not configured", 500)
    
    def _handle_health(self) -> None:
        """Health check endpoint."""
        self._send_json_response({"status": "ok"})
    
    def _handle_info(self) -> None:
        """Server info endpoint."""
        info = {
            "name": "shakkashell",
            "version": "2.0.0",
            "protocol": "mcp",
            "transport": "http",
            "sse_enabled": self.config.enable_sse if self.config else False,
        }
        self._send_json_response(info)
    
    def _handle_sse(self) -> None:
        """Handle SSE (Server-Sent Events) connection."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._set_cors_headers()
        self.end_headers()
        
        # Register this client
        MCPHTTPHandler.sse_clients.add(self)
        
        try:
            # Send initial connection event
            self._send_sse_event("connected", {"message": "Connected to MCP SSE stream"})
            
            # Keep connection alive
            while True:
                # Send heartbeat every 30 seconds
                self._send_sse_event("heartbeat", {"timestamp": asyncio.get_event_loop().time()})
                import time
                time.sleep(30)
                
        except Exception:
            pass
        finally:
            MCPHTTPHandler.sse_clients.discard(self)
    
    def _send_sse_event(self, event: str, data: Any) -> None:
        """Send an SSE event."""
        try:
            self.wfile.write(f"event: {event}\n".encode())
            self.wfile.write(f"data: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()
        except Exception:
            pass


# =============================================================================
# HTTP Transport
# =============================================================================

class MCPHTTPTransport:
    """HTTP transport for MCP server.
    
    Enables the MCP server to communicate over HTTP instead of stdio,
    allowing integration with HTTP-based clients.
    
    Example:
        from shakka.mcp.server import MCPServer
        from shakka.mcp.transport import MCPHTTPTransport
        
        server = MCPServer()
        transport = MCPHTTPTransport(server, port=3000)
        transport.start()  # Blocking
        
        # Or async:
        await transport.start_async()
    """
    
    def __init__(
        self,
        mcp_server: Any,  # MCPServer
        config: Optional[HTTPTransportConfig] = None,
    ):
        """Initialize HTTP transport.
        
        Args:
            mcp_server: The MCPServer instance to use
            config: HTTP transport configuration
        """
        self.mcp_server = mcp_server
        self.config = config or HTTPTransportConfig()
        self._http_server: Optional[HTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
    
    @property
    def address(self) -> str:
        """Get the server address."""
        return f"http://{self.config.host}:{self.config.port}"
    
    @property
    def running(self) -> bool:
        """Check if server is running."""
        return self._running
    
    def start(self, blocking: bool = True) -> None:
        """Start the HTTP server.
        
        Args:
            blocking: If True, block until server stops. If False, run in background.
        """
        # Configure the handler class
        MCPHTTPHandler.message_handler = self.mcp_server._handle_message
        MCPHTTPHandler.config = self.config
        
        # Create the server
        server_address = (self.config.host, self.config.port)
        self._http_server = HTTPServer(server_address, MCPHTTPHandler)
        self._running = True
        
        logger.info(f"MCP HTTP server starting on {self.address}")
        
        if blocking:
            try:
                self._http_server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()
        else:
            self._server_thread = threading.Thread(
                target=self._http_server.serve_forever,
                daemon=True,
            )
            self._server_thread.start()
    
    async def start_async(self) -> None:
        """Start the HTTP server asynchronously."""
        # Run blocking server in executor
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.start(blocking=True))
    
    def stop(self) -> None:
        """Stop the HTTP server."""
        self._running = False
        
        if self._http_server:
            self._http_server.shutdown()
            self._http_server = None
        
        if self._server_thread:
            self._server_thread.join(timeout=5)
            self._server_thread = None
        
        logger.info("MCP HTTP server stopped")
    
    def broadcast_sse(self, event: str, data: Any) -> None:
        """Broadcast an SSE event to all connected clients.
        
        Args:
            event: Event name
            data: Event data (will be JSON serialized)
        """
        for client in list(MCPHTTPHandler.sse_clients):
            try:
                client._send_sse_event(event, data)
            except Exception:
                MCPHTTPHandler.sse_clients.discard(client)


# =============================================================================
# Async HTTP Transport (using asyncio)
# =============================================================================

class AsyncMCPHTTPTransport:
    """Async HTTP transport for MCP server using asyncio.
    
    A fully async implementation that integrates better with
    async MCP server methods.
    
    Example:
        transport = AsyncMCPHTTPTransport(server, port=3000)
        await transport.start()
    """
    
    def __init__(
        self,
        mcp_server: Any,
        config: Optional[HTTPTransportConfig] = None,
    ):
        """Initialize async HTTP transport.
        
        Args:
            mcp_server: The MCPServer instance
            config: HTTP transport configuration
        """
        self.mcp_server = mcp_server
        self.config = config or HTTPTransportConfig()
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._sse_clients: Set[asyncio.StreamWriter] = set()
    
    @property
    def address(self) -> str:
        """Get the server address."""
        return f"http://{self.config.host}:{self.config.port}"
    
    @property
    def running(self) -> bool:
        """Check if server is running."""
        return self._running
    
    async def start(self) -> None:
        """Start the async HTTP server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.config.host,
            self.config.port,
        )
        self._running = True
        
        logger.info(f"MCP Async HTTP server starting on {self.address}")
        
        async with self._server:
            await self._server.serve_forever()
    
    async def start_background(self) -> None:
        """Start the server in background (non-blocking)."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.config.host,
            self.config.port,
        )
        self._running = True
        logger.info(f"MCP Async HTTP server started on {self.address}")
    
    async def stop(self) -> None:
        """Stop the async HTTP server."""
        self._running = False
        
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        
        # Close all SSE clients
        for writer in list(self._sse_clients):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self._sse_clients.clear()
        
        logger.info("MCP Async HTTP server stopped")
    
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming client connection."""
        try:
            # Read HTTP request
            request_line = await asyncio.wait_for(
                reader.readline(),
                timeout=self.config.request_timeout,
            )
            
            if not request_line:
                return
            
            # Parse request line
            request_parts = request_line.decode().strip().split()
            if len(request_parts) < 2:
                await self._send_error(writer, 400, "Bad Request")
                return
            
            method, path = request_parts[0], request_parts[1]
            
            # Read headers
            headers = {}
            while True:
                line = await reader.readline()
                if line == b"\r\n" or line == b"\n" or not line:
                    break
                if b":" in line:
                    key, value = line.decode().split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Check authentication
            if self.config.auth_enabled:
                auth = headers.get("authorization", "")
                if not auth.startswith("Bearer ") or auth[7:] != self.config.auth_token:
                    await self._send_error(writer, 401, "Unauthorized")
                    return
            
            # Handle method
            if method == "OPTIONS":
                await self._send_cors_preflight(writer)
            elif method == "GET":
                await self._handle_get(writer, path)
            elif method == "POST":
                await self._handle_post(reader, writer, headers)
            else:
                await self._send_error(writer, 405, "Method Not Allowed")
                
        except asyncio.TimeoutError:
            await self._send_error(writer, 408, "Request Timeout")
        except Exception as e:
            logger.error(f"Error handling client: {e}")
            await self._send_error(writer, 500, "Internal Server Error")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    async def _handle_get(self, writer: asyncio.StreamWriter, path: str) -> None:
        """Handle GET requests."""
        parsed = urlparse(path)
        
        if parsed.path == "/health":
            await self._send_json(writer, {"status": "ok"})
        elif parsed.path == "/info":
            await self._send_json(writer, {
                "name": "shakkashell",
                "version": "2.0.0",
                "protocol": "mcp",
                "transport": "http-async",
            })
        elif parsed.path == "/sse" and self.config.enable_sse:
            await self._handle_sse(writer)
        else:
            await self._send_error(writer, 404, "Not Found")
    
    async def _handle_post(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        headers: Dict[str, str],
    ) -> None:
        """Handle POST requests (JSON-RPC)."""
        # Read body
        content_length = int(headers.get("content-length", 0))
        if content_length > self.config.max_request_size:
            await self._send_error(writer, 413, "Request Entity Too Large")
            return
        
        body = await reader.read(content_length)
        message = body.decode("utf-8")
        
        # Handle message through MCP server
        try:
            response = await self.mcp_server._handle_message(message)
            
            if response:
                await self._send_json(writer, response)
            else:
                await self._send_no_content(writer)
                
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": str(e)},
            }
            await self._send_json(writer, error_response, 500)
    
    async def _handle_sse(self, writer: asyncio.StreamWriter) -> None:
        """Handle SSE connection."""
        # Send SSE headers
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        )
        writer.write(response.encode())
        await writer.drain()
        
        # Register client
        self._sse_clients.add(writer)
        
        try:
            # Send connected event
            await self._send_sse_event(writer, "connected", {"message": "Connected"})
            
            # Keep alive with heartbeats
            while self._running:
                await asyncio.sleep(30)
                await self._send_sse_event(writer, "heartbeat", {})
                
        except Exception:
            pass
        finally:
            self._sse_clients.discard(writer)
    
    async def _send_sse_event(
        self,
        writer: asyncio.StreamWriter,
        event: str,
        data: Any,
    ) -> None:
        """Send an SSE event."""
        message = f"event: {event}\ndata: {json.dumps(data)}\n\n"
        writer.write(message.encode())
        await writer.drain()
    
    async def broadcast_sse(self, event: str, data: Any) -> None:
        """Broadcast SSE event to all clients."""
        for writer in list(self._sse_clients):
            try:
                await self._send_sse_event(writer, event, data)
            except Exception:
                self._sse_clients.discard(writer)
    
    async def _send_json(
        self,
        writer: asyncio.StreamWriter,
        data: Any,
        status: int = 200,
    ) -> None:
        """Send JSON response."""
        body = json.dumps(data).encode()
        response = (
            f"HTTP/1.1 {status} OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        )
        writer.write(response.encode() + body)
        await writer.drain()
    
    async def _send_no_content(self, writer: asyncio.StreamWriter) -> None:
        """Send 204 No Content response."""
        response = (
            "HTTP/1.1 204 No Content\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        )
        writer.write(response.encode())
        await writer.drain()
    
    async def _send_error(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        message: str,
    ) -> None:
        """Send error response."""
        body = json.dumps({"error": message}).encode()
        response = (
            f"HTTP/1.1 {status} {message}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        )
        writer.write(response.encode() + body)
        await writer.drain()
    
    async def _send_cors_preflight(self, writer: asyncio.StreamWriter) -> None:
        """Send CORS preflight response."""
        response = (
            "HTTP/1.1 204 No Content\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
            "Access-Control-Max-Age: 86400\r\n"
            "\r\n"
        )
        writer.write(response.encode())
        await writer.drain()


# =============================================================================
# Factory functions
# =============================================================================

def create_http_transport(
    mcp_server: Any,
    host: str = "127.0.0.1",
    port: int = 3000,
    **kwargs,
) -> MCPHTTPTransport:
    """Create an HTTP transport for the MCP server.
    
    Args:
        mcp_server: MCPServer instance
        host: Host to bind to
        port: Port to listen on
        **kwargs: Additional HTTPTransportConfig options
        
    Returns:
        Configured MCPHTTPTransport
    """
    config = HTTPTransportConfig(host=host, port=port, **kwargs)
    return MCPHTTPTransport(mcp_server, config)


def create_async_http_transport(
    mcp_server: Any,
    host: str = "127.0.0.1",
    port: int = 3000,
    **kwargs,
) -> AsyncMCPHTTPTransport:
    """Create an async HTTP transport for the MCP server.
    
    Args:
        mcp_server: MCPServer instance
        host: Host to bind to
        port: Port to listen on
        **kwargs: Additional HTTPTransportConfig options
        
    Returns:
        Configured AsyncMCPHTTPTransport
    """
    config = HTTPTransportConfig(host=host, port=port, **kwargs)
    return AsyncMCPHTTPTransport(mcp_server, config)
